"""Parser for the LightIDS simplified Snort-style rule subset."""

from __future__ import annotations

import re
from pathlib import Path

from app.rules.models import DetectionRule, RuleLoadResult


SUPPORTED_ACTIONS = {"alert"}
SUPPORTED_PROTOCOLS = {"tcp", "udp", "icmp", "ip"}
HEADER_PATTERN = re.compile(
    r"^(?P<header>.+?)\s*\((?P<options>.*)\)\s*$"
)


class RuleParseError(RuntimeError):
    """Raised when a rule file cannot be loaded."""


def load_rules(path: Path) -> RuleLoadResult:
    if not path.exists():
        raise RuleParseError(f"Rule file not found: {path}")
    if not path.is_file():
        raise RuleParseError(f"Rule path is not a file: {path}")

    rules: list[DetectionRule] = []
    sid_seen: dict[int, int] = {}

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        rule = parse_rule_line(stripped, line_number)
        if rule.sid is not None:
            previous_line = sid_seen.get(rule.sid)
            if previous_line is not None:
                rule.errors.append(f"duplicate sid {rule.sid} also used on line {previous_line}")
            else:
                sid_seen[rule.sid] = line_number
        rule.enabled = rule.is_valid
        rules.append(rule)

    return RuleLoadResult(rules=rules, source_path=str(path))


def parse_rule_line(raw_text: str, line_number: int = 0) -> DetectionRule:
    rule = DetectionRule(raw_text=raw_text, line_number=line_number)
    match = HEADER_PATTERN.match(raw_text)
    if not match:
        rule.errors.append("missing or invalid option parentheses")
        _parse_header(raw_text, rule)
        return rule

    _parse_header(match.group("header").strip(), rule)
    _parse_options(match.group("options").strip(), rule)
    _validate_rule(rule)
    return rule


def _parse_header(header_text: str, rule: DetectionRule) -> None:
    parts = header_text.split()
    if len(parts) != 7:
        rule.errors.append("rule header must contain 7 fields")
        return

    (
        rule.action,
        rule.protocol,
        rule.src_ip,
        rule.src_port,
        rule.direction,
        rule.dst_ip,
        rule.dst_port,
    ) = parts
    rule.protocol = rule.protocol.lower()
    rule.action = rule.action.lower()


def _parse_options(options_text: str, rule: DetectionRule) -> None:
    if not options_text.endswith(";"):
        rule.errors.append("options must end with semicolon")

    for option in _split_options(options_text):
        if not option:
            continue
        if ":" in option:
            key, value = option.split(":", 1)
            key = key.strip().lower()
            value = _strip_quotes(value.strip())
            rule.options[key] = value
        else:
            rule.options[option.strip().lower()] = True

    rule.message = str(rule.options.get("msg", ""))
    rule.classtype = _optional_text(rule.options.get("classtype"))
    rule.content = _optional_text(rule.options.get("content"))
    rule.flags = _optional_text(rule.options.get("flags"))
    rule.nocase = bool(rule.options.get("nocase", False))
    rule.icmp_type = _parse_icmp_type(rule)

    sid_value = rule.options.get("sid")
    if isinstance(sid_value, str) and sid_value.isdigit():
        rule.sid = int(sid_value)

    priority_value = rule.options.get("priority")
    if isinstance(priority_value, str) and priority_value.isdigit():
        rule.priority = int(priority_value)


def _split_options(options_text: str) -> list[str]:
    options: list[str] = []
    current: list[str] = []
    in_quotes = False
    escape_next = False

    for char in options_text:
        if escape_next:
            current.append(char)
            escape_next = False
            continue
        if char == "\\":
            current.append(char)
            escape_next = True
            continue
        if char == '"':
            in_quotes = not in_quotes
            current.append(char)
            continue
        if char == ";" and not in_quotes:
            options.append("".join(current).strip())
            current = []
            continue
        current.append(char)

    tail = "".join(current).strip()
    if tail:
        options.append(tail)
    return options


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _optional_text(value: str | bool | None) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _parse_icmp_type(rule: DetectionRule) -> int | None:
    type_values = [
        value
        for key in ("itype", "icmp_type")
        if isinstance((value := rule.options.get(key)), str)
    ]
    parsed_values = [int(value) for value in type_values if value.isdigit()]
    if parsed_values:
        return parsed_values[0]
    return None


def _validate_rule(rule: DetectionRule) -> None:
    if rule.action not in SUPPORTED_ACTIONS:
        rule.errors.append("unsupported action")
    if rule.protocol not in SUPPORTED_PROTOCOLS:
        rule.errors.append("unsupported protocol")
    if rule.direction != "->":
        rule.errors.append("unsupported direction")

    _validate_port(rule.src_port, "source port", rule)
    _validate_port(rule.dst_port, "destination port", rule)

    if "sid" not in rule.options:
        rule.errors.append("missing sid")
    elif rule.sid is None:
        rule.errors.append("sid must be a number")

    if "msg" not in rule.options or not rule.message:
        rule.errors.append("missing msg")

    if "priority" in rule.options and rule.priority is None:
        rule.errors.append("priority must be a number")

    _validate_icmp_type(rule)


def _validate_port(port: str, label: str, rule: DetectionRule) -> None:
    if port == "any":
        return
    if port.isdigit():
        value = int(port)
        if 0 <= value <= 65535:
            return
    rule.errors.append(f"{label} must be 'any' or 0-65535")


def _validate_icmp_type(rule: DetectionRule) -> None:
    type_keys = [key for key in ("itype", "icmp_type") if key in rule.options]
    if not type_keys:
        return

    parsed_values: list[int] = []
    for key in type_keys:
        value = rule.options.get(key)
        if not isinstance(value, str) or not value.isdigit():
            rule.errors.append(f"{key} must be a number")
            continue
        parsed_value = int(value)
        if not 0 <= parsed_value <= 255:
            rule.errors.append(f"{key} must be 0-255")
            continue
        parsed_values.append(parsed_value)

    if len(set(parsed_values)) > 1:
        rule.errors.append("itype and icmp_type must match when both are set")
