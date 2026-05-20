"""LightIDS 简化 Snort 风格规则解析器。

本模块负责把 ``rules/default.rules`` 中的文本规则转换为 ``DetectionRule``。
当前项目不是完整 Snort 兼容实现，而是为了课程 IDS 链路实现一组稳定、可测试、
可展示的规则子集。

支持的规则基本形态：

```
alert tcp any any -> any 80 (msg:"..."; sid:1001; priority:2; content:"GET"; nocase;)
```

解析流程大致为：

1. ``load_rules`` 读取规则文件，跳过空行和注释；
2. ``parse_rule_line`` 把单行规则拆成 header 和 options；
3. ``_parse_header`` 解析动作、协议、地址、端口和方向；
4. ``_parse_options`` 解析 msg、sid、priority、content、flags、itype 等选项；
5. ``_validate_rule`` 做统一语法检查，错误写入 ``DetectionRule.errors``。
"""

from __future__ import annotations

import re
from pathlib import Path

from app.rules.models import DetectionRule, RuleLoadResult


# 当前项目只实现告警规则，不支持 pass/drop/log 等其他动作。
SUPPORTED_ACTIONS = {"alert"}
# 规则引擎目前支持的协议集合；ARP 解析后可展示，但不参与简化规则匹配。
SUPPORTED_PROTOCOLS = {"tcp", "udp", "icmp", "ip"}
# 用正则把规则分成两部分：
#   header:   alert tcp any any -> any 80
#   options:  msg:"..."; sid:1001; ...
HEADER_PATTERN = re.compile(
    r"^(?P<header>.+?)\s*\((?P<options>.*)\)\s*$"
)


class RuleParseError(RuntimeError):
    """规则文件路径不可用或读取失败时抛出的统一异常。"""


def load_rules(path: Path) -> RuleLoadResult:
    """从规则文件加载所有规则。

    该函数只把“文件级别无法处理”的情况作为异常抛出，例如文件不存在或路径不是
    文件。单条规则写错不会中断整个加载流程，而是记录在对应 ``DetectionRule`` 的
    ``errors`` 中，并让 UI 显示这条规则无效。
    """
    if not path.exists():
        raise RuleParseError(f"Rule file not found: {path}")
    if not path.is_file():
        raise RuleParseError(f"Rule path is not a file: {path}")

    rules: list[DetectionRule] = []
    # sid 应当在规则文件内唯一。字典保存 sid 第一次出现的行号，用于后续报错。
    sid_seen: dict[int, int] = {}

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw_line.strip()
        # 空行和以 # 开头的注释行不生成规则对象。
        if not stripped or stripped.startswith("#"):
            continue

        rule = parse_rule_line(stripped, line_number)
        if rule.sid is not None:
            previous_line = sid_seen.get(rule.sid)
            if previous_line is not None:
                rule.errors.append(f"duplicate sid {rule.sid} also used on line {previous_line}")
            else:
                sid_seen[rule.sid] = line_number

        # 合法规则默认启用；非法规则默认禁用，避免参与检测。
        rule.enabled = rule.is_valid
        rules.append(rule)

    return RuleLoadResult(rules=rules, source_path=str(path))


def parse_rule_line(raw_text: str, line_number: int = 0) -> DetectionRule:
    """解析单行规则文本。

    返回值始终是 ``DetectionRule``。即使规则格式错误，也会尽量填充能解析出的字段
    并把错误写入 ``errors``，这样 Rules 页面可以展示具体错误，而不是简单丢弃。
    """
    rule = DetectionRule(raw_text=raw_text, line_number=line_number)
    match = HEADER_PATTERN.match(raw_text)
    if not match:
        # 缺少外层括号时仍尝试解析 header，便于给出更多错误信息。
        rule.errors.append("missing or invalid option parentheses")
        _parse_header(raw_text, rule)
        return rule

    _parse_header(match.group("header").strip(), rule)
    _parse_options(match.group("options").strip(), rule)
    _validate_rule(rule)
    return rule


def _parse_header(header_text: str, rule: DetectionRule) -> None:
    """解析规则头部。

    简化规则头部固定为 7 个空白分隔字段：

    ``action protocol src_ip src_port direction dst_ip dst_port``

    例如：``alert tcp any any -> any 80``。
    """
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
    # 协议和动作统一小写，后续校验和匹配就不必关心大小写。
    rule.protocol = rule.protocol.lower()
    rule.action = rule.action.lower()


def _parse_options(options_text: str, rule: DetectionRule) -> None:
    """解析括号中的规则选项。

    选项以分号分隔，支持两种形式：

    * ``key:value;``，例如 ``sid:1001;``、``content:"GET";``；
    * ``flag;``，例如 ``nocase;``，解析后保存为布尔值 ``True``。
    """
    if not options_text.endswith(";"):
        rule.errors.append("options must end with semicolon")

    for option in _split_options(options_text):
        if not option:
            continue
        if ":" in option:
            # 只按第一个冒号拆分，允许 value 中继续出现冒号。
            key, value = option.split(":", 1)
            key = key.strip().lower()
            value = _strip_quotes(value.strip())
            rule.options[key] = value
        else:
            rule.options[option.strip().lower()] = True

    # 把 options 字典中的常用字段提升到 DetectionRule 的直接属性，
    # 后续 rule_engine 可以直接读取，不需要理解 options 字典结构。
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
    """按分号拆分规则选项，同时保护引号中的分号。

    规则中可能出现 ``content:"a;b";`` 这样的内容。如果直接 ``split(";")``，会把
    引号里的分号也切开。这里用一个小型状态机记录当前是否在双引号内，并处理
    反斜杠转义，确保只在引号外的分号处分割。
    """
    options: list[str] = []
    current: list[str] = []
    in_quotes = False
    escape_next = False

    for char in options_text:
        if escape_next:
            # 上一个字符是反斜杠时，当前字符无条件作为普通内容保留。
            current.append(char)
            escape_next = False
            continue
        if char == "\\":
            current.append(char)
            escape_next = True
            continue
        if char == '"':
            # 切换“是否在双引号内”的状态，但引号本身也保留，后续 _strip_quotes
            # 会统一去掉成对外层引号。
            in_quotes = not in_quotes
            current.append(char)
            continue
        if char == ";" and not in_quotes:
            # 只有引号外的分号才表示一个 option 结束。
            options.append("".join(current).strip())
            current = []
            continue
        current.append(char)

    tail = "".join(current).strip()
    if tail:
        options.append(tail)
    return options


def _strip_quotes(value: str) -> str:
    """去掉 option 值外层的一对双引号。"""
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _optional_text(value: str | bool | None) -> str | None:
    """把可选文本选项规范化为 ``str | None``。

    ``nocase`` 这类无值选项会以 ``True`` 保存，不能当成文本字段使用；空字符串也
    视为没有设置。
    """
    if isinstance(value, str) and value:
        return value
    return None


def _parse_icmp_type(rule: DetectionRule) -> int | None:
    """解析 ICMP type 选项。

    为了方便书写，项目同时支持 ``itype`` 和 ``icmp_type`` 两个名字。这里先取出
    所有可解析为数字的值；最终一致性和范围校验交给 ``_validate_icmp_type``。
    """
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
    """对解析后的规则做统一合法性检查。

    解析阶段尽量“能读多少读多少”，校验阶段再集中判断支持范围、必填字段和数值
    范围。所有错误都会追加到 ``rule.errors``，不会抛异常中断整个规则文件加载。
    """
    if rule.action not in SUPPORTED_ACTIONS:
        rule.errors.append("unsupported action")
    if rule.protocol not in SUPPORTED_PROTOCOLS:
        rule.errors.append("unsupported protocol")
    if rule.direction != "->":
        rule.errors.append("unsupported direction")

    _validate_port(rule.src_port, "source port", rule)
    _validate_port(rule.dst_port, "destination port", rule)

    # sid 是规则唯一标识，必须存在且为数字；重复 sid 在 load_rules 中检查。
    if "sid" not in rule.options:
        rule.errors.append("missing sid")
    elif rule.sid is None:
        rule.errors.append("sid must be a number")

    # msg 用于生成告警 message，缺失时 UI 和日志都难以解释告警含义。
    if "msg" not in rule.options or not rule.message:
        rule.errors.append("missing msg")

    if "priority" in rule.options and rule.priority is None:
        rule.errors.append("priority must be a number")

    _validate_icmp_type(rule)


def _validate_port(port: str, label: str, rule: DetectionRule) -> None:
    """校验端口字段。

    当前简化规则只支持 ``any`` 或单个 0-65535 的端口号，不支持端口范围、列表或
    取反语法。
    """
    if port == "any":
        return
    if port.isdigit():
        value = int(port)
        if 0 <= value <= 65535:
            return
    rule.errors.append(f"{label} must be 'any' or 0-65535")


def _validate_icmp_type(rule: DetectionRule) -> None:
    """校验 ICMP type 选项。

    ``itype`` 和 ``icmp_type`` 是同一含义的别名。如果两者同时出现，必须写成相同
    数值；否则规则语义不明确，应标记为非法。
    """
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
