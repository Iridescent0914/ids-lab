"""Configuration loading for LightIDS."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ThresholdConfig:
    window_seconds: int
    port_scan_unique_ports: int
    horizontal_scan_unique_hosts: int
    icmp_high_frequency_count: int


@dataclass(frozen=True)
class CaptureConfig:
    max_display_packets: int
    max_display_alerts: int
    default_timeout_seconds: int


@dataclass(frozen=True)
class AppConfig:
    app_name: str
    database_path: Path
    log_file: Path
    log_level: str
    default_rules_path: Path
    threshold: ThresholdConfig
    capture: CaptureConfig


def _require_mapping(data: Any, name: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError(f"Config section '{name}' must be an object")
    return data


def _resolve_path(value: Any, default: str, root: Path) -> Path:
    path = Path(value or default)
    if path.is_absolute():
        return path
    return root / path


def load_config(path: Path, root: Path) -> AppConfig:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = json.loads(path.read_text(encoding="utf-8"))
    data = _require_mapping(raw, "root")
    threshold = _require_mapping(data.get("threshold", {}), "threshold")
    capture = _require_mapping(data.get("capture", {}), "capture")
    storage = _require_mapping(data.get("storage", {}), "storage")
    logging_config = _require_mapping(data.get("logging", {}), "logging")
    rules = _require_mapping(data.get("rules", {}), "rules")

    return AppConfig(
        app_name=str(data.get("app_name", "LightIDS")),
        database_path=Path(storage.get("database_path", "data/lightids.db")),
        log_file=Path(logging_config.get("file", "logs/lightids.log")),
        log_level=str(logging_config.get("level", "INFO")).upper(),
        default_rules_path=_resolve_path(
            rules.get("default_rules_path", "rules/default.rules"),
            "rules/default.rules",
            root,
        ),
        threshold=ThresholdConfig(
            window_seconds=int(threshold.get("window_seconds", 10)),
            port_scan_unique_ports=int(threshold.get("port_scan_unique_ports", 10)),
            horizontal_scan_unique_hosts=int(threshold.get("horizontal_scan_unique_hosts", 10)),
            icmp_high_frequency_count=int(threshold.get("icmp_high_frequency_count", 20)),
        ),
        capture=CaptureConfig(
            max_display_packets=int(capture.get("max_display_packets", 1000)),
            max_display_alerts=int(capture.get("max_display_alerts", 1000)),
            default_timeout_seconds=int(capture.get("default_timeout_seconds", 30)),
        ),
    )
