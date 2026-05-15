"""Rule data models for the simplified Snort-style rule system."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class DetectionRule:
    raw_text: str
    line_number: int
    action: str = "alert"
    protocol: str = ""
    src_ip: str = ""
    src_port: str = ""
    direction: str = "->"
    dst_ip: str = ""
    dst_port: str = ""
    sid: int | None = None
    message: str = ""
    priority: int | None = None
    classtype: str | None = None
    content: str | None = None
    nocase: bool = False
    flags: str | None = None
    icmp_type: int | None = None
    options: dict[str, str | bool] = field(default_factory=dict)
    enabled: bool = True
    hit_count: int = 0
    last_hit: datetime | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not self.errors

    @property
    def display_sid(self) -> str:
        return str(self.sid) if self.sid is not None else "-"

    @property
    def display_priority(self) -> str:
        return str(self.priority) if self.priority is not None else "-"

    @property
    def display_source(self) -> str:
        return f"{self.src_ip}:{self.src_port}" if self.src_ip and self.src_port else "-"

    @property
    def display_destination(self) -> str:
        return f"{self.dst_ip}:{self.dst_port}" if self.dst_ip and self.dst_port else "-"

    @property
    def display_last_hit(self) -> str:
        if self.last_hit is None:
            return "-"
        return self.last_hit.strftime("%Y-%m-%d %H:%M:%S")

    @property
    def status_text(self) -> str:
        return "OK" if self.is_valid else "; ".join(self.errors)

    def record_hit(self, timestamp: datetime | None = None) -> None:
        self.hit_count += 1
        self.last_hit = timestamp or datetime.now()


@dataclass(frozen=True)
class RuleLoadResult:
    rules: list[DetectionRule]
    source_path: str

    @property
    def valid_count(self) -> int:
        return sum(1 for rule in self.rules if rule.is_valid)

    @property
    def invalid_count(self) -> int:
        return sum(1 for rule in self.rules if not rule.is_valid)
