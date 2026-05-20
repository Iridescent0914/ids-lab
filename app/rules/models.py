"""简化 Snort 风格规则系统的数据模型。

规则文件中的每一行文本会先由 ``rule_parser`` 转换为 ``DetectionRule``。检测层
不再直接处理字符串规则，而是读取这里定义好的结构化字段，例如协议、源/目的
地址、端口、content、flags 和 ICMP type。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class DetectionRule:
    """单条检测规则的结构化表示。

    该对象同时服务三个场景：

    * 规则解析：保存从文本中拆出的 header 和 options；
    * 规则检测：供 ``rule_engine`` 读取字段并匹配 ``PacketInfo``；
    * 界面展示：保存启用状态、命中次数、最近命中时间和语法错误。

    之所以没有使用 ``frozen=True``，是因为规则命中时需要更新 ``hit_count`` 和
    ``last_hit``，用户也可以在 Rules 页面启用或禁用规则。
    """

    # 原始规则文本，用于调试、展示或错误定位。
    raw_text: str
    # 规则在文件中的行号；手动解析单行规则时可以为 0。
    line_number: int

    # 规则头部 7 个字段：
    # action protocol src_ip src_port direction dst_ip dst_port
    action: str = "alert"
    protocol: str = ""
    src_ip: str = ""
    src_port: str = ""
    direction: str = "->"
    dst_ip: str = ""
    dst_port: str = ""

    # 常用规则选项字段。sid 是规则唯一标识，message 用于生成告警描述，
    # priority 用于告警严重级别，content/flags/icmp_type 用于具体匹配。
    sid: int | None = None
    message: str = ""
    priority: int | None = None
    classtype: str | None = None
    content: str | None = None
    nocase: bool = False
    flags: str | None = None
    icmp_type: int | None = None

    # 保存所有解析出的 options。值可能是字符串，也可能是无值选项 True，
    # 例如 ``nocase;`` 会保存为 {"nocase": True}。
    options: dict[str, str | bool] = field(default_factory=dict)

    # UI 和检测层状态。无效规则默认不会启用；有效规则可以由用户手动关闭。
    enabled: bool = True
    hit_count: int = 0
    last_hit: datetime | None = None

    # 解析和校验阶段收集的错误列表；为空表示规则合法。
    errors: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """规则是否通过语法和字段校验。"""
        return not self.errors

    @property
    def display_sid(self) -> str:
        """返回适合 Rules 表格展示的 sid 文本。"""
        return str(self.sid) if self.sid is not None else "-"

    @property
    def display_priority(self) -> str:
        """返回适合 Rules 表格展示的 priority 文本。"""
        return str(self.priority) if self.priority is not None else "-"

    @property
    def display_source(self) -> str:
        """返回 ``源地址:源端口`` 的展示文本。"""
        return f"{self.src_ip}:{self.src_port}" if self.src_ip and self.src_port else "-"

    @property
    def display_destination(self) -> str:
        """返回 ``目的地址:目的端口`` 的展示文本。"""
        return f"{self.dst_ip}:{self.dst_port}" if self.dst_ip and self.dst_port else "-"

    @property
    def display_last_hit(self) -> str:
        """返回最近命中时间；未命中过则显示 ``-``。"""
        if self.last_hit is None:
            return "-"
        return self.last_hit.strftime("%Y-%m-%d %H:%M:%S")

    @property
    def status_text(self) -> str:
        """返回规则状态文本。

        合法规则显示 ``OK``；非法规则把所有错误拼成一段文本，方便 UI 直接展示。
        """
        return "OK" if self.is_valid else "; ".join(self.errors)

    def record_hit(self, timestamp: datetime | None = None) -> None:
        """记录一次规则命中。

        ``SignatureDetector`` 命中规则后调用该方法。若传入数据包时间，就使用数据包
        时间作为最近命中时间；否则用当前系统时间兜底。
        """
        self.hit_count += 1
        self.last_hit = timestamp or datetime.now()


@dataclass(frozen=True)
class RuleLoadResult:
    """规则文件加载结果。

    ``load_rules`` 会返回该对象，而不是只返回规则列表。这样主窗口可以同时知道
    规则来自哪个文件、总数、合法数量和非法数量，便于状态栏提示。
    """

    rules: list[DetectionRule]
    source_path: str

    @property
    def valid_count(self) -> int:
        """返回合法规则数量。"""
        return sum(1 for rule in self.rules if rule.is_valid)

    @property
    def invalid_count(self) -> int:
        """返回非法规则数量。"""
        return sum(1 for rule in self.rules if not rule.is_valid)
