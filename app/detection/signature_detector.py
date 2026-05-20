"""基于规则特征的单包检测器。

该模块负责把已经解析好的 ``PacketInfo`` 与规则列表逐条匹配。它不直接解析
规则文本，也不关心 Scapy 原始数据包，只接收 ``DetectionRule`` 和
``PacketInfo`` 两个项目内部模型。这样实时抓包和 PCAP 导入都能复用同一套
规则检测流程。
"""

from __future__ import annotations

from app.detection.rule_engine import rule_matches_packet
from app.parser.models import AlertEvent, PacketInfo
from app.rules.models import DetectionRule


class SignatureDetector:
    """执行简化 Snort 风格规则的检测器。

    ``SignatureDetector`` 的职责很窄：保存当前启用的规则集合，并在每个数据包
    到达时调用 ``rule_engine`` 完成具体字段匹配。命中规则后，它负责更新规则
    命中统计并生成统一的 ``AlertEvent``，交给 UI 和 SQLite 存储层继续处理。
    """

    def __init__(self, rules: list[DetectionRule]) -> None:
        """保存当前规则列表。

        主窗口重新加载规则或用户启用/禁用规则后，会重新创建检测器或修改规则
        对象状态；这里保留规则对象本身，是为了命中时能直接更新 ``hit_count``
        和 ``last_hit``。
        """
        self.rules = rules

    def detect(self, packet: PacketInfo) -> list[AlertEvent]:
        """对单个 ``PacketInfo`` 执行规则检测。

        返回值是一个告警列表，因为同一个数据包可能同时命中多条规则。例如一条
        HTTP 请求既可能命中目的端口规则，也可能命中 payload 中的 Web 攻击关键字
        规则。没有命中时返回空列表。
        """
        alerts: list[AlertEvent] = []
        for rule in self.rules:
            # 具体协议、IP、端口、content、flags、ICMP type 等字段判断都放在
            # rule_engine 中，保持本类只负责“遍历规则”和“生成告警”。
            if not rule_matches_packet(rule, packet):
                continue

            # 规则对象会展示在 Rules 页面，因此命中后立即记录次数和最近命中时间。
            rule.record_hit(packet.timestamp)
            alerts.append(
                AlertEvent(
                    # 规则事件沿用触发数据包的时间和网络五元组，便于回溯是哪一个
                    # 包触发了告警。
                    timestamp=packet.timestamp,
                    message=rule.message,
                    # priority 是规则里的严重级别；缺失时使用 4 作为较低严重级别，
                    # 避免因为规则没写 priority 导致告警无法生成。
                    severity=rule.priority or 4,
                    protocol=packet.protocol,
                    # ``rule_event`` 用来和阶段六的 ``threshold_alert`` 区分：
                    # 前者是单包规则事件，后者是多包行为告警。
                    alert_type="rule_event",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    rule_sid=rule.sid,
                    packet_length=packet.packet_length,
                )
            )
        return alerts
