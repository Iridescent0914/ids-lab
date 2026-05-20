"""LightIDS 规则字段匹配引擎。

本模块只判断“某条规则是否匹配某个标准化后的数据包”。它不负责读取规则文件、
不更新规则命中次数，也不生成告警对象；这些工作分别由 ``rule_parser``、
``SignatureDetector`` 和 UI/存储层完成。

当前规则语法是简化 Snort 风格，支持：

* 协议：tcp、udp、icmp、ip；
* 地址：any 或精确 IP/文本匹配；
* 端口：any 或单个端口号；
* content/nocase：在 Raw payload 中查找字节串；
* flags：TCP 标志集合精确匹配；
* itype/icmp_type：ICMP type 匹配。
"""

from __future__ import annotations

import ipaddress

from app.parser.models import PacketInfo
from app.rules.models import DetectionRule


def rule_matches_packet(rule: DetectionRule, packet: PacketInfo) -> bool:
    """判断一条规则是否匹配一个数据包。

    匹配采用“逐项短路”的方式：任何一个必要条件不满足就立即返回 ``False``。
    这样既减少无意义的后续判断，也让匹配顺序清晰地对应规则头部和规则选项：
    先检查启用/合法状态，再检查协议、地址、端口，最后检查可选 payload、
    TCP flags 和 ICMP type。
    """
    # 无效规则或用户在 Rules 页面取消勾选的规则不参与检测。
    if not rule.enabled or not rule.is_valid:
        return False

    # 规则头部字段：协议、源地址、目的地址、源端口、目的端口。
    if not _match_protocol(rule, packet):
        return False
    if not _match_ip(rule.src_ip, packet.src_ip):
        return False
    if not _match_ip(rule.dst_ip, packet.dst_ip):
        return False
    if not _match_port(rule.src_port, packet.src_port):
        return False
    if not _match_port(rule.dst_port, packet.dst_port):
        return False

    # 规则选项字段：只有规则显式写了该选项时才检查。
    if rule.content is not None and not _match_content(rule, packet):
        return False
    if rule.flags is not None and not _match_flags(rule.flags, packet.tcp_flags):
        return False
    if rule.icmp_type is not None and not _match_icmp_type(rule.icmp_type, packet.icmp_type):
        return False
    return True


def _match_protocol(rule: DetectionRule, packet: PacketInfo) -> bool:
    """匹配规则协议字段。

    ``ip`` 在 Snort 语义中通常表示任意 IP 层流量，因此这里让规则 ``ip`` 匹配
    IP、TCP、UDP、ICMP。ARP 不属于 IP 层，所以不会被 ``ip`` 规则命中。
    其他协议使用小写规则协议名与 ``PacketInfo.protocol`` 比较。
    """
    if rule.protocol == "ip":
        return packet.protocol in {"IP", "TCP", "UDP", "ICMP"}
    return packet.protocol.lower() == rule.protocol


def _match_ip(rule_value: str, packet_value: str | None) -> bool:
    """匹配规则 IP 地址字段。

    当前实现支持 ``any`` 和精确地址匹配。优先使用 ``ipaddress`` 做规范化比较，
    这样 ``010.000.000.001`` 之类可解析地址会按 IP 语义处理；如果规则值或数据包
    值不是标准 IP，就退回到字符串相等，给特殊文本或后续扩展保留余地。
    """
    if rule_value == "any":
        return True
    if packet_value is None:
        return False
    try:
        return ipaddress.ip_address(rule_value) == ipaddress.ip_address(packet_value)
    except ValueError:
        return rule_value == packet_value


def _match_port(rule_value: str, packet_value: int | None) -> bool:
    """匹配规则端口字段。

    TCP/UDP 数据包才有端口；ICMP、ARP 或未知协议没有端口时，只有规则写 ``any``
    才能通过端口检查。当前规则解析器只允许 ``any`` 或 0-65535 的单个数字端口。
    """
    if rule_value == "any":
        return True
    if packet_value is None:
        return False
    return rule_value.isdigit() and int(rule_value) == packet_value


def _match_content(rule: DetectionRule, packet: PacketInfo) -> bool:
    """在数据包 Raw payload 中匹配 ``content`` 选项。

    ``PacketInfo.payload`` 保存的是原始字节，因此规则中的文本内容会先按 UTF-8
    编码为字节串再查找。若规则包含 ``nocase``，则把两边都转为小写字节后比较。
    这适合课程项目中的明文 HTTP 关键字检测；它不做 TCP 流重组或 HTTPS 解密。
    """
    if rule.content is None:
        return True

    payload = packet.payload
    content = rule.content.encode("utf-8", errors="ignore")
    if rule.nocase:
        return content.lower() in payload.lower()
    return content in payload


def _match_flags(required_flags: str, packet_flags: str | None) -> bool:
    """匹配 TCP flags。

    这里使用集合相等而不是包含关系。例如规则 ``flags:S`` 只匹配纯 SYN，不匹配
    SYN-ACK。这样可以避免服务器响应包 ``SA`` 被误判为客户端主动扫描包。
    """
    if packet_flags is None:
        return False
    return set(required_flags) == set(packet_flags)


def _match_icmp_type(required_type: int, packet_type: int | None) -> bool:
    """匹配 ICMP type。

    Echo Request 常见 type 为 8，Echo Reply 常见 type 为 0。规则解析器已经负责
    校验 type 范围，因此这里直接比较解析后的整数即可。
    """
    return packet_type == required_type
