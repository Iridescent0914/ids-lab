"""把 Scapy 原始数据包转换为 LightIDS 的 ``PacketInfo``。

采集层负责拿到原始 Scapy packet；本模块负责抽取检测需要的稳定字段，包括
时间、长度、IP、端口、TCP flags、ICMP type/code、ARP 操作和 payload。
检测层不直接依赖 Scapy 对象，因此实时抓包和 PCAP 导入可以共用后续逻辑。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.packet import Raw

from app.parser.models import PacketInfo


ARP_OPERATIONS = {
    # ARP op=1 表示询问某个 IP 对应的 MAC 地址。
    1: "who-has",
    # ARP op=2 表示回应某个 IP 对应的 MAC 地址。
    2: "is-at",
}


def _packet_time(packet: Any) -> datetime:
    """从 Scapy packet 中提取时间戳。

    Scapy 通常在 ``packet.time`` 中保存抓包时间。对于手工构造、异常或空对象，
    这里使用当前时间兜底，保证解析函数总能返回可用的 ``PacketInfo``。
    """
    try:
        return datetime.fromtimestamp(float(packet.time))
    except (AttributeError, TypeError, ValueError, OSError):
        return datetime.now()


def _packet_length(packet: Any) -> int:
    """返回数据包长度。

    Scapy packet 一般支持 ``len(packet)``；异常对象无法计算长度时返回 0。
    """
    try:
        return int(len(packet))
    except TypeError:
        return 0


def _payload_bytes(packet: Any) -> bytes:
    """提取 Raw 层中的原始 payload 字节。

    LightIDS 的 ``content`` 规则基于字节串查找，因此这里保留 bytes，而不是过早
    转成字符串。没有 Raw 层时返回空字节串。
    """
    if packet is not None and packet.haslayer(Raw):
        raw_load = packet[Raw].load
        if isinstance(raw_load, bytes):
            return raw_load
        return bytes(raw_load)
    return b""


def _parse_ip_packet(packet: Any, timestamp: datetime, packet_length: int, payload: bytes) -> PacketInfo:
    """解析包含 IP 层的数据包。

    IP 层提供源/目的地址；随后根据更具体的上层协议分发到 TCP、UDP 或 ICMP。
    如果只有 IP 层而没有这些上层协议，则返回 protocol="IP" 的基础信息。
    """
    ip = packet[IP]
    # TCP/UDP/ICMP 共用 IP 地址、时间、长度和 payload，因此先集中放入基础字段。
    base_fields = {
        "timestamp": timestamp,
        "packet_length": packet_length,
        "src_ip": str(ip.src),
        "dst_ip": str(ip.dst),
        "payload": payload,
    }

    if packet.haslayer(TCP):
        # TCP 额外提取端口和 flags，flags 用于规则匹配和扫描响应过滤。
        tcp = packet[TCP]
        return PacketInfo(
            **base_fields,
            protocol="TCP",
            src_port=int(tcp.sport),
            dst_port=int(tcp.dport),
            tcp_flags=str(tcp.flags),
        )

    if packet.haslayer(UDP):
        # UDP 只有端口字段，没有 TCP flags。
        udp = packet[UDP]
        return PacketInfo(
            **base_fields,
            protocol="UDP",
            src_port=int(udp.sport),
            dst_port=int(udp.dport),
        )

    if packet.haslayer(ICMP):
        # ICMP 没有端口，检测时主要关心 type/code，例如 Echo Request/Reply。
        icmp = packet[ICMP]
        return PacketInfo(
            **base_fields,
            protocol="ICMP",
            icmp_type=int(icmp.type),
            icmp_code=int(icmp.code),
        )

    # 其他 IP 承载协议仍保留 IP 地址、长度和 payload，便于界面观察。
    return PacketInfo(**base_fields, protocol="IP")


def _parse_arp_packet(packet: Any, timestamp: datetime, packet_length: int, payload: bytes) -> PacketInfo:
    """解析 ARP 数据包。

    ARP 不属于 IP 层，但仍有协议地址字段 psrc/pdst。这里将它们映射到
    ``src_ip`` 和 ``dst_ip``，使 UI 和告警显示可以复用相同字段。
    """
    arp = packet[ARP]
    # 常见操作码转为可读文本，未知操作码保留原始数字字符串。
    operation = ARP_OPERATIONS.get(int(arp.op), str(arp.op))
    return PacketInfo(
        timestamp=timestamp,
        protocol="ARP",
        packet_length=packet_length,
        src_ip=str(arp.psrc),
        dst_ip=str(arp.pdst),
        payload=payload,
        arp_operation=operation,
    )


def parse_packet(packet: Any) -> PacketInfo:
    """解析任意 Scapy packet，返回统一 ``PacketInfo``。

    这是解析层对外的主入口。函数先提取所有协议都可能用到的时间、长度和
    payload，再按 IP、ARP、未知协议的顺序分发处理。
    """
    timestamp = _packet_time(packet)
    packet_length = _packet_length(packet)
    payload = _payload_bytes(packet)

    # IP 是最常见的网络层协议，TCP/UDP/ICMP 都会走这里。
    if packet is not None and packet.haslayer(IP):
        return _parse_ip_packet(packet, timestamp, packet_length, payload)

    # ARP 没有 IP 层，但在局域网分析中很常见，因此单独支持。
    if packet is not None and packet.haslayer(ARP):
        return _parse_arp_packet(packet, timestamp, packet_length, payload)

    # 兜底路径：保留对象类名作为协议名，避免未知包导致整个导入流程失败。
    protocol = packet.__class__.__name__.upper() if packet is not None else "UNKNOWN"
    return PacketInfo(
        timestamp=timestamp,
        protocol=protocol,
        packet_length=packet_length,
        payload=payload,
    )
