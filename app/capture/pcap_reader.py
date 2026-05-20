"""LightIDS 的 PCAP/PCAPNG 离线读取模块。

该模块只负责从文件中逐包读取原始 Scapy packet，并立即转换为项目内部统一的
``PacketInfo``。后续规则检测、阈值检测和界面展示都基于 ``PacketInfo``，
因此实时抓包和离线读取可以共用同一套检测流程。
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from scapy.utils import PcapReader

from app.parser.models import PacketInfo
from app.parser.protocol_parser import parse_packet


class PcapReadError(RuntimeError):
    """PCAP 文件不存在、路径非法或读取失败时抛出的统一异常。"""


def iter_pcap_packets(path: Path, limit: int | None = None) -> Iterator[PacketInfo]:
    """按需迭代读取 PCAP 文件并生成 ``PacketInfo``。

    使用生成器可以避免一次性把大 PCAP 全部读入内存。``limit`` 主要用于测试
    或调试场景，用来限制最多读取的数据包数量。
    """
    # 先做明确的路径检查，让调用方看到更具体的错误原因。
    if not path.exists():
        raise PcapReadError(f"PCAP file not found: {path}")
    if not path.is_file():
        raise PcapReadError(f"PCAP path is not a file: {path}")

    try:
        count = 0
        # Scapy 的 PcapReader 会逐包解析文件内容，适合大文件流式处理。
        with PcapReader(str(path)) as reader:
            for packet in reader:
                # 采集层不保留 Scapy 原始对象，统一交给协议解析层标准化。
                yield parse_packet(packet)
                count += 1
                if limit is not None and count >= limit:
                    break
    except Exception as exc:  # pragma: no cover - depends on external PCAP data
        raise PcapReadError(f"Failed to read PCAP file: {path}") from exc


def read_pcap(path: Path, limit: int | None = None) -> list[PacketInfo]:
    """一次性读取 PCAP 文件并返回列表。

    这是 ``iter_pcap_packets`` 的便捷包装，适合单元测试或小文件读取；主界面
    的导入流程使用生成器版本，以便分批处理。
    """
    return list(iter_pcap_packets(path, limit))
