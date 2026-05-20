"""数据采集层用于界面展示的数据包摘要模型。

采集层和解析层内部使用 ``PacketInfo`` 保存完整字段；界面表格只需要一组
已经格式化好的字符串和长度信息，因此这里提供 ``PacketSummary`` 作为轻量
展示模型，避免 UI 直接关心端口、ICMP type/code 等字段的格式化细节。
"""

from __future__ import annotations

from dataclasses import dataclass

from app.parser.models import PacketInfo


@dataclass(frozen=True)
class PacketSummary:
    """Traffic 表格中一行数据包摘要。

    该对象只面向展示，不参与检测逻辑。使用 ``frozen=True`` 可以避免界面层
    或其他调用方意外修改已经生成的摘要内容。
    """

    timestamp: str
    protocol: str
    source: str
    source_port: str
    destination: str
    destination_port: str
    length: int


def summary_from_packet_info(packet: PacketInfo) -> PacketSummary:
    """将完整的 ``PacketInfo`` 转换为界面表格需要的摘要字段。

    ``PacketInfo`` 已经提供了 ``timestamp_text``、``source_text`` 等显示属性，
    这里负责集中调用这些属性，保证 Traffic 表格中的展示格式保持一致。
    """
    return PacketSummary(
        timestamp=packet.timestamp_text,
        protocol=packet.protocol,
        source=packet.source_text,
        source_port=packet.source_port_text,
        destination=packet.destination_text,
        destination_port=packet.destination_port_text,
        length=packet.packet_length,
    )



# models.py：定义 PacketSummary，这是给 Traffic 表格用的轻量展示对象。完整数据仍然是 PacketInfo，这里负责把时间、源地址、目的地址、端口、长度等字段转成界面可直接显示的格式。

# pcap_reader.py：负责离线读取 PCAP/PCAPNG。iter_pcap_packets() 用生成器逐包读取，适合大文件；read_pcap() 是一次性读成列表的便捷函数，适合测试或小文件。读取失败统一抛 PcapReadError。

# pcap_importer.py：负责后台导入 PCAP。它是 QObject Worker，通常放到 QThread 里跑，避免大 PCAP 导入时卡住 PyQt 主界面。它按批次发出 packet_batch，支持 Stop 取消，失败时发 failed，结束时发 finished(count, cancelled)。

# packet_capture.py：负责实时抓包和网卡枚举。前半部分把 Scapy/Npcap 的底层接口名整理成用户可理解的 Wi-Fi、Ethernet、Loopback、Advanced 等显示项；后半部分 PacketCaptureWorker 在后台线程里调用 Scapy sniff()，每抓到一个包就转成 PacketInfo 发给主窗口。