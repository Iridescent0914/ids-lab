"""PCAP 后台导入 Worker。

PCAP 文件可能较大，如果直接在 PyQt 主线程中读取和检测，会导致界面卡顿。
该 Worker 运行在 ``QThread`` 中，按批次把 ``PacketInfo`` 发回主窗口处理。
"""

from __future__ import annotations

import logging
from pathlib import Path
from threading import Event

from PyQt6.QtCore import QObject, pyqtSignal

from app.parser.models import PacketInfo
from app.capture.pcap_reader import iter_pcap_packets


logger = logging.getLogger(__name__)


class PcapImportWorker(QObject):
    """在后台线程中分批导入 PCAP 文件。

    Worker 只负责读取和分批发送数据包，不直接更新界面，也不直接执行检测。
    主窗口收到 ``packet_batch`` 信号后，再统一刷新 Traffic 表、执行检测并写库。
    """

    # 一批 PacketInfo；使用 object 是为了让 PyQt 信号能传递 Python list。
    packet_batch = pyqtSignal(object)
    # 状态栏文本，例如导入开始、已导入多少包。
    status_changed = pyqtSignal(str)
    # 读取失败时把错误信息发回主窗口。
    failed = pyqtSignal(str)
    # 参数分别表示已读取数量和是否被用户取消。
    finished = pyqtSignal(int, bool)

    def __init__(self, path: Path, batch_size: int = 200, status_interval: int = 1000) -> None:
        """保存导入参数并初始化停止标志。

        ``batch_size`` 控制每次发给主窗口的数据包数量；``status_interval`` 控制
        状态栏更新频率。二者都至少为 1，避免调用方传入 0 导致逻辑异常。
        """
        super().__init__()
        self.path = path
        self.batch_size = max(1, batch_size)
        self.status_interval = max(1, status_interval)
        self._stop_event = Event()

    def stop(self) -> None:
        """请求停止导入。

        这里不强行终止线程，而是设置标志位，让 ``run`` 在处理完当前包后自然
        退出，避免文件读取和信号发送处于半截状态。
        """
        self._stop_event.set()

    def run(self) -> None:
        """执行 PCAP 导入主循环。

        逐包读取 PCAP，累积到一批后通过信号发送给主窗口；如果用户请求停止，
        则标记为取消并跳出循环。所有结束路径都会发送 ``finished`` 信号。
        """
        count = 0
        cancelled = False
        batch: list[PacketInfo] = []
        self.status_changed.emit(f"Importing {self.path.name}...")

        try:
            for packet in iter_pcap_packets(self.path):
                # 用户点击 Stop 后，不再继续读取后续数据包。
                if self._stop_event.is_set():
                    cancelled = True
                    break

                batch.append(packet)
                count += 1

                # 分批发送能减少 UI 刷新和数据库写入的频率。
                if len(batch) >= self.batch_size:
                    self.packet_batch.emit(batch)
                    batch = []

                # 大文件导入时定期更新状态，让用户知道程序仍在工作。
                if count % self.status_interval == 0:
                    self.status_changed.emit(f"Imported {count} packets from {self.path.name}...")

            # 循环结束后还有未满一批的数据，也需要发回主窗口处理。
            if batch:
                self.packet_batch.emit(batch)
        except Exception as exc:  # pragma: no cover - depends on external PCAP data
            logger.exception("PCAP import failed")
            self.failed.emit(str(exc))
        finally:
            self.finished.emit(count, cancelled)
