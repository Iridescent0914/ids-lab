"""Background PCAP import worker."""

from __future__ import annotations

import logging
from pathlib import Path
from threading import Event

from PyQt6.QtCore import QObject, pyqtSignal

from app.parser.models import PacketInfo
from app.capture.pcap_reader import iter_pcap_packets


logger = logging.getLogger(__name__)


class PcapImportWorker(QObject):
    packet_batch = pyqtSignal(object)
    status_changed = pyqtSignal(str)
    failed = pyqtSignal(str)
    finished = pyqtSignal(int, bool)

    def __init__(self, path: Path, batch_size: int = 200, status_interval: int = 1000) -> None:
        super().__init__()
        self.path = path
        self.batch_size = max(1, batch_size)
        self.status_interval = max(1, status_interval)
        self._stop_event = Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        count = 0
        cancelled = False
        batch: list[PacketInfo] = []
        self.status_changed.emit(f"Importing {self.path.name}...")

        try:
            for packet in iter_pcap_packets(self.path):
                if self._stop_event.is_set():
                    cancelled = True
                    break

                batch.append(packet)
                count += 1

                if len(batch) >= self.batch_size:
                    self.packet_batch.emit(batch)
                    batch = []

                if count % self.status_interval == 0:
                    self.status_changed.emit(f"Imported {count} packets from {self.path.name}...")

            if batch:
                self.packet_batch.emit(batch)
        except Exception as exc:  # pragma: no cover - depends on external PCAP data
            logger.exception("PCAP import failed")
            self.failed.emit(str(exc))
        finally:
            self.finished.emit(count, cancelled)
