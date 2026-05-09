"""Main window for LightIDS."""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QThread, Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from app.capture.models import PacketSummary, summary_from_packet_info
from app.capture.packet_capture import CaptureInterface, PacketCaptureWorker, list_interfaces
from app.capture.pcap_reader import PcapReadError, read_pcap
from app.core.config import AppConfig
from app.detection.signature_detector import SignatureDetector
from app.detection.threshold_detector import ThresholdDetector, ThresholdSettings
from app.parser.models import AlertEvent, PacketInfo
from app.rules.models import DetectionRule
from app.rules.rule_parser import RuleParseError, load_rules
from app.storage.database import DatabaseManager


class MainWindow(QMainWindow):
    def __init__(self, config: AppConfig, database: DatabaseManager) -> None:
        super().__init__()
        self.config = config
        self.database = database
        self.capture_thread: QThread | None = None
        self.capture_worker: PacketCaptureWorker | None = None
        self.available_interfaces: list[CaptureInterface] = []
        self.rules: list[DetectionRule] = []
        self.loading_rules_table = False
        self.threshold_detector = ThresholdDetector(
            ThresholdSettings(
                window_seconds=config.threshold.window_seconds,
                port_scan_unique_ports=config.threshold.port_scan_unique_ports,
                icmp_high_frequency_count=config.threshold.icmp_high_frequency_count,
            )
        )
        self.total_packets = 0
        self.total_alerts = 0
        self.high_severity_alerts = 0
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}
        self.alert_severity_counts: dict[int, int] = {}
        self.alert_type_counts = {"rule_event": 0, "threshold_alert": 0}

        self.setWindowTitle(config.app_name)
        self.resize(1100, 720)

        self._build_status_bar()
        self._build_toolbar()
        self._build_tabs()
        self.reload_rules()

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)

        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(260)
        self.advanced_interfaces_checkbox = QCheckBox("Show advanced interfaces")
        self.refresh_button = QPushButton("Refresh Interfaces")
        self.start_button = QPushButton("Start Capture")
        self.stop_button = QPushButton("Stop")
        self.import_button = QPushButton("Import PCAP")
        self.clear_button = QPushButton("Clear Traffic")
        self.rules_button = QPushButton("Reload Rules")

        self.stop_button.setEnabled(False)

        toolbar.addWidget(self.interface_combo)
        toolbar.addWidget(self.advanced_interfaces_checkbox)
        toolbar.addWidget(self.refresh_button)
        toolbar.addSeparator()
        toolbar.addWidget(self.start_button)
        toolbar.addWidget(self.stop_button)
        toolbar.addSeparator()
        toolbar.addWidget(self.import_button)
        toolbar.addWidget(self.clear_button)
        toolbar.addSeparator()
        toolbar.addWidget(self.rules_button)
        self.addToolBar(toolbar)

        self.refresh_button.clicked.connect(self.refresh_interfaces)
        self.advanced_interfaces_checkbox.toggled.connect(self.populate_interface_combo)
        self.interface_combo.currentIndexChanged.connect(self.update_interface_hint)
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.import_button.clicked.connect(self.import_pcap)
        self.clear_button.clicked.connect(self.clear_traffic)
        self.rules_button.clicked.connect(self.reload_rules)
        self.refresh_interfaces()

    def _build_tabs(self) -> None:
        tabs = QTabWidget()
        tabs.addTab(self._traffic_tab(), "Traffic")
        tabs.addTab(self._alerts_tab(), "Alerts")
        tabs.addTab(self._rules_tab(), "Rules")
        tabs.addTab(self._statistics_tab(), "Statistics")
        self.setCentralWidget(tabs)

    def _traffic_tab(self) -> QWidget:
        self.traffic_table = QTableWidget(0, 7)
        self.traffic_table.setHorizontalHeaderLabels(
            ["Time", "Protocol", "Source", "Source Port", "Destination", "Destination Port", "Length"]
        )
        return self._table_page(self.traffic_table)

    def _alerts_tab(self) -> QWidget:
        self.alerts_table = QTableWidget(0, 8)
        self.alerts_table.setHorizontalHeaderLabels(
            ["Time", "Severity", "SID", "Message", "Protocol", "Source", "Destination", "Type"]
        )
        return self._table_page(self.alerts_table)

    def _rules_tab(self) -> QWidget:
        self.rules_table = QTableWidget(0, 10)
        self.rules_table.setHorizontalHeaderLabels(
            [
                "Enabled",
                "SID",
                "Protocol",
                "Source",
                "Destination",
                "Message",
                "Priority",
                "Hits",
                "Last Hit",
                "Status",
            ]
        )
        self.rules_table.itemChanged.connect(self.on_rule_item_changed)
        return self._table_page(self.rules_table)

    def _statistics_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.total_packets_label = QLabel("Total packets: 0")
        self.total_alerts_label = QLabel("Total alerts: 0")
        self.high_alerts_label = QLabel("High severity alerts: 0")
        self.protocols_label = QLabel("TCP / UDP / ICMP / ARP: 0 / 0 / 0 / 0")
        self.alert_levels_label = QLabel("Alert severity counts: -")
        self.alert_types_label = QLabel("Rule events / Threshold alerts: 0 / 0")
        self.threshold_config_label = QLabel(
            "Thresholds: "
            f"{self.config.threshold.port_scan_unique_ports} ports / "
            f"{self.config.threshold.icmp_high_frequency_count} ICMP packets / "
            f"{self.config.threshold.window_seconds}s"
        )

        for label in [
            self.total_packets_label,
            self.total_alerts_label,
            self.high_alerts_label,
            self.protocols_label,
            self.alert_levels_label,
            self.alert_types_label,
            self.threshold_config_label,
        ]:
            label.setMinimumHeight(32)
            layout.addWidget(label)

        return page

    def _table_page(self, table: QTableWidget) -> QWidget:
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.horizontalHeader().setStretchLastSection(True)

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(table)
        return page

    def _build_status_bar(self) -> None:
        status = QStatusBar()
        status.showMessage(
            f"Ready | DB: {self.config.database_path} | Rules: {self.config.default_rules_path}"
        )
        self.setStatusBar(status)

    def refresh_interfaces(self) -> None:
        self.interface_combo.clear()
        try:
            self.available_interfaces = list_interfaces()
        except Exception as exc:  # pragma: no cover - depends on local Scapy/Npcap
            QMessageBox.warning(self, "Interface Error", f"Failed to list interfaces:\n{exc}")
            self.statusBar().showMessage("Failed to list interfaces")
            return

        self.populate_interface_combo()

    def populate_interface_combo(self, checked: bool | None = None) -> None:
        current = self.interface_combo.currentData()
        current_device = current.device_name if isinstance(current, CaptureInterface) else ""
        self.interface_combo.clear()
        show_advanced = self.advanced_interfaces_checkbox.isChecked()
        visible_interfaces = [
            item for item in self.available_interfaces if show_advanced or item.is_common
        ]

        for capture_interface in visible_interfaces:
            self.interface_combo.addItem(capture_interface.display_name, capture_interface)
            item_index = self.interface_combo.count() - 1
            self.interface_combo.setItemData(
                item_index,
                f"{capture_interface.hint}\nDevice: {capture_interface.device_name}",
                Qt.ItemDataRole.ToolTipRole,
            )

        if current_device:
            for index, capture_interface in enumerate(visible_interfaces):
                if capture_interface.device_name == current_device:
                    self.interface_combo.setCurrentIndex(index)
                    break

        if show_advanced:
            self.statusBar().showMessage(
                f"Showing all {len(visible_interfaces)} network interfaces"
            )
        else:
            hidden_count = len(self.available_interfaces) - len(visible_interfaces)
            self.statusBar().showMessage(
                f"Showing {len(visible_interfaces)} common interfaces; {hidden_count} hidden"
            )
        self.update_interface_hint()

    def update_interface_hint(self, index: int | None = None) -> None:
        selected = self.interface_combo.currentData()
        if not isinstance(selected, CaptureInterface):
            return

        self.interface_combo.setToolTip(f"{selected.hint}\nDevice: {selected.device_name}")
        self.statusBar().showMessage(f"Current interface: {selected.display_name}. {selected.hint}")

    def import_pcap(self) -> None:
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Import PCAP",
            "",
            "Packet captures (*.pcap *.pcapng);;All files (*.*)",
        )
        if not file_name:
            return

        try:
            packets = read_pcap(Path(file_name))
        except PcapReadError as exc:
            QMessageBox.warning(self, "PCAP Error", str(exc))
            self.statusBar().showMessage("Failed to import PCAP")
            return

        self.clear_traffic()
        for packet in packets:
            self.add_packet_info(packet)
        self.statusBar().showMessage(
            f"Processed {len(packets)} packets from {Path(file_name).name}; "
            f"displaying latest {self.traffic_table.rowCount()}"
        )

    def start_capture(self) -> None:
        selected = self.interface_combo.currentData()
        if not isinstance(selected, CaptureInterface):
            QMessageBox.information(self, "Capture", "No network interface selected.")
            return
        interface = selected.device_name

        if self.capture_thread is not None:
            return

        self.capture_thread = QThread(self)
        self.capture_worker = PacketCaptureWorker(interface=interface)
        self.capture_worker.moveToThread(self.capture_thread)

        self.capture_thread.started.connect(self.capture_worker.run)
        self.capture_worker.packet_captured.connect(self.add_packet_info)
        self.capture_worker.status_changed.connect(self.statusBar().showMessage)
        self.capture_worker.failed.connect(self._capture_failed)
        self.capture_worker.finished.connect(self._capture_finished)
        self.capture_worker.finished.connect(self.capture_thread.quit)
        self.capture_worker.finished.connect(self.capture_worker.deleteLater)
        self.capture_thread.finished.connect(self.capture_thread.deleteLater)

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.import_button.setEnabled(False)
        self.clear_button.setEnabled(False)
        self.refresh_button.setEnabled(False)
        self.advanced_interfaces_checkbox.setEnabled(False)
        self.interface_combo.setEnabled(False)
        self.capture_thread.start()

    def stop_capture(self) -> None:
        if self.capture_worker is not None:
            self.capture_worker.stop()
            self.statusBar().showMessage("Stopping capture...")

    def _capture_failed(self, message: str) -> None:
        QMessageBox.warning(self, "Capture Error", message)

    def _capture_finished(self) -> None:
        self.capture_worker = None
        self.capture_thread = None
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.import_button.setEnabled(True)
        self.clear_button.setEnabled(True)
        self.refresh_button.setEnabled(True)
        self.advanced_interfaces_checkbox.setEnabled(True)
        self.interface_combo.setEnabled(True)

    def reload_rules(self) -> None:
        rules_path = Path(self.config.default_rules_path)
        if not rules_path.is_absolute():
            rules_path = Path.cwd() / rules_path

        try:
            result = load_rules(rules_path)
        except RuleParseError as exc:
            QMessageBox.warning(self, "Rules Error", str(exc))
            self.statusBar().showMessage("Failed to load rules")
            return

        self.rules = result.rules
        self.populate_rules_table()
        self.statusBar().showMessage(
            f"Loaded {len(result.rules)} rules from {Path(result.source_path).name}: "
            f"{result.valid_count} valid, {result.invalid_count} invalid"
        )

    def populate_rules_table(self) -> None:
        self.loading_rules_table = True
        self.rules_table.setRowCount(0)

        for row, rule in enumerate(self.rules):
            self.rules_table.insertRow(row)
            self._set_rule_item(
                row,
                0,
                "Enabled" if rule.is_valid else "Invalid",
                rule.enabled,
                checkable=rule.is_valid,
            )
            self._set_rule_item(row, 1, rule.display_sid)
            self._set_rule_item(row, 2, rule.protocol or "-")
            self._set_rule_item(row, 3, rule.display_source)
            self._set_rule_item(row, 4, rule.display_destination)
            self._set_rule_item(row, 5, rule.message or "-")
            self._set_rule_item(row, 6, rule.display_priority)
            self._set_rule_item(row, 7, str(rule.hit_count))
            self._set_rule_item(row, 8, rule.display_last_hit)
            self._set_rule_item(row, 9, rule.status_text)

        self.loading_rules_table = False

    def _set_rule_item(
        self,
        row: int,
        column: int,
        text: str,
        checked: bool = False,
        checkable: bool = False,
    ) -> None:
        item = self._table_item(text)
        if checkable:
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
        self.rules_table.setItem(row, column, item)

    def _table_item(self, text: str) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        item.setToolTip(text)
        return item

    def on_rule_item_changed(self, item: QTableWidgetItem) -> None:
        if self.loading_rules_table or item.column() != 0:
            return
        row = item.row()
        if 0 <= row < len(self.rules):
            self.rules[row].enabled = item.checkState() == Qt.CheckState.Checked

    def clear_traffic(self) -> None:
        self.traffic_table.setRowCount(0)
        self.alerts_table.setRowCount(0)
        self.threshold_detector.reset()
        for rule in self.rules:
            rule.hit_count = 0
            rule.last_hit = None
        self.total_packets = 0
        self.total_alerts = 0
        self.high_severity_alerts = 0
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}
        self.alert_severity_counts = {}
        self.alert_type_counts = {"rule_event": 0, "threshold_alert": 0}
        self.total_packets_label.setText("Total packets: 0")
        self.total_alerts_label.setText("Total alerts: 0")
        self.high_alerts_label.setText("High severity alerts: 0")
        self.update_statistics_labels()
        if self.rules:
            self.populate_rules_table()
        self.statusBar().showMessage("Traffic and current event view cleared")

    def add_packet_info(self, packet: PacketInfo) -> None:
        self.add_packet_summary(summary_from_packet_info(packet))
        self.detect_packet(packet)

    def detect_packet(self, packet: PacketInfo) -> None:
        signature_alerts = SignatureDetector(self.rules).detect(packet)
        threshold_alerts = self.threshold_detector.detect(packet)
        alerts = signature_alerts + threshold_alerts
        if not alerts:
            return

        for alert in alerts:
            self.database.insert_alert(alert)
            self.add_alert_event(alert)
        if signature_alerts:
            self.populate_rules_table()

    def add_alert_event(self, alert: AlertEvent) -> None:
        row = self.alerts_table.rowCount()
        self.alerts_table.insertRow(row)
        values = [
            alert.timestamp_text,
            str(alert.severity),
            alert.display_sid,
            alert.message,
            alert.protocol,
            alert.source_text,
            alert.destination_text,
            alert.alert_type,
        ]
        for column, value in enumerate(values):
            self.alerts_table.setItem(row, column, self._table_item(value))

        self.total_alerts += 1
        if alert.severity <= 2:
            self.high_severity_alerts += 1
        self.alert_severity_counts[alert.severity] = self.alert_severity_counts.get(alert.severity, 0) + 1
        self.alert_type_counts[alert.alert_type] = self.alert_type_counts.get(alert.alert_type, 0) + 1
        self.total_alerts_label.setText(f"Total alerts: {self.total_alerts}")
        self.high_alerts_label.setText(f"High severity alerts: {self.high_severity_alerts}")
        self.update_statistics_labels()

    def add_packet_summary(self, packet: PacketSummary) -> None:
        max_rows = self.config.capture.max_display_packets
        if self.traffic_table.rowCount() >= max_rows:
            self.traffic_table.removeRow(0)

        row = self.traffic_table.rowCount()
        self.traffic_table.insertRow(row)
        values = [
            packet.timestamp,
            packet.protocol,
            packet.source,
            packet.source_port,
            packet.destination,
            packet.destination_port,
            str(packet.length),
        ]
        for column, value in enumerate(values):
            self.traffic_table.setItem(row, column, self._table_item(value))

        self.total_packets += 1
        protocol = packet.protocol if packet.protocol in self.protocol_counts else "OTHER"
        self.protocol_counts[protocol] += 1
        self.total_packets_label.setText(f"Total packets: {self.total_packets}")
        self.update_statistics_labels()

    def update_statistics_labels(self) -> None:
        self.protocols_label.setText(
            "TCP / UDP / ICMP / ARP: "
            f"{self.protocol_counts['TCP']} / "
            f"{self.protocol_counts['UDP']} / "
            f"{self.protocol_counts['ICMP']} / "
            f"{self.protocol_counts['ARP']}"
        )
        if self.alert_severity_counts:
            severity_text = ", ".join(
                f"{severity}:{count}" for severity, count in sorted(self.alert_severity_counts.items())
            )
        else:
            severity_text = "-"
        self.alert_levels_label.setText(f"Alert severity counts: {severity_text}")
        self.alert_types_label.setText(
            "Rule events / Threshold alerts: "
            f"{self.alert_type_counts.get('rule_event', 0)} / "
            f"{self.alert_type_counts.get('threshold_alert', 0)}"
        )

    def closeEvent(self, event: object) -> None:
        if self.capture_worker is not None:
            self.capture_worker.stop()
            if self.capture_thread is not None:
                self.capture_thread.quit()
                self.capture_thread.wait(1500)
        super().closeEvent(event)
