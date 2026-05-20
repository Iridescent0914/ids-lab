"""LightIDS 主窗口。

该模块是 PyQt6 图形界面的核心编排层。它负责：

* 构建工具栏、Traffic/Alerts/Rules/Statistics 四个页面；
* 启动和停止实时抓包线程；
* 启动和停止 PCAP 后台导入线程；
* 把 ``PacketInfo`` 送入规则检测和阈值检测；
* 把告警写入 SQLite，并刷新表格、规则命中和统计视图；
* 读取历史告警、按类型筛选、导出 CSV 和清空历史告警。

真正的抓包、解析、检测和存储逻辑分别放在 capture/parser/detection/storage 模块，
主窗口只负责把这些模块连接成用户可操作的应用流程。
"""

from __future__ import annotations

import csv
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
from app.capture.pcap_importer import PcapImportWorker
from app.core.config import AppConfig
from app.detection.signature_detector import SignatureDetector
from app.detection.threshold_detector import ThresholdDetector, ThresholdSettings
from app.parser.models import AlertEvent, PacketInfo
from app.rules.models import DetectionRule
from app.rules.rule_parser import RuleParseError, load_rules
from app.storage.database import DatabaseManager


class MainWindow(QMainWindow):
    """LightIDS 的主界面窗口。

    ``MainWindow`` 持有应用配置、数据库管理器、检测器、后台线程和 UI 控件状态。
    它是“事件驱动”的：用户点击按钮或后台 Worker 发出信号后，对应槽函数会更新
    界面、调用检测逻辑或读写数据库。
    """

    def __init__(self, config: AppConfig, database: DatabaseManager) -> None:
        """初始化主窗口状态并构建界面。

        ``config`` 来自 ``app.core.config.load_config``，``database`` 已经在
        ``app.main.bootstrap`` 中完成初始化。构造函数只保存依赖、初始化运行状态，
        然后搭建状态栏、工具栏、标签页并加载默认规则。
        """
        super().__init__()
        self.config = config
        self.database = database

        # 实时抓包线程和 Worker。Worker 负责在后台调用 Scapy sniff，
        # 主线程通过 PyQt 信号接收 PacketInfo。
        self.capture_thread: QThread | None = None
        self.capture_worker: PacketCaptureWorker | None = None

        # PCAP 后台导入线程和 Worker。导入大文件时分批发回 PacketInfo，避免阻塞 UI。
        self.pcap_import_thread: QThread | None = None
        self.pcap_import_worker: PcapImportWorker | None = None
        self.pcap_import_name = ""
        self.pcap_import_had_error = False

        # 上一次实时抓包使用的网卡，用于切换网卡时提示是否清空当前会话。
        self.last_capture_interface: str | None = None
        self.available_interfaces: list[CaptureInterface] = []

        # 规则和单包规则检测器。reload_rules() 会重新加载 rules 并重建检测器。
        self.rules: list[DetectionRule] = []
        self.signature_detector = SignatureDetector(self.rules)
        # 填充 Rules 表格时会触发 itemChanged；该标志用于区分程序填表和用户点击。
        self.loading_rules_table = False

        # 行为阈值检测器保存滑动窗口状态；新会话或清空流量时需要 reset。
        self.threshold_detector = ThresholdDetector(self._threshold_settings())

        # 当前视图统计，只反映本次会话或当前载入的历史视图，不等于数据库总量。
        self.total_packets = 0
        self.total_alerts = 0
        self.high_severity_alerts = 0
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}
        self.alert_severity_counts: dict[int, int] = {}
        self.alert_type_counts = {"rule_event": 0, "threshold_alert": 0}
        # 当前 Alerts 视图的数据源。筛选时会基于它重建 Alerts 表格。
        self.current_alerts: list[AlertEvent] = []

        self.setWindowTitle(config.app_name)
        self.resize(1100, 720)

        self._build_status_bar()
        self._build_toolbar()
        self._build_tabs()
        self.reload_rules()

    def _threshold_settings(self) -> ThresholdSettings:
        """把应用配置转换为阈值检测器需要的配置对象。"""
        return ThresholdSettings(
            window_seconds=self.config.threshold.window_seconds,
            port_scan_unique_ports=self.config.threshold.port_scan_unique_ports,
            horizontal_scan_unique_hosts=self.config.threshold.horizontal_scan_unique_hosts,
            icmp_high_frequency_count=self.config.threshold.icmp_high_frequency_count,
        )

    def _reset_threshold_detector(self) -> None:
        """清空阈值检测器的滑动窗口状态。"""
        self.threshold_detector.reset()

    def _build_toolbar(self) -> None:
        """创建顶部工具栏并连接按钮事件。

        工具栏分成两组：Capture 负责网卡选择和实时抓包；Data 负责 PCAP 导入、
        清空当前视图、规则重载、告警筛选、历史读取、CSV 导出和历史清理。
        """
        capture_toolbar = QToolBar("Capture")
        capture_toolbar.setMovable(False)
        data_toolbar = QToolBar("Data")
        data_toolbar.setMovable(False)

        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(260)
        self.advanced_interfaces_checkbox = QCheckBox("Show advanced interfaces")
        self.refresh_button = QPushButton("Refresh Interfaces")
        self.start_button = QPushButton("Start Capture")
        self.stop_button = QPushButton("Stop")
        self.import_button = QPushButton("Import PCAP")
        self.clear_button = QPushButton("Clear Traffic")
        self.rules_button = QPushButton("Reload Rules")
        self.alert_filter_combo = QComboBox()
        self.load_history_button = QPushButton("Load History")
        self.export_button = QPushButton("Export CSV")
        self.clear_logs_button = QPushButton("Clear Logs")

        self.stop_button.setEnabled(False)
        # combo item 的 userData 保存实际过滤值；None 表示不过滤。
        self.alert_filter_combo.addItem("All alerts", None)
        self.alert_filter_combo.addItem("Rule events", "rule_event")
        self.alert_filter_combo.addItem("Threshold alerts", "threshold_alert")

        capture_toolbar.addWidget(self.interface_combo)
        capture_toolbar.addWidget(self.advanced_interfaces_checkbox)
        capture_toolbar.addWidget(self.refresh_button)
        capture_toolbar.addSeparator()
        capture_toolbar.addWidget(self.start_button)
        capture_toolbar.addWidget(self.stop_button)

        data_toolbar.addWidget(self.import_button)
        data_toolbar.addWidget(self.clear_button)
        data_toolbar.addSeparator()
        data_toolbar.addWidget(self.rules_button)
        data_toolbar.addSeparator()
        data_toolbar.addWidget(QLabel("Alert filter:"))
        data_toolbar.addWidget(self.alert_filter_combo)
        data_toolbar.addWidget(self.load_history_button)
        data_toolbar.addWidget(self.export_button)
        data_toolbar.addWidget(self.clear_logs_button)

        self.addToolBar(capture_toolbar)
        self.addToolBarBreak()
        self.addToolBar(data_toolbar)

        # PyQt 信号连接到主窗口槽函数。后台 Worker 的信号连接在启动线程时完成。
        self.refresh_button.clicked.connect(self.refresh_interfaces)
        self.advanced_interfaces_checkbox.toggled.connect(self.populate_interface_combo)
        self.interface_combo.currentIndexChanged.connect(self.update_interface_hint)
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.import_button.clicked.connect(self.import_pcap)
        self.clear_button.clicked.connect(self.clear_traffic)
        self.rules_button.clicked.connect(self.reload_rules)
        self.alert_filter_combo.currentIndexChanged.connect(self.apply_alert_filter)
        self.load_history_button.clicked.connect(self.load_alert_history)
        self.export_button.clicked.connect(self.export_alerts_csv)
        self.clear_logs_button.clicked.connect(self.clear_alert_logs)
        self.refresh_interfaces()

    def _build_tabs(self) -> None:
        """创建四个主标签页并设置为中央控件。"""
        tabs = QTabWidget()
        tabs.addTab(self._traffic_tab(), "Traffic")
        tabs.addTab(self._alerts_tab(), "Alerts")
        tabs.addTab(self._rules_tab(), "Rules")
        tabs.addTab(self._statistics_tab(), "Statistics")
        self.setCentralWidget(tabs)

    def _traffic_tab(self) -> QWidget:
        """创建 Traffic 表格页。

        每一行对应一个 ``PacketSummary``，展示包时间、协议、源/目的地址端口和长度。
        """
        self.traffic_table = QTableWidget(0, 7)
        self.traffic_table.setHorizontalHeaderLabels(
            ["Time", "Protocol", "Source", "Source Port", "Destination", "Destination Port", "Length"]
        )
        return self._table_page(self.traffic_table)

    def _alerts_tab(self) -> QWidget:
        """创建 Alerts 表格页。

        Alerts 页面显示当前视图中的告警，既可以是实时/导入产生的新告警，也可以是
        从 SQLite 加载的历史告警。
        """
        self.alerts_table = QTableWidget(0, 8)
        self.alerts_table.setHorizontalHeaderLabels(
            ["Time", "Severity", "SID", "Message", "Protocol", "Source", "Destination", "Type"]
        )
        return self._table_page(self.alerts_table)

    def _rules_tab(self) -> QWidget:
        """创建 Rules 表格页。

        规则表展示规则启用状态、SID、匹配范围、消息、优先级、命中次数和语法状态。
        第一列可勾选，用于启用或禁用合法规则。
        """
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
        """创建 Statistics 统计页。"""
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
            f"{self.config.threshold.horizontal_scan_unique_hosts} hosts / "
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
        """为表格应用统一显示风格并包装成页面。"""
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
        """创建底部状态栏并展示数据库、规则路径。"""
        status = QStatusBar()
        status.showMessage(
            f"Ready | DB: {self.config.database_path} | Rules: {self.config.default_rules_path}"
        )
        self.setStatusBar(status)

    def refresh_interfaces(self) -> None:
        """重新枚举本机可抓包网卡。

        网卡枚举依赖本机 Scapy/Npcap 环境，可能因为未安装 Npcap、权限不足或平台
        差异失败；失败时弹窗提示，不让异常退出整个 GUI。
        """
        self.interface_combo.clear()
        try:
            self.available_interfaces = list_interfaces()
        except Exception as exc:  # pragma: no cover - depends on local Scapy/Npcap
            QMessageBox.warning(self, "Interface Error", f"Failed to list interfaces:\n{exc}")
            self.statusBar().showMessage("Failed to list interfaces")
            return

        self.populate_interface_combo()

    def populate_interface_combo(self, checked: bool | None = None) -> None:
        """根据“是否显示高级接口”刷新网卡下拉框。

        ``list_interfaces`` 会把常用真实网卡和虚拟/VPN/特殊接口做分类。默认只显示
        常用接口，勾选 Show advanced interfaces 后展示全部接口。
        """
        current = self.interface_combo.currentData()
        current_device = current.device_name if isinstance(current, CaptureInterface) else ""
        self.interface_combo.clear()
        show_advanced = self.advanced_interfaces_checkbox.isChecked()
        visible_interfaces = [
            item for item in self.available_interfaces if show_advanced or item.is_common
        ]

        for capture_interface in visible_interfaces:
            # 文本显示友好名称，userData 保存真正传给 Scapy sniff 的底层接口名。
            self.interface_combo.addItem(capture_interface.display_name, capture_interface)
            item_index = self.interface_combo.count() - 1
            self.interface_combo.setItemData(
                item_index,
                f"{capture_interface.hint}\nDevice: {capture_interface.device_name}",
                Qt.ItemDataRole.ToolTipRole,
            )

        if current_device:
            # 刷新列表时尽量保留用户当前选择，减少勾选高级接口时的跳动。
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
        """更新当前网卡的 tooltip 和状态栏提示。"""
        selected = self.interface_combo.currentData()
        if not isinstance(selected, CaptureInterface):
            return

        self.interface_combo.setToolTip(f"{selected.hint}\nDevice: {selected.device_name}")
        self.statusBar().showMessage(f"Current interface: {selected.display_name}. {selected.hint}")

    def import_pcap(self) -> None:
        """选择并后台导入 PCAP/PCAPNG 文件。

        导入前会清空当前 Traffic/Alerts/Statistics 视图，因为离线检测通常代表一次
        独立测试会话。实际读取在 ``PcapImportWorker`` 所在线程中完成，主线程只接收
        分批 ``PacketInfo`` 并执行检测/刷新。
        """
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Import PCAP",
            "",
            "Packet captures (*.pcap *.pcapng);;All files (*.*)",
        )
        if not file_name:
            return
        if self.capture_thread is not None or self.pcap_import_thread is not None:
            return

        # 新的离线导入视为新会话，先清空当前界面和阈值窗口。
        self.clear_traffic()
        self.pcap_import_name = Path(file_name).name
        self.pcap_import_had_error = False
        self.pcap_import_thread = QThread(self)
        self.pcap_import_worker = PcapImportWorker(Path(file_name))
        self.pcap_import_worker.moveToThread(self.pcap_import_thread)

        # QThread 只提供线程环境，真正工作逻辑在 Worker.run() 中。
        self.pcap_import_thread.started.connect(self.pcap_import_worker.run)
        # Worker 每发一批包，主线程就批量追加表格、检测并写库。
        self.pcap_import_worker.packet_batch.connect(self.add_packet_batch)
        self.pcap_import_worker.status_changed.connect(self.statusBar().showMessage)
        self.pcap_import_worker.failed.connect(self._pcap_import_failed)
        self.pcap_import_worker.finished.connect(self._pcap_import_finished)
        self.pcap_import_worker.finished.connect(self.pcap_import_thread.quit)
        self.pcap_import_worker.finished.connect(self.pcap_import_worker.deleteLater)
        self.pcap_import_thread.finished.connect(self.pcap_import_thread.deleteLater)

        self._set_busy_controls()
        self.pcap_import_thread.start()
        self.statusBar().showMessage(
            f"Importing {self.pcap_import_name} in background..."
        )

    def start_capture(self) -> None:
        """启动实时抓包。

        实时抓包会创建 ``PacketCaptureWorker`` 并移动到后台 ``QThread``。每捕获一个
        原始包，Worker 会解析成 ``PacketInfo``，再通过信号发回主线程。
        """
        selected = self.interface_combo.currentData()
        if not isinstance(selected, CaptureInterface):
            QMessageBox.information(self, "Capture", "No network interface selected.")
            return
        interface = selected.device_name

        if self.capture_thread is not None:
            return

        if not self._confirm_new_interface_session(interface):
            return

        # 新的实时抓包会话需要清空行为检测窗口，避免上一轮包影响本轮阈值告警。
        self._reset_threshold_detector()
        self.capture_thread = QThread(self)
        self.capture_worker = PacketCaptureWorker(
            interface=interface,
            timeout_seconds=self.config.capture.default_timeout_seconds,
        )
        self.capture_worker.moveToThread(self.capture_thread)

        # 抓包 Worker 的信号都回到主线程处理，避免后台线程直接操作 UI 控件。
        self.capture_thread.started.connect(self.capture_worker.run)
        self.capture_worker.packet_captured.connect(self.add_packet_info)
        self.capture_worker.status_changed.connect(self.statusBar().showMessage)
        self.capture_worker.failed.connect(self._capture_failed)
        self.capture_worker.finished.connect(self._capture_finished)
        self.capture_worker.finished.connect(self.capture_thread.quit)
        self.capture_worker.finished.connect(self.capture_worker.deleteLater)
        self.capture_thread.finished.connect(self.capture_thread.deleteLater)

        self._set_busy_controls()
        self.last_capture_interface = interface
        self.capture_thread.start()

    def stop_capture(self) -> None:
        """停止当前后台任务。

        Stop 按钮同时服务实时抓包和 PCAP 导入。两个 Worker 都是协作式停止：这里
        设置停止标志，Worker 会在当前 sniff/读取批次结束后自然退出。
        """
        if self.pcap_import_worker is not None:
            self.pcap_import_worker.stop()
            self.statusBar().showMessage("Stopping PCAP import...")
            return
        if self.capture_worker is not None:
            self.capture_worker.stop()
            self.statusBar().showMessage("Stopping capture...")

    def _capture_failed(self, message: str) -> None:
        """显示实时抓包错误。"""
        QMessageBox.warning(self, "Capture Error", message)

    def _capture_finished(self) -> None:
        """实时抓包 Worker 结束后的 UI 状态恢复。"""
        self.capture_worker = None
        self.capture_thread = None
        self._set_idle_controls()

    def _pcap_import_failed(self, message: str) -> None:
        """记录 PCAP 导入失败并显示错误。"""
        self.pcap_import_had_error = True
        QMessageBox.warning(self, "PCAP Error", message)

    def _pcap_import_finished(self, processed_count: int, cancelled: bool) -> None:
        """PCAP 导入结束后的清理和状态栏提示。

        ``finished`` 信号可能发生在正常完成、用户停止或读取失败之后。失败信息由
        ``_pcap_import_failed`` 先记录到 ``pcap_import_had_error``，这里统一恢复按钮
        并给出最终处理数量。
        """
        imported_name = self.pcap_import_name
        had_error = self.pcap_import_had_error
        self.pcap_import_worker = None
        self.pcap_import_thread = None
        self.pcap_import_name = ""
        self.pcap_import_had_error = False
        self._set_idle_controls()
        if had_error:
            self.statusBar().showMessage(
                f"PCAP import failed after {processed_count} packets from {imported_name}"
            )
            return
        if cancelled:
            self.statusBar().showMessage(
                f"PCAP import stopped after {processed_count} packets from {imported_name}; "
                f"displaying latest {self.traffic_table.rowCount()} packets and "
                f"{self.alerts_table.rowCount()} alerts"
            )
            return
        self.statusBar().showMessage(
            f"Processed {processed_count} packets from {imported_name}; "
            f"displaying latest {self.traffic_table.rowCount()} packets and "
            f"{self.alerts_table.rowCount()} of {self.total_alerts} alerts"
        )

    def _set_idle_controls(self) -> None:
        """恢复空闲状态下可点击的控件。"""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.import_button.setEnabled(True)
        self.clear_button.setEnabled(True)
        self.refresh_button.setEnabled(True)
        self.rules_button.setEnabled(True)
        self.load_history_button.setEnabled(True)
        self.export_button.setEnabled(True)
        self.clear_logs_button.setEnabled(True)
        self.alert_filter_combo.setEnabled(True)
        self.advanced_interfaces_checkbox.setEnabled(True)
        self.interface_combo.setEnabled(True)

    def _set_busy_controls(self) -> None:
        """进入后台任务运行状态。

        抓包或导入期间禁用会改变数据源、规则和历史视图的按钮，只保留 Stop，避免
        用户在 Worker 运行时同时启动另一个任务或清空正在写入的视图。
        """
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.import_button.setEnabled(False)
        self.clear_button.setEnabled(False)
        self.refresh_button.setEnabled(False)
        self.rules_button.setEnabled(False)
        self.load_history_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.clear_logs_button.setEnabled(False)
        self.alert_filter_combo.setEnabled(False)
        self.advanced_interfaces_checkbox.setEnabled(False)
        self.interface_combo.setEnabled(False)

    def load_alert_history(self) -> None:
        """从 SQLite 加载历史告警到当前 Alerts 视图。

        加载历史不会恢复 Traffic 表，因为数据库只保存告警，不保存每个数据包。
        如果当前 Alerts 视图已有数据，先询问用户是否替换。
        """
        if self._has_current_alert_view_data():
            answer = QMessageBox.question(
                self,
                "Load History",
                "Replace the current Alerts view with historical alerts from SQLite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        alerts = self.database.fetch_alerts()
        self.load_alerts_into_current_view(alerts)

        filter_text = self.alert_filter_combo.currentText()
        matching_count = self.count_matching_current_alerts()
        self.statusBar().showMessage(
            f"Loaded {len(alerts)} alerts from SQLite; "
            f"showing {self.alerts_table.rowCount()} of {matching_count} {filter_text.lower()}"
        )

    def export_alerts_csv(self) -> None:
        """把 SQLite 中符合当前筛选条件的告警导出为 CSV。

        导出从数据库读取完整历史数据，而不是只导出当前 Alerts 表格中可见的最多
        1000 行，避免大 PCAP 场景下导出数据不完整。
        """
        alert_filter = self.current_alert_filter()
        alerts = self.database.fetch_alerts(alert_filter)
        if not alerts:
            QMessageBox.information(self, "Export CSV", "No matching alerts to export.")
            return

        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Export Alerts CSV",
            "lightids_alerts.csv",
            "CSV files (*.csv);;All files (*.*)",
        )
        if not file_name:
            return

        export_path = Path(file_name)
        if export_path.suffix.lower() != ".csv":
            # 用户没有写扩展名时自动补 .csv。
            export_path = export_path.with_suffix(".csv")

        headers = ["Time", "Severity", "SID", "Message", "Protocol", "Source", "Destination", "Type"]
        try:
            # utf-8-sig 方便 Windows Excel 直接识别中文和 UTF-8 内容。
            with export_path.open("w", newline="", encoding="utf-8-sig") as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(headers)
                for alert in alerts:
                    writer.writerow(self._alert_csv_row(alert))
        except OSError as exc:
            QMessageBox.warning(self, "Export CSV", f"Failed to export CSV:\n{exc}")
            self.statusBar().showMessage("Failed to export alerts CSV")
            return

        filter_text = self.alert_filter_combo.currentText()
        self.statusBar().showMessage(
            f"Exported {len(alerts)} {filter_text.lower()} from SQLite to {export_path}"
        )

    def current_alert_filter(self) -> str | None:
        """返回当前告警类型筛选值。"""
        value = self.alert_filter_combo.currentData()
        return str(value) if value is not None else None

    def _alert_csv_row(self, alert: AlertEvent) -> list[str]:
        """把告警对象转换为 CSV 一行。"""
        return [
            alert.timestamp_text,
            str(alert.severity),
            alert.display_sid,
            alert.message,
            alert.protocol,
            alert.source_text,
            alert.destination_text,
            alert.alert_type,
        ]

    def clear_alert_logs(self) -> None:
        """清空 SQLite 中的历史告警。

        这只影响数据库中的 alerts 表和当前 Alerts 视图，不删除 Traffic 行、规则文件、
        配置文件或 logs/lightids.log。
        """
        answer = QMessageBox.question(
            self,
            "Clear Logs",
            "Clear all historical alert records from SQLite?\n\n"
            "This will not delete Traffic rows, rules, config files, or logs/lightids.log.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        deleted_count = self.database.clear_alerts()
        self.clear_alert_view()
        self.statusBar().showMessage(
            f"Cleared {deleted_count} historical alert records; new detections will be stored again"
        )

    def reload_rules(self) -> None:
        """重新加载默认规则文件并刷新 Rules 表格。

        规则文件路径来自配置。加载成功后会重建 ``SignatureDetector``，让后续检测
        使用最新规则；加载失败则保留当前规则和检测器。
        """
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
        self.signature_detector = SignatureDetector(self.rules)
        self.populate_rules_table()
        self.statusBar().showMessage(
            f"Loaded {len(result.rules)} rules from {Path(result.source_path).name}: "
            f"{result.valid_count} valid, {result.invalid_count} invalid"
        )

    def populate_rules_table(self) -> None:
        """把当前规则列表渲染到 Rules 表格。"""
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
        """设置 Rules 表格中的一个单元格。

        第一列需要可勾选，用来控制规则启用状态；其他列只显示文本。
        """
        item = self._table_item(text)
        if checkable:
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
        self.rules_table.setItem(row, column, item)

    def _table_item(self, text: str) -> QTableWidgetItem:
        """创建统一风格的表格单元格。

        tooltip 保留完整文本，避免长消息被列宽截断后看不全。
        """
        item = QTableWidgetItem(text)
        item.setToolTip(text)
        return item

    def on_rule_item_changed(self, item: QTableWidgetItem) -> None:
        """处理用户在 Rules 表格中启用/禁用规则。"""
        if self.loading_rules_table or item.column() != 0:
            return
        row = item.row()
        if 0 <= row < len(self.rules):
            self.rules[row].enabled = item.checkState() == Qt.CheckState.Checked

    def clear_traffic(self) -> None:
        """清空当前会话的 Traffic、Alerts、统计和规则命中状态。

        该方法不会清空 SQLite 历史告警；历史清理由 ``clear_alert_logs`` 完成。
        """
        self.traffic_table.setRowCount(0)
        self.clear_alert_view(refresh_statistics=False)
        self._reset_threshold_detector()
        self.last_capture_interface = None
        for rule in self.rules:
            rule.hit_count = 0
            rule.last_hit = None
        self.total_packets = 0
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}
        self.refresh_statistics_view()
        if self.rules:
            self.populate_rules_table()
        self.statusBar().showMessage("Traffic and current event view cleared")

    def clear_alert_view(self, refresh_statistics: bool = True) -> None:
        """清空当前 Alerts 视图和告警统计。"""
        self.alerts_table.setRowCount(0)
        self.current_alerts = []
        self.reset_alert_statistics()
        if refresh_statistics:
            self.refresh_statistics_view()

    def reset_alert_statistics(self) -> None:
        """重置当前视图中的告警统计计数。"""
        self.total_alerts = 0
        self.high_severity_alerts = 0
        self.alert_severity_counts = {}
        self.alert_type_counts = {"rule_event": 0, "threshold_alert": 0}

    def load_alerts_into_current_view(self, alerts: list[AlertEvent]) -> None:
        """把一批告警作为当前 Alerts 视图的数据源。"""
        self.current_alerts = list(alerts)
        self.recalculate_alert_statistics()
        self.rebuild_alert_table_from_current_alerts()
        self.refresh_statistics_view()

    def recalculate_alert_statistics(self) -> None:
        """根据 ``current_alerts`` 重新计算告警统计。"""
        self.reset_alert_statistics()
        for alert in self.current_alerts:
            self.record_alert_statistics(alert)

    def record_alert_statistics(self, alert: AlertEvent) -> None:
        """把单条告警计入当前统计。"""
        self.total_alerts += 1
        if alert.severity <= 2:
            self.high_severity_alerts += 1
        self.alert_severity_counts[alert.severity] = self.alert_severity_counts.get(alert.severity, 0) + 1
        self.alert_type_counts[alert.alert_type] = self.alert_type_counts.get(alert.alert_type, 0) + 1

    def _has_current_session_data(self) -> bool:
        """当前会话是否已有流量或告警数据。"""
        return (
            self.total_packets > 0
            or self.total_alerts > 0
            or self.traffic_table.rowCount() > 0
            or self.alerts_table.rowCount() > 0
        )

    def _has_current_alert_view_data(self) -> bool:
        """当前 Alerts 视图是否已有告警数据。"""
        return self.total_alerts > 0 or self.alerts_table.rowCount() > 0 or bool(self.current_alerts)

    def apply_alert_filter(self, index: int | None = None) -> None:
        """应用告警类型筛选并重建 Alerts 表格。"""
        self.rebuild_alert_table_from_current_alerts()
        self.refresh_statistics_view()
        matching_count = self.count_matching_current_alerts()
        self.statusBar().showMessage(
            f"Showing {self.alerts_table.rowCount()} of {matching_count} "
            f"{self.alert_filter_combo.currentText().lower()}"
        )

    def count_matching_current_alerts(self) -> int:
        """统计当前筛选条件下应显示的告警数量。"""
        return sum(1 for alert in self.current_alerts if self.alert_matches_current_filter(alert))

    def alert_matches_current_filter(self, alert: AlertEvent) -> bool:
        """判断告警是否匹配当前类型筛选。"""
        alert_filter = self.current_alert_filter()
        return alert_filter is None or alert.alert_type == alert_filter

    def rebuild_alert_table_from_current_alerts(self) -> None:
        """从 ``current_alerts`` 重建 Alerts 表格。

        切换筛选条件或加载历史告警时使用。重建期间临时关闭表格更新，减少闪烁。
        """
        self.alerts_table.setUpdatesEnabled(False)
        try:
            self.alerts_table.setRowCount(0)
            for alert in self.current_alerts:
                if self.alert_matches_current_filter(alert):
                    self.append_alert_row(alert)
        finally:
            self.alerts_table.setUpdatesEnabled(True)

    def _confirm_new_interface_session(self, interface: str) -> bool:
        """切换实时抓包网卡前确认是否清空当前会话。

        如果用户选择了不同接口且当前会话已有数据，继续混在同一 Traffic/Statistics
        视图中容易误解，因此这里询问是否清空；Cancel 会中止启动抓包。
        """
        if self.last_capture_interface in {None, interface}:
            return True
        if not self._has_current_session_data():
            return True

        answer = QMessageBox.question(
            self,
            "Switch Interface",
            "You selected a different network interface.\n\n"
            "Clear the current Traffic, Alerts, and Statistics before starting?",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No
            | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Yes,
        )
        if answer == QMessageBox.StandardButton.Cancel:
            return False
        if answer == QMessageBox.StandardButton.Yes:
            self.clear_traffic()
        return True

    def add_packet_info(self, packet: PacketInfo) -> None:
        """处理实时抓包 Worker 发来的单个数据包。"""
        self.add_packet_summary(summary_from_packet_info(packet))
        self.detect_packet(packet)

    def add_packet_batch(self, packets: list[PacketInfo]) -> None:
        """处理 PCAP 导入 Worker 发来的批量数据包。

        批量路径会暂时关闭表格更新，并把告警汇总后一次性批量写入数据库。这样比
        每个包都刷新统计、刷新规则表和单条插入 SQLite 更适合大 PCAP。
        """
        if not packets:
            return

        self.traffic_table.setUpdatesEnabled(False)
        self.alerts_table.setUpdatesEnabled(False)
        rules_changed = False
        batch_alerts: list[AlertEvent] = []
        try:
            for packet in packets:
                # Traffic 表格仍逐包追加，但统计刷新推迟到批处理结束。
                self.add_packet_summary(summary_from_packet_info(packet), refresh_statistics=False)
                alerts, has_signature_alerts = self.detect_packet_alerts(packet)
                batch_alerts.extend(alerts)
                rules_changed = has_signature_alerts or rules_changed
                for alert in alerts:
                    # 告警先进入当前视图和统计，数据库写入在循环后统一完成。
                    self.add_alert_event(alert, refresh_statistics=False)
        finally:
            self.traffic_table.setUpdatesEnabled(True)
            self.alerts_table.setUpdatesEnabled(True)

        self.database.insert_alerts(batch_alerts)
        if rules_changed:
            self.populate_rules_table()
        self.refresh_statistics_view()

    def detect_packet_alerts(self, packet: PacketInfo) -> tuple[list[AlertEvent], bool]:
        """对单个数据包执行规则检测和阈值检测。

        返回 ``(alerts, has_signature_alerts)``。第二个布尔值用于判断是否需要刷新
        Rules 表格中的命中次数和最近命中时间。
        """
        signature_alerts = self.signature_detector.detect(packet)
        threshold_alerts = self.threshold_detector.detect(packet)
        return signature_alerts + threshold_alerts, bool(signature_alerts)

    def detect_packet(
        self,
        packet: PacketInfo,
        refresh_rules: bool = True,
        refresh_statistics: bool = True,
    ) -> bool:
        """检测单个数据包并立即写库、刷新界面。

        实时抓包路径使用该方法。PCAP 批量导入为了性能会调用
        ``detect_packet_alerts`` 后自行批量写库。
        """
        alerts, has_signature_alerts = self.detect_packet_alerts(packet)
        if not alerts:
            return False

        self.database.insert_alerts(alerts)
        for alert in alerts:
            self.add_alert_event(alert, refresh_statistics=refresh_statistics)
        if has_signature_alerts and refresh_rules:
            self.populate_rules_table()
        return has_signature_alerts

    def add_alert_event(self, alert: AlertEvent, refresh_statistics: bool = True) -> None:
        """把告警加入当前视图数据源、统计和表格。"""
        self.current_alerts.append(alert)
        self.record_alert_statistics(alert)
        if self.alert_matches_current_filter(alert):
            self.append_alert_row(alert)

        if refresh_statistics:
            self.refresh_statistics_view()

    def append_alert_row(self, alert: AlertEvent) -> None:
        """向 Alerts 表格追加一行。

        表格只保留配置中的最大行数，避免长时间抓包或大 PCAP 导入导致 UI 过重。
        数据库仍会保存完整历史。
        """
        max_rows = self.config.capture.max_display_alerts
        if self.alerts_table.rowCount() >= max_rows:
            self.alerts_table.removeRow(0)

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

    def add_packet_summary(self, packet: PacketSummary, refresh_statistics: bool = True) -> None:
        """向 Traffic 表格追加一行数据包摘要并更新协议统计。"""
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
        if refresh_statistics:
            self.refresh_statistics_view()

    def refresh_statistics_view(self) -> None:
        """刷新 Statistics 页面中的主计数。"""
        self.total_packets_label.setText(f"Total packets: {self.total_packets}")
        self.total_alerts_label.setText(f"Total alerts: {self.total_alerts}")
        self.high_alerts_label.setText(f"High severity alerts: {self.high_severity_alerts}")
        self.update_statistics_labels()

    def update_statistics_labels(self) -> None:
        """刷新协议分布、严重级别分布和告警类型分布。"""
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
        """窗口关闭时停止后台 Worker 并等待线程退出。

        这里尽量给抓包/导入线程一个短时间窗口自然退出，避免关闭窗口后后台线程继续
        访问已经销毁的 UI 对象。
        """
        if self.pcap_import_worker is not None:
            self.pcap_import_worker.stop()
            if self.pcap_import_thread is not None:
                self.pcap_import_thread.quit()
                self.pcap_import_thread.wait(1500)
        if self.capture_worker is not None:
            self.capture_worker.stop()
            if self.capture_thread is not None:
                self.capture_thread.quit()
                self.capture_thread.wait(1500)
        super().closeEvent(event)
