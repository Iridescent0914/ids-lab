"""LightIDS SQLite 存储层。

本模块负责本地数据库的初始化和基础持久化操作。检测层产生的 ``AlertEvent`` 会
通过这里写入 SQLite；UI 的 Load History、Export CSV 和 Clear Logs 也通过这里
读取或清理历史告警。

当前数据库包含三张表：

* ``metadata``：保存 schema_version 等元信息；
* ``alerts``：保存规则事件和阈值告警；
* ``app_events``：保存应用启动等运行事件。
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.parser.models import AlertEvent


# 当前数据库结构版本。后续如果表结构发生不兼容变化，可以用它驱动迁移逻辑。
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class DatabaseInfo:
    """数据库初始化结果。

    ``initialize`` 返回该对象，方便调用方知道实际数据库路径和当前 schema 版本。
    """

    path: Path
    schema_version: int


class DatabaseManager:
    """LightIDS 的 SQLite 数据库管理器。

    该类采用“每个操作单独打开连接、提交后立即关闭”的方式。对于本项目的桌面
    应用规模，这种方式足够简单可靠，也能避免 Windows 下测试或关闭程序时数据库
    文件仍被连接占用。
    """

    def __init__(self, db_path: Path) -> None:
        """保存数据库文件路径。

        路径通常来自 ``config.storage.database_path``，并在 ``app.main`` 中解析到
        运行时可写目录。开发环境下通常是项目根目录的 ``data/lightids.db``。
        """
        self.db_path = db_path

    def connect(self) -> sqlite3.Connection:
        """创建一个 SQLite 连接。

        调用前会确保数据库父目录存在；``row_factory=sqlite3.Row`` 让查询结果可以
        通过列名访问，例如 ``row["message"]``，比纯元组更适合后续字段映射。
        """
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> DatabaseInfo:
        """初始化数据库表结构并写入 schema 版本。

        该方法在应用启动阶段调用。所有 ``CREATE TABLE`` 都使用
        ``IF NOT EXISTS``，因此重复调用是安全的。表创建后会执行轻量迁移，再把
        当前 ``SCHEMA_VERSION`` 写入 ``metadata``。
        """
        connection = self.connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                -- 统一告警表。rule_event 和 threshold_alert 都写入这里，通过
                -- alert_type 字段区分来源。
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    source_port INTEGER,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    protocol TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    rule_sid INTEGER,
                    message TEXT NOT NULL,
                    packet_length INTEGER,
                    alert_type TEXT NOT NULL
                );

                -- 应用级运行事件，例如启动成功。当前 UI 主要展示 alerts，
                -- app_events 保留给运行记录和后续扩展使用。
                CREATE TABLE IF NOT EXISTS app_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL
                );
                """
            )
            # 兼容旧版本数据库字段名。
            self._migrate_alerts_schema(connection)
            connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES(?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )
            connection.commit()
        finally:
            connection.close()
        return DatabaseInfo(path=self.db_path, schema_version=SCHEMA_VERSION)

    def _migrate_alerts_schema(self, connection: sqlite3.Connection) -> None:
        """执行 alerts 表的轻量兼容迁移。

        早期版本把告警来源字段命名为 ``detector``，后来语义调整为
        ``alert_type``，用于区分 ``rule_event`` 和 ``threshold_alert``。如果用户
        已经有旧数据库，这里会自动把旧列名改成新列名。
        """
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(alerts)").fetchall()
        }
        if "detector" in columns and "alert_type" not in columns:
            connection.execute("ALTER TABLE alerts RENAME COLUMN detector TO alert_type")

    def record_app_event(self, event_type: str, message: str) -> None:
        """记录应用级事件。

        当前启动流程会写入 ``application_initialized``，用于说明程序已经完成配置、
        日志和数据库初始化。时间使用 UTC ISO 字符串，便于跨时区排查日志。
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        connection = self.connect()
        try:
            connection.execute(
                """
                INSERT INTO app_events(timestamp, event_type, message)
                VALUES(?, ?, ?)
                """,
                (timestamp, event_type, message),
            )
            connection.commit()
        finally:
            connection.close()

    def insert_alert(self, alert: AlertEvent) -> int:
        """插入单条告警并返回自增 id。

        实时抓包时每个数据包产生的告警数量通常不多，可以直接使用单条插入。字段
        映射基本保持 ``AlertEvent`` 命名，只是在数据库中使用更明确的
        ``source_*`` / ``destination_*`` 列名。
        """
        connection = self.connect()
        try:
            cursor = connection.execute(
                """
                INSERT INTO alerts(
                    timestamp,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                    protocol,
                    severity,
                    rule_sid,
                    message,
                    packet_length,
                    alert_type
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    # datetime 以 ISO 字符串保存，读取时再用 fromisoformat 还原。
                    alert.timestamp.isoformat(),
                    alert.src_ip,
                    alert.src_port,
                    alert.dst_ip,
                    alert.dst_port,
                    alert.protocol,
                    alert.severity,
                    alert.rule_sid,
                    alert.message,
                    alert.packet_length,
                    alert.alert_type,
                ),
            )
            connection.commit()
            return int(cursor.lastrowid)
        finally:
            connection.close()

    def insert_alerts(self, alerts: list[AlertEvent]) -> int:
        """批量插入告警并返回插入数量。

        PCAP 导入时可能一次批处理产生多条告警，使用 ``executemany`` 能显著减少
        SQLite 提交次数和 UI 卡顿。空列表直接返回 0，避免打开无意义连接。
        """
        if not alerts:
            return 0

        connection = self.connect()
        try:
            connection.executemany(
                """
                INSERT INTO alerts(
                    timestamp,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                    protocol,
                    severity,
                    rule_sid,
                    message,
                    packet_length,
                    alert_type
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        # 与 insert_alert 保持完全一致的字段映射。
                        alert.timestamp.isoformat(),
                        alert.src_ip,
                        alert.src_port,
                        alert.dst_ip,
                        alert.dst_port,
                        alert.protocol,
                        alert.severity,
                        alert.rule_sid,
                        alert.message,
                        alert.packet_length,
                        alert.alert_type,
                    )
                    for alert in alerts
                ],
            )
            connection.commit()
            return len(alerts)
        finally:
            connection.close()

    def fetch_alerts(self, alert_type: str | None = None) -> list[AlertEvent]:
        """读取历史告警。

        ``alert_type`` 为 ``None`` 时返回全部告警；传入 ``rule_event`` 或
        ``threshold_alert`` 时只返回对应类型。结果按自增 id 升序排列，也就是按写入
        顺序展示，符合 UI 的历史查看和 CSV 导出预期。
        """
        connection = self.connect()
        try:
            query = """
            SELECT
                timestamp,
                source_ip,
                source_port,
                destination_ip,
                destination_port,
                protocol,
                severity,
                rule_sid,
                message,
                packet_length,
                alert_type
            FROM alerts
            """
            parameters: tuple[str, ...] = ()
            if alert_type is not None:
                # 使用参数化查询，避免字符串拼接带来的 SQL 注入风险。
                query += " WHERE alert_type = ?"
                parameters = (alert_type,)
            query += " ORDER BY id ASC"
            rows = connection.execute(query, parameters).fetchall()
        finally:
            connection.close()

        # 数据库行转换回统一的 AlertEvent，UI 和导出层就不需要理解 SQLite 字段名。
        return [
            AlertEvent(
                timestamp=datetime.fromisoformat(row["timestamp"]),
                message=str(row["message"]),
                severity=int(row["severity"]),
                protocol=str(row["protocol"]),
                alert_type=str(row["alert_type"]),
                src_ip=row["source_ip"],
                dst_ip=row["destination_ip"],
                src_port=row["source_port"],
                dst_port=row["destination_port"],
                rule_sid=row["rule_sid"],
                packet_length=int(row["packet_length"] or 0),
            )
            for row in rows
        ]

    def clear_alerts(self) -> int:
        """清空历史告警并返回删除条数。

        只清理 ``alerts`` 表，不清理 ``metadata`` 和 ``app_events``。这对应 UI 中
        Clear Logs 的语义：删除历史检测结果，但保留数据库结构版本和应用运行记录。
        """
        connection = self.connect()
        try:
            cursor = connection.execute("DELETE FROM alerts")
            connection.commit()
            return int(cursor.rowcount)
        finally:
            connection.close()




# DatabaseManager
#   connect()              创建 SQLite 连接
#   initialize()           初始化 metadata / alerts / app_events
#   record_app_event()     记录应用运行事件
#   insert_alert()         写入单条告警
#   insert_alerts()        批量写入告警
#   fetch_alerts()         查询历史告警
#   clear_alerts()         清空历史告警