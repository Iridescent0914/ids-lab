"""SQLite database initialization and basic persistence."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.parser.models import AlertEvent


SCHEMA_VERSION = 1


@dataclass(frozen=True)
class DatabaseInfo:
    path: Path
    schema_version: int


class DatabaseManager:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> DatabaseInfo:
        connection = self.connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

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

                CREATE TABLE IF NOT EXISTS app_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL
                );
                """
            )
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
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(alerts)").fetchall()
        }
        if "detector" in columns and "alert_type" not in columns:
            connection.execute("ALTER TABLE alerts RENAME COLUMN detector TO alert_type")

    def record_app_event(self, event_type: str, message: str) -> None:
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
                query += " WHERE alert_type = ?"
                parameters = (alert_type,)
            query += " ORDER BY id ASC"
            rows = connection.execute(query, parameters).fetchall()
        finally:
            connection.close()

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
        connection = self.connect()
        try:
            cursor = connection.execute("DELETE FROM alerts")
            connection.commit()
            return int(cursor.rowcount)
        finally:
            connection.close()
