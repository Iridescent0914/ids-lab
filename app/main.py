"""Application entry point for LightIDS."""

from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtWidgets import QApplication, QMessageBox

from app.core.config import AppConfig, load_config
from app.core.logger import setup_logging
from app.storage.database import DatabaseManager
from app.ui.main_window import MainWindow


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def bootstrap(root: Path) -> tuple[AppConfig, DatabaseManager]:
    config = load_config(root / "config" / "config.json", root)
    setup_logging(root / config.log_file, config.log_level)

    database = DatabaseManager(root / config.database_path)
    database.initialize()
    database.record_app_event("application_initialized", "LightIDS started")
    return config, database


def main() -> int:
    root = project_root()
    app = QApplication(sys.argv)
    app.setApplicationName("LightIDS")

    try:
        config, database = bootstrap(root)
    except Exception as exc:  # pragma: no cover - GUI startup guard
        QMessageBox.critical(None, "LightIDS startup failed", str(exc))
        return 1

    window = MainWindow(config=config, database=database)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
