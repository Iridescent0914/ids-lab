"""Application entry point for LightIDS."""

from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtWidgets import QApplication, QMessageBox

from app.core.config import AppConfig, load_config
from app.core.logger import setup_logging
from app.storage.database import DatabaseManager
from app.ui.main_window import MainWindow


def resource_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return Path(__file__).resolve().parents[1]


def runtime_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return resource_root()


def _resolve_runtime_path(path: Path, root: Path) -> Path:
    if path.is_absolute():
        return path
    return root / path


def project_root() -> Path:
    return resource_root()


def bootstrap(root: Path) -> tuple[AppConfig, DatabaseManager]:
    run_root = runtime_root()
    config = load_config(root / "config" / "config.json", root)
    setup_logging(_resolve_runtime_path(config.log_file, run_root), config.log_level)

    database = DatabaseManager(_resolve_runtime_path(config.database_path, run_root))
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
