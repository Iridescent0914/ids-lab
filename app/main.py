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
    """返回程序资源根目录。

    开发环境下资源根目录是项目根目录；PyInstaller 打包后，资源会被解压到
    ``sys._MEIPASS``，因此需要从该位置读取配置文件、规则文件等随包资源。
    """
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return Path(__file__).resolve().parents[1]


def runtime_root() -> Path:
    """返回运行时可写目录。

    打包后可执行文件所在目录用于保存数据库、日志等运行期文件；开发环境下
    直接复用项目根目录，便于调试时查看生成的数据文件。
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return resource_root()


def _resolve_runtime_path(path: Path, root: Path) -> Path:
    """将配置中的相对路径解析到指定运行根目录下。

    配置文件中可以写绝对路径或相对路径。绝对路径保持不变，相对路径则挂到
    ``root`` 下面，避免打包后把日志和数据库写进只读的内部资源目录。
    """
    if path.is_absolute():
        return path
    return root / path


def project_root() -> Path:
    """返回项目或打包资源根目录。

    该函数作为上层启动逻辑的语义化入口，目前等价于 ``resource_root()``。
    """
    return resource_root()


def bootstrap(root: Path) -> tuple[AppConfig, DatabaseManager]:
    """完成应用启动前的基础初始化。

    初始化内容包括读取配置、设置日志、创建并初始化 SQLite 数据库，以及记录
    一条应用启动事件。函数返回主窗口后续需要使用的配置对象和数据库管理器。
    """
    run_root = runtime_root()
    config = load_config(root / "config" / "config.json", root)
    setup_logging(_resolve_runtime_path(config.log_file, run_root), config.log_level)

    database = DatabaseManager(_resolve_runtime_path(config.database_path, run_root))
    database.initialize()
    database.record_app_event("application_initialized", "LightIDS started")
    return config, database


def main() -> int:
    """创建 Qt 应用并启动 LightIDS 主窗口。

    如果配置、日志或数据库初始化失败，会弹出错误提示并返回非零状态码；
    初始化成功后进入 Qt 事件循环，直到用户关闭主窗口。
    """
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



# resource_root()：确定“资源目录”。开发时是项目根目录，打包后是 PyInstaller 的 _MEIPASS 内部资源目录，用来读取 config/、rules/ 等随包文件。
# runtime_root()：确定“运行目录”。打包后是 LightIDS.exe 所在目录，用来保存数据库和日志，避免写入 _internal 资源目录。
# _resolve_runtime_path()：把配置里的相对路径解析到运行目录下；绝对路径则原样使用。
# project_root()：语义化包装，目前等价于 resource_root()，让启动流程读起来更清楚。
# bootstrap()：启动前初始化，包括加载配置、初始化日志、创建 SQLite 数据库、记录启动事件。
# main()：创建 QApplication，执行初始化，创建并显示 MainWindow，最后进入 Qt 事件循环。