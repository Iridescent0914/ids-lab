"""LightIDS 配置加载模块。

该模块负责读取 ``config/config.json``，并把松散的 JSON 字典转换为强类型的配置
对象。应用启动后，主窗口、检测器、采集器和数据库初始化都通过 ``AppConfig``
获取参数，而不是反复读取 JSON。

路径语义需要注意：

* ``default_rules_path`` 会在这里解析到资源根目录下，因为规则文件属于随程序打包
  的资源；
* ``database_path`` 和 ``log_file`` 在这里保留配置中的相对路径，后续由
  ``app.main`` 根据运行环境解析到可写目录，避免打包后写入只读资源目录。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ThresholdConfig:
    """行为阈值检测配置。

    这些字段会被主窗口转换为 ``ThresholdSettings``，再传给
    ``ThresholdDetector``。配置独立成数据类，方便把 JSON、UI 和检测逻辑解耦。
    """

    # 滑动时间窗口长度，单位为秒。
    window_seconds: int
    # 垂直端口扫描阈值：同一源 IP 在窗口内访问同一目的 IP 的不同端口数。
    port_scan_unique_ports: int
    # 横向扫描阈值：同一源 IP 在窗口内访问同一目的端口的不同主机数。
    horizontal_scan_unique_hosts: int
    # ICMP 高频阈值：同一源 IP 在窗口内发送 Echo Request 的数量。
    icmp_high_frequency_count: int


@dataclass(frozen=True)
class CaptureConfig:
    """采集和界面展示相关配置。"""

    # Traffic 表格最多保留的数据包行数，防止长时间抓包导致 UI 无限增长。
    max_display_packets: int
    # Alerts 表格最多保留的当前视图行数；历史完整数据仍保存在 SQLite。
    max_display_alerts: int
    # 实时抓包单次 sniff 的超时时间，影响 Stop 按钮响应速度。
    default_timeout_seconds: int


@dataclass(frozen=True)
class AppConfig:
    """应用启动后使用的总配置对象。

    ``AppConfig`` 是配置模块对外的主要返回值。它把存储、日志、规则、阈值和采集
    参数集中在一个不可变对象中，避免运行过程中被意外修改。
    """

    # 应用名称，用于窗口标题和 QApplication 名称。
    app_name: str
    # SQLite 数据库路径；相对路径会在 app.main 中解析到运行时可写目录。
    database_path: Path
    # 日志文件路径；相对路径会在 app.main 中解析到运行时可写目录。
    log_file: Path
    # Python logging 等级，例如 INFO、DEBUG、WARNING。
    log_level: str
    # 默认规则文件路径；这里已经按资源根目录解析为可直接读取的路径。
    default_rules_path: Path
    # 行为阈值检测配置。
    threshold: ThresholdConfig
    # 抓包和 UI 展示配置。
    capture: CaptureConfig


def _require_mapping(data: Any, name: str) -> dict[str, Any]:
    """确保配置节点是 JSON object。

    JSON 解析后 object 会变成 ``dict``。如果某个配置节被写成字符串、数组或其他
    类型，后续 ``.get`` 会报不直观的错误，因此这里提前给出明确异常信息。
    """
    if not isinstance(data, dict):
        raise ValueError(f"Config section '{name}' must be an object")
    return data


def _resolve_path(value: Any, default: str, root: Path) -> Path:
    """把配置中的资源路径解析为 ``Path``。

    绝对路径保持原样；相对路径挂到 ``root`` 下。该函数目前主要用于规则文件路径，
    因为规则文件属于随包资源，开发环境在项目根目录，PyInstaller 打包后在
    ``_MEIPASS`` 资源目录。
    """
    path = Path(value or default)
    if path.is_absolute():
        return path
    return root / path


def load_config(path: Path, root: Path) -> AppConfig:
    """读取 JSON 配置并返回 ``AppConfig``。

    ``path`` 是配置文件位置，``root`` 是资源根目录。开发环境下通常是项目根目录；
    PyInstaller 打包后通常是 ``dist/LightIDS/_internal``。函数会为缺失字段提供
    默认值，让配置文件可以保持简洁。
    """
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = json.loads(path.read_text(encoding="utf-8"))
    # 分节读取配置。缺失的节使用空字典，然后在字段级别套默认值。
    data = _require_mapping(raw, "root")
    threshold = _require_mapping(data.get("threshold", {}), "threshold")
    capture = _require_mapping(data.get("capture", {}), "capture")
    storage = _require_mapping(data.get("storage", {}), "storage")
    logging_config = _require_mapping(data.get("logging", {}), "logging")
    rules = _require_mapping(data.get("rules", {}), "rules")

    return AppConfig(
        app_name=str(data.get("app_name", "LightIDS")),
        # 数据库和日志路径先保持为配置中的 Path。它们是运行期可写文件，最终会在
        # app.main.bootstrap 中解析到 runtime_root。
        database_path=Path(storage.get("database_path", "data/lightids.db")),
        log_file=Path(logging_config.get("file", "logs/lightids.log")),
        log_level=str(logging_config.get("level", "INFO")).upper(),
        # 默认规则文件是随包资源，因此在配置加载时就解析到资源根目录。
        default_rules_path=_resolve_path(
            rules.get("default_rules_path", "rules/default.rules"),
            "rules/default.rules",
            root,
        ),
        # 阈值和采集参数都转为 int，确保后续检测器/界面拿到稳定类型。
        threshold=ThresholdConfig(
            window_seconds=int(threshold.get("window_seconds", 10)),
            port_scan_unique_ports=int(threshold.get("port_scan_unique_ports", 10)),
            horizontal_scan_unique_hosts=int(threshold.get("horizontal_scan_unique_hosts", 10)),
            icmp_high_frequency_count=int(threshold.get("icmp_high_frequency_count", 20)),
        ),
        capture=CaptureConfig(
            max_display_packets=int(capture.get("max_display_packets", 1000)),
            max_display_alerts=int(capture.get("max_display_alerts", 1000)),
            default_timeout_seconds=int(capture.get("default_timeout_seconds", 30)),
        ),
    )
