"""LightIDS 日志初始化模块。

项目中其他模块直接使用 ``logging.getLogger(__name__)`` 获取 logger。本模块只在
应用启动时调用一次 ``setup_logging``，统一设置日志等级、输出格式、文件输出和
控制台输出。
"""

from __future__ import annotations

import logging
from pathlib import Path


def setup_logging(log_file: Path, level: str = "INFO") -> None:
    """初始化 Python logging。

    日志会同时写入文件和标准输出。文件日志便于用户或开发者在程序关闭后排查
    PCAP 导入、实时抓包、数据库等问题；标准输出则方便源码运行时直接观察。

    ``force=True`` 会重置已有 logging 配置，避免在测试、重复启动或 PyQt 环境中
    因旧 handler 残留导致日志重复输出。
    """
    # 确保日志目录存在，例如 logs/lightids.log 中的 logs。
    log_file.parent.mkdir(parents=True, exist_ok=True)
    # 把字符串等级转换为 logging 使用的数字等级；非法等级回退到 INFO。
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            # 写入 UTF-8 文件，避免中文日志在 Windows 上乱码。
            logging.FileHandler(log_file, encoding="utf-8"),
            # 源码运行时也输出到控制台；打包 GUI 程序中该 handler 通常不可见，
            # 但保留它不会影响文件日志。
            logging.StreamHandler(),
        ],
        force=True,
    )
