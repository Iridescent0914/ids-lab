"""LightIDS 核心基础设施包。

``config`` 负责把 JSON 配置加载为强类型对象；``logger`` 负责应用启动时统一设置
日志输出。二者都在 ``app.main.bootstrap`` 中初始化，是其他模块运行前的基础。
"""
