"""LightIDS 检测模块集合。

该包包含两类检测能力：

* ``signature_detector``：单包规则检测，负责生成 ``rule_event``；
* ``threshold_detector``：多包阈值检测，负责生成 ``threshold_alert``；
* ``rule_engine``：规则字段匹配函数，被规则检测器调用。

上层主窗口不直接关心检测细节，只需要把 ``PacketInfo`` 传入检测器并接收
``AlertEvent``。
"""
