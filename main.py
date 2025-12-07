#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S7Z压缩解压工具启动程序
"""

import sys
from PySide6.QtWidgets import QApplication
from gui import ResponsiveCompressionGUI
from core_func import self_repair

if __name__ == "__main__":
    # 在程序启动时运行自修复功能
    repair_results = self_repair()
    
    # 自动关联STZ文件类型
    try:
        import file_association
        # 检查是否已关联，如果未关联则尝试关联
        is_associated, msg = file_association.check_stz_association()
        if not is_associated:
            # 即使没有管理员权限也尝试关联，会自动提示用户
            success, msg = file_association.associate_stz_file_type()
    except Exception as e:
        # 如果关联失败，不影响程序正常运行
        pass
    
    app = QApplication(sys.argv)
    
    # 创建GUI实例
    win = ResponsiveCompressionGUI()
    
    # 检查是否有命令行参数（双击STZ文件时会传递文件路径）
    if len(sys.argv) > 1:
        stz_file_path = sys.argv[1]
        # 确保是STZ文件
        if stz_file_path.lower().endswith('.stz'):
            win.handle_stz_file(stz_file_path)
    
    win.show()
    sys.exit(app.exec())
