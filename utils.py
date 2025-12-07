#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
utils.py - STZ压缩工具通用工具函数模块
包含弹窗提示、数据校验、通用小功能等
"""
import os
import winsound
import html
from typing import Any

from PySide6 import QtWidgets, QtGui

# 日志颜色映射
_LOG_COLORS = {
    "info": "#000000",
    "warning": "#c07a00",
    "error": "#c00000",
    "success": "#008000"
}


def play_sound(sound_type: str):
    """
    播放提示音（Windows 下使用 winsound，其他平台忽略）
    参数:
        sound_type: "success" / "error" / "warning"
    """
    try:
        if sound_type == "success":
            winsound.Beep(1000, 200)
        elif sound_type == "error":
            winsound.Beep(500, 300)
        elif sound_type == "warning":
            winsound.Beep(750, 250)
    except Exception:
        # 非 Windows 或失败时静默忽略
        pass


def add_log_to_text_widget(text_widget: Any, log: str, level: str = "info"):
    """
    向 QTextEdit 或类似控件添加带颜色的日志（兼容 PySide6 QTextEdit / QTextBrowser）
    参数:
        text_widget: QTextEdit / QTextBrowser
        log: 日志文本
        level: 日志级别 ("info","warning","error","success")
    """
    color = _LOG_COLORS.get(level, "#000000")
    safe = html.escape(str(log))
    # 使用 HTML 追加，保留换行
    try:
        # QTextEdit.append 支持 HTML
        text_widget.append(f'<span style="color:{color}">{safe}</span>')
    except Exception:
        # 退回为 plain text 写入（若控件不是 Qt）
        try:
            text_widget.insertPlainText(log + "\n")
        except Exception:
            pass


def clear_text_widget(text_widget: Any):
    """
    清空 QTextEdit / QTextBrowser 等文本控件
    """
    try:
        text_widget.clear()
    except Exception:
        try:
            # 兼容非 Qt 文本控件
            text_widget.delete(1.0, "end")
        except Exception:
            pass


def select_all_listbox(list_widget: Any):
    """
    全选 Qt 的 QListWidget 或 QTreeWidget 的所有项（兼容）
    """
    try:
        if hasattr(list_widget, "selectAll"):
            list_widget.selectAll()
        else:
            # try select via items
            for i in range(list_widget.count()):
                it = list_widget.item(i)
                it.setSelected(True)
    except Exception:
        pass


def deselect_all_listbox(list_widget: Any):
    """取消选择"""
    try:
        if hasattr(list_widget, "clearSelection"):
            list_widget.clearSelection()
        else:
            for i in range(list_widget.count()):
                it = list_widget.item(i)
                it.setSelected(False)
    except Exception:
        pass


def toggle_listbox_selection(list_widget: Any):
    """
    切换列表选择（若有选中则取消全部，否则全选）
    """
    try:
        sel = False
        # 支持 QListWidget
        if hasattr(list_widget, "selectedItems"):
            sel = bool(list_widget.selectedItems())
        elif hasattr(list_widget, "selectedIndexes"):
            sel = bool(list_widget.selectedIndexes())
        if sel:
            deselect_all_listbox(list_widget)
        else:
            select_all_listbox(list_widget)
    except Exception:
        pass


def validate_path_exists(path: str) -> bool:
    """验证路径是否存在"""
    return bool(path) and os.path.exists(path)


def get_file_size_str(size_bytes: int) -> str:
    """字节转可读字符串"""
    try:
        size = float(size_bytes)
    except Exception:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def show_info_message(title: str, message: str):
    QtWidgets.QMessageBox.information(None, title, message)


def show_warning_message(title: str, message: str):
    QtWidgets.QMessageBox.warning(None, title, message)


def show_error_message(title: str, message: str):
    QtWidgets.QMessageBox.critical(None, title, message)


def add_to_recent_paths(config: dict, path_type: str, path: str, max_paths: int = 10):
    """
    添加路径到最近使用列表，config 字段与之前保持一致:
      path_type: "compress" / "decompress" / "modify"
    """
    if path_type not in ["compress", "decompress", "modify"]:
        return
    key = f"recent_{path_type}_paths"
    if key not in config:
        config[key] = []
    if path and path not in config[key]:
        config[key].insert(0, path)
        if len(config[key]) > max_paths:
            config[key] = config[key][:max_paths]


def check_disk_space(path: str, required_space: int = 0) -> tuple[bool, int, int]:
    """
    检查指定路径所在磁盘的可用空间
    参数:
        path: 文件或目录路径
        required_space: 需要的空间（字节），默认为0（仅检查可用空间）
    返回:
        (has_enough_space, available_space, required_space)
        - has_enough_space: 布尔值，表示是否有足够空间
        - available_space: 可用空间（字节）
        - required_space: 请求的空间（字节）
    """
    try:
        import shutil
        # 获取磁盘使用情况
        usage = shutil.disk_usage(os.path.abspath(path))
        available_space = usage.free
        if required_space > 0:
            return (available_space >= required_space, available_space, required_space)
        return (True, available_space, required_space)
    except Exception as e:
        # 处理可能的异常（路径不存在、权限不足等）
        return (False, 0, required_space)


def check_file_permissions(path: str, write: bool = False) -> bool:
    """
    检查对指定文件或目录的访问权限
    参数:
        path: 文件或目录路径
        write: 是否需要写入权限
    返回:
        布尔值，表示是否有足够权限
    """
    try:
        if os.path.exists(path):
            # 检查读取权限
            if not os.access(path, os.R_OK):
                return False
            # 如果需要写入权限，检查写入权限
            if write and not os.access(path, os.W_OK):
                return False
            # 如果是目录，检查执行权限（需要进入目录）
            if os.path.isdir(path) and not os.access(path, os.X_OK):
                return False
            return True
        else:
            # 路径不存在，检查父目录的写入权限（用于创建新文件/目录）
            parent_dir = os.path.dirname(os.path.abspath(path))
            if not parent_dir:
                parent_dir = os.getcwd()
            return os.access(parent_dir, os.W_OK) and os.access(parent_dir, os.X_OK)
    except Exception as e:
        return False


def check_file_in_use(file_path: str) -> bool:
    """
    检查文件是否被其他程序占用
    参数:
        file_path: 文件路径
    返回:
        布尔值，表示文件是否被占用
    """
    if not os.path.exists(file_path) or os.path.isdir(file_path):
        return False
    
    try:
        with open(file_path, 'r+b') as f:
            f.flush()
            os.fsync(f.fileno())
        return False
    except PermissionError:
        # Windows 下文件被占用会抛出 PermissionError
        return True
    except Exception:
        # 其他平台或异常情况
        return False


def format_bytes(size_bytes: int) -> str:
    """
    将字节数格式化为人类可读的字符串
    参数:
        size_bytes: 字节数
    返回:
        格式化后的字符串（如 "1.2 MB"）
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"