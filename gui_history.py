#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
历史记录页面组件
提供压缩/解压操作历史记录的查看和管理功能
"""

import os
import json
import shutil
from datetime import datetime
from PySide6 import QtCore, QtWidgets, QtGui
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QMessageBox, QHeaderView, QMenu, QComboBox,
    QDateTimeEdit, QGroupBox, QCheckBox
)
from PySide6.QtCore import Qt, QDate
from gui_utils import LANGUAGE_PACKS, _human_readable_size

HISTORY_FILE = "compression_history.json"
MAX_HISTORY_ITEMS = 1000  # 最大历史记录条数

class HistoryPage(QWidget):
    """历史记录页面"""
    log_signal = QtCore.Signal(str, str)
    progress_signal = QtCore.Signal(int, str)
    reexecute_signal = QtCore.Signal(dict)  # 重新执行信号，传递历史记录数据

    def __init__(self, compressor, config, language="zh"):
        super().__init__()
        self.compressor = compressor
        self.config = config
        self.language = language
        self.lang_pack = LANGUAGE_PACKS.get(language, LANGUAGE_PACKS["zh"])
        self.history_data = []
        self.filtered_data = []
        self.setup_ui()
        self.load_history()
        self.update_table()

    def tr(self, key):
        """翻译"""
        return self.lang_pack.get(key, key)

    def setup_ui(self):
        """设置界面"""
        main_layout = QVBoxLayout(self)

        # 顶部过滤区域
        self.filter_group = QGroupBox(self.tr("filter_title"))
        filter_layout = QHBoxLayout(self.filter_group)

        # 操作类型过滤
        self.filter_type = QComboBox()
        self.filter_type.addItems([
            self.tr("all_operations"),
            self.tr("compression_operations"),
            self.tr("decompression_operations")
        ])
        self.filter_type.currentIndexChanged.connect(self.apply_filters)
        self.lbl_operation_type = QLabel(self.tr("operation_type"))
        filter_layout.addWidget(self.lbl_operation_type)
        filter_layout.addWidget(self.filter_type)

        # 日期范围过滤
        self.date_from = QDateTimeEdit()
        self.date_from.setCalendarPopup(True)
        self.date_from.setDate(QDate.currentDate().addDays(-30))  # 默认显示30天内的记录
        self.date_from.dateChanged.connect(self.apply_filters)
        self.date_to = QDateTimeEdit()
        self.date_to.setCalendarPopup(True)
        self.date_to.setDate(QDate.currentDate())
        self.date_to.dateChanged.connect(self.apply_filters)
        self.lbl_date_range = QLabel(self.tr("date_range"))
        self.lbl_date_separator = QLabel("-")
        filter_layout.addWidget(self.lbl_date_range)
        filter_layout.addWidget(self.date_from)
        filter_layout.addWidget(self.lbl_date_separator)
        filter_layout.addWidget(self.date_to)

        # 状态过滤
        self.filter_status = QComboBox()
        self.filter_status.addItems([
            self.tr("all_status"),
            self.tr("success_status"),
            self.tr("failed_status")
        ])
        self.filter_status.currentIndexChanged.connect(self.apply_filters)
        self.lbl_status = QLabel(self.tr("status"))
        filter_layout.addWidget(self.lbl_status)
        filter_layout.addWidget(self.filter_status)

        filter_layout.addStretch()
        main_layout.addWidget(self.filter_group)

        # 历史记录表格
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(8)
        self.history_table.setHorizontalHeaderLabels([
            self.tr("operation_type"),
            self.tr("source_files"),
            self.tr("target_file"),
            self.tr("size_before"),
            self.tr("size_after"),
            self.tr("time"),
            self.tr("date"),
            self.tr("status")
        ])
        
        # 设置表格属性
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self.show_context_menu)
        main_layout.addWidget(self.history_table)

        # 底部操作按钮
        button_layout = QHBoxLayout()
        
        # 重新执行按钮
        self.btn_reexecute = QPushButton(self.tr("reexecute"))
        self.btn_reexecute.clicked.connect(self.reexecute_operation)
        button_layout.addWidget(self.btn_reexecute)
        
        # 查看详情按钮
        self.btn_details = QPushButton(self.tr("view_details"))
        self.btn_details.clicked.connect(self.view_details)
        button_layout.addWidget(self.btn_details)
        
        # 删除选中按钮
        self.btn_delete_selected = QPushButton(self.tr("delete_selected"))
        self.btn_delete_selected.clicked.connect(self.delete_selected)
        button_layout.addWidget(self.btn_delete_selected)
        
        # 清空所有按钮
        self.btn_clear_all = QPushButton(self.tr("clear_all"))
        self.btn_clear_all.clicked.connect(self.clear_all)
        button_layout.addWidget(self.btn_clear_all)
        
        button_layout.addStretch()
        main_layout.addLayout(button_layout)

    def load_history(self):
        """加载历史记录"""
        try:
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                    self.history_data = json.load(f)
        except Exception as e:
            self.log_signal.emit(f"加载历史记录失败: {str(e)}", "ERROR")

    def save_history(self):
        """保存历史记录"""
        try:
            # 限制历史记录数量
            if len(self.history_data) > MAX_HISTORY_ITEMS:
                self.history_data = self.history_data[-MAX_HISTORY_ITEMS:]
            
            with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.history_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            self.log_signal.emit(f"保存历史记录失败: {str(e)}", "ERROR")

    def add_history_item(self, operation_type, source_files, target_file, 
                         size_before, size_after, status, additional_info=None):
        """添加历史记录项"""
        history_item = {
            "id": datetime.now().strftime("%Y%m%d%H%M%S%f"),
            "operation_type": operation_type,  # "compress" or "decompress"
            "source_files": source_files,
            "target_file": target_file,
            "size_before": size_before,
            "size_after": size_after,
            "date": datetime.now().strftime("%Y-%m-%d"),
            "time": datetime.now().strftime("%H:%M:%S"),
            "status": status,  # "success" or "failed"
            "additional_info": additional_info or {}
        }
        
        self.history_data.append(history_item)
        self.save_history()
        self.apply_filters()  # 应用过滤器更新表格

    def apply_filters(self):
        """应用过滤器"""
        filtered = self.history_data.copy()
        
        # 操作类型过滤
        type_filter = self.filter_type.currentIndex()
        if type_filter == 1:  # 只显示压缩
            filtered = [item for item in filtered if item["operation_type"] == "compress"]
        elif type_filter == 2:  # 只显示解压
            filtered = [item for item in filtered if item["operation_type"] == "decompress"]
        
        # 日期过滤
        date_from = self.date_from.date().toString("yyyy-MM-dd")
        date_to = self.date_to.date().toString("yyyy-MM-dd")
        filtered = [item for item in filtered if date_from <= item["date"] <= date_to]
        
        # 状态过滤
        status_filter = self.filter_status.currentIndex()
        if status_filter == 1:  # 只显示成功
            filtered = [item for item in filtered if item["status"] == "success"]
        elif status_filter == 2:  # 只显示失败
            filtered = [item for item in filtered if item["status"] == "failed"]
        
        self.filtered_data = filtered
        self.update_table()

    def update_table(self):
        """更新表格显示"""
        self.history_table.setRowCount(len(self.filtered_data))
        
        for row, item in enumerate(self.filtered_data):
            # 操作类型
            type_item = QTableWidgetItem(
                self.tr("compression_label") if item["operation_type"] == "compress" else self.tr("decompression_label")
            )
            type_item.setData(Qt.UserRole, item)
            self.history_table.setItem(row, 0, type_item)
            
            # 源文件
            source_text = ", ".join(item["source_files"])
            if len(source_text) > 100:
                source_text = source_text[:97] + "..."
            self.history_table.setItem(row, 1, QTableWidgetItem(source_text))
            
            # 目标文件
            self.history_table.setItem(row, 2, QTableWidgetItem(item["target_file"]))
            
            # 原始大小
            size_before = _human_readable_size(item["size_before"]) if item["size_before"] else "-"
            self.history_table.setItem(row, 3, QTableWidgetItem(size_before))
            
            # 结果大小
            size_after = _human_readable_size(item["size_after"]) if item["size_after"] else "-"
            self.history_table.setItem(row, 4, QTableWidgetItem(size_after))
            
            # 时间
            self.history_table.setItem(row, 5, QTableWidgetItem(item["time"]))
            
            # 日期
            self.history_table.setItem(row, 6, QTableWidgetItem(item["date"]))
            
            # 状态
            status_item = QTableWidgetItem(
                self.tr("success_label") if item["status"] == "success" else self.tr("failed_label")
            )
            status_item.setTextColor(
                QtGui.QColor("green") if item["status"] == "success" else QtGui.QColor("red")
            )
            self.history_table.setItem(row, 7, status_item)
        
        # 调整列宽
        self.history_table.resizeColumnsToContents()

    def show_context_menu(self, position):
        """显示右键菜单"""
        menu = QMenu()
        
        # 获取选中的行
        selected_rows = self.history_table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        # 添加重新执行菜单项
        reexecute_action = menu.addAction(self.tr("reexecute"))
        reexecute_action.triggered.connect(self.reexecute_operation)
        
        # 添加查看详情菜单项
        details_action = menu.addAction(self.tr("view_details"))
        details_action.triggered.connect(self.view_details)
        
        # 添加删除菜单项
        delete_action = menu.addAction(self.tr("delete_selected"))
        delete_action.triggered.connect(self.delete_selected)
        
        # 显示菜单
        menu.exec(self.history_table.viewport().mapToGlobal(position))

    def reexecute_operation(self):
        """重新执行选中的操作"""
        selected_rows = self.history_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, self.tr("warning"), self.tr("no_item_selected"))
            return
            
        # 只处理第一行
        index = selected_rows[0].row()
        history_item = self.filtered_data[index]
        
        # 发送重新执行信号
        self.reexecute_signal.emit(history_item)
        
        # 切换到对应的标签页
        self.log_signal.emit(f"准备重新执行操作: {history_item['operation_type']}", "INFO")

    def view_details(self):
        """查看选中操作的详细信息"""
        selected_rows = self.history_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, self.tr("warning"), self.tr("no_item_selected"))
            return
            
        index = selected_rows[0].row()
        history_item = self.filtered_data[index]
        
        # 构建详细信息文本
        details = []
        details.append(f"{self.tr('operation_type')}: {history_item['operation_type']}")
        details.append(f"{self.tr('date')}: {history_item['date']} {history_item['time']}")
        details.append(f"{self.tr('status')}: {history_item['status']}")
        details.append(f"{self.tr('source_files')}: {', '.join(history_item['source_files'])}")
        details.append(f"{self.tr('target_file')}: {history_item['target_file']}")
        details.append(f"{self.tr('size_before')}: {_human_readable_size(history_item['size_before'])}")
        details.append(f"{self.tr('size_after')}: {_human_readable_size(history_item['size_after'])}")
        
        if history_item.get('additional_info'):
            details.append(f"\n{self.tr('additional_info')}:")
            for key, value in history_item['additional_info'].items():
                details.append(f"  {key}: {value}")
        
        QMessageBox.information(self, self.tr('operation_details'), "\n".join(details))

    def delete_selected(self):
        """删除选中的历史记录"""
        selected_rows = self.history_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, self.tr("warning"), self.tr("no_item_selected"))
            return
            
        if QMessageBox.question(
            self, self.tr("confirmation"),
            self.tr("confirm_delete_selected"),
            QMessageBox.Yes | QMessageBox.No
        ) != QMessageBox.Yes:
            return
        
        # 获取选中项的ID并从原始数据中删除
        selected_ids = []
        for index in selected_rows:
            row = index.row()
            history_item = self.filtered_data[row]
            selected_ids.append(history_item['id'])
        
        self.history_data = [item for item in self.history_data if item['id'] not in selected_ids]
        
        # 保存并更新表格
        self.save_history()
        self.apply_filters()
        
        self.log_signal.emit(self.tr("selected_deleted"), "INFO")

    def clear_all(self):
        """清空所有历史记录"""
        if QMessageBox.question(
            self, self.tr("confirmation"),
            self.tr("confirm_clear_all"),
            QMessageBox.Yes | QMessageBox.No
        ) != QMessageBox.Yes:
            return
        
        self.history_data = []
        self.save_history()
        self.update_table()
        
        self.log_signal.emit(self.tr("all_history_cleared"), "INFO")

    def update_language(self, language):
        """更新语言"""
        # 添加安全检查，确保语言存在于语言包中
        if language not in LANGUAGE_PACKS:
            language = "zh"  # 默认使用中文
        self.language = language
        # 更新界面文本
        self.update_ui_text()
        self.apply_filters()
    
    def change_language(self, language):
        """更改语言"""
        self.language = language
        self.lang_pack = LANGUAGE_PACKS.get(language, LANGUAGE_PACKS["zh"])
        # 更新界面文本
        self.filter_group.setTitle(self.tr("filter_title"))
        
        # 更新操作类型标签和过滤选项
        if hasattr(self, 'lbl_operation_type'):
            self.lbl_operation_type.setText(self.tr("operation_type"))
        self.filter_type.setItemText(0, self.tr("all_operations"))
        self.filter_type.setItemText(1, self.tr("compression_operations"))
        self.filter_type.setItemText(2, self.tr("decompression_operations"))
        
        # 更新日期范围标签
        if hasattr(self, 'lbl_date_range'):
            self.lbl_date_range.setText(self.tr("date_range"))
        
        # 更新状态标签和过滤选项
        if hasattr(self, 'lbl_status'):
            self.lbl_status.setText(self.tr("status"))
        
        # 更新状态过滤（如果存在）
        if hasattr(self, 'filter_status'):
            self.filter_status.setItemText(0, self.tr("all_status"))
            self.filter_status.setItemText(1, self.tr("success_status"))
            self.filter_status.setItemText(2, self.tr("failed_status"))
        
        # 更新表格表头
        if hasattr(self, 'history_table'):
            self.history_table.setHorizontalHeaderLabels([
                self.tr("operation_type"),
                self.tr("source_files"),
                self.tr("target_file"),
                self.tr("size_before"),
                self.tr("size_after"),
                self.tr("time"),
                self.tr("date"),
                self.tr("status")
            ])
        
        # 更新按钮文本
        button_translations = {
            'btn_reexecute': 'reexecute',
            'btn_details': 'view_details',
            'btn_delete_selected': 'delete_selected',
            'btn_clear_all': 'clear_all'
        }
        for btn_name, trans_key in button_translations.items():
            if hasattr(self, btn_name):
                btn = getattr(self, btn_name)
                btn.setText(self.tr(trans_key))
        
        self.apply_filters()
        
        # 重新应用过滤器以更新表格内容
        self.apply_filters()
