#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
压缩率分析工具页面
"""

import os
import sys
import time
import threading
import json
from datetime import datetime
from PySide6 import QtCore, QtWidgets, QtGui
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QPushButton, 
    QFileDialog, QListWidget, QTextEdit, QProgressBar, QLabel, 
    QLineEdit, QCheckBox, QComboBox, QMessageBox, QGroupBox
)
from PySide6.QtCore import Signal, Slot
from PySide6.QtGui import QIcon, QColor

import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

from core_func import CustomCompressor
from gui_utils import LOG_COLORS, LANGUAGE_PACKS, _human_readable_size

class AnalyzerPage(QWidget):
    # 定义信号
    progress_signal = Signal(int, str)
    log_signal = Signal(str, str)
    analyze_done = Signal(tuple)
    
    def __init__(self, compressor, config, current_lang):
        super().__init__()
        self.compressor = compressor
        self.config = config
        self.current_lang = current_lang
        
        # 分析结果数据
        self.analysis_results = []
        
        # 初始化界面
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        
        # 顶部选项区域
        top_layout = QHBoxLayout()
        
        # 左侧：文件/文件夹选择
        select_layout = QVBoxLayout()
        
        file_btn_layout = QHBoxLayout()
        self.btn_add_files = QPushButton(LANGUAGE_PACKS[self.current_lang]["btn_add_files"])
        self.btn_add_folder = QPushButton(LANGUAGE_PACKS[self.current_lang]["btn_add_folder"])
        self.btn_clear_list = QPushButton(LANGUAGE_PACKS[self.current_lang]["btn_clear_list"])
        
        file_btn_layout.addWidget(self.btn_add_files)
        file_btn_layout.addWidget(self.btn_add_folder)
        file_btn_layout.addWidget(self.btn_clear_list)
        select_layout.addLayout(file_btn_layout)
        
        # 文件列表
        self.list_files = QListWidget()
        self.list_files.setSelectionMode(QtWidgets.QAbstractItemView.MultiSelection)
        select_layout.addWidget(self.list_files)
        
        # 压缩选项
        options_layout = QVBoxLayout()
        
        # 算法选择
        self.cb_algorithm = QComboBox()
        self.cb_algorithm.addItems(["zlib", "lzma", "brotli", "zstandard"])
        options_layout.addWidget(QLabel(LANGUAGE_PACKS[self.current_lang]["lbl_algorithm"]))
        options_layout.addWidget(self.cb_algorithm)
        
        # 压缩级别选择
        level_layout = QHBoxLayout()
        self.cb_level = QComboBox()
        self.cb_level.addItems(["1", "2", "3", "4", "5", "6", "7", "8", "9"])
        self.cb_level.setCurrentText("6")
        level_layout.addWidget(QLabel(LANGUAGE_PACKS[self.current_lang]["lbl_compression_level"]))
        level_layout.addWidget(self.cb_level)
        options_layout.addLayout(level_layout)
        
        # 压缩格式选择
        self.cb_format = QComboBox()
        self.cb_format.addItems(["stz", "zip", "7z"])
        options_layout.addWidget(QLabel(LANGUAGE_PACKS[self.current_lang]["lbl_compression_format"]))
        options_layout.addWidget(self.cb_format)
        
        # 开始分析按钮
        self.btn_start_analyze = QPushButton(LANGUAGE_PACKS[self.current_lang]["btn_start_analyze"])
        self.btn_start_analyze.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        options_layout.addWidget(self.btn_start_analyze)
        
        # 底部布局
        bottom_layout = QVBoxLayout()
        
        # 结果显示区域
        result_group = QGroupBox(LANGUAGE_PACKS[self.current_lang]["group_analysis_results"])
        result_layout = QHBoxLayout(result_group)
        
        # 结果列表
        self.results_list = QListWidget()
        result_layout.addWidget(self.results_list)
        
        # 图表显示
        self.figure = Figure(figsize=(6, 4), dpi=100)
        self.canvas = FigureCanvas(self.figure)
        result_layout.addWidget(self.canvas)
        
        bottom_layout.addWidget(result_group)
        
        # 进度条
        self.pb_analyze = QProgressBar()
        self.pb_analyze.setValue(0)
        bottom_layout.addWidget(self.pb_analyze)
        
        # 日志显示
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setStyleSheet("background-color: #f0f0f0; font-family: Courier New;")
        bottom_layout.addWidget(self.log_edit)
        
        # 将所有布局组合起来
        top_layout.addLayout(select_layout)
        top_layout.addLayout(options_layout)
        main_layout.addLayout(top_layout)
        main_layout.addLayout(bottom_layout)
    
    def _connect_signals(self):
        self.btn_add_files.clicked.connect(self.add_files)
        self.btn_add_folder.clicked.connect(self.add_folder)
        self.btn_clear_list.clicked.connect(self.clear_list)
        self.btn_start_analyze.clicked.connect(self.start_analysis_thread)
    
    def change_language(self, language):
        """更改语言"""
        self.current_lang = language
        self.lang_pack = LANGUAGE_PACKS.get(language, LANGUAGE_PACKS["zh"])
        
        # 更新界面文本
        self.btn_add_files.setText(self.lang_pack["btn_add_files"])
        self.btn_add_folder.setText(self.lang_pack["btn_add_folder"])
        self.btn_clear_list.setText(self.lang_pack["btn_clear_list"])
        self.btn_start_analyze.setText(self.lang_pack["btn_start_analyze"])
        
        # 获取布局层次
        main_layout = self.layout()
        top_layout = main_layout.itemAt(0).layout()
        options_layout = top_layout.itemAt(1).layout()
        bottom_layout = main_layout.itemAt(1).layout()
        
        # 更新算法标签
        if options_layout.itemAt(0).widget() and isinstance(options_layout.itemAt(0).widget(), QLabel):
            options_layout.itemAt(0).widget().setText(self.lang_pack["lbl_algorithm"])
        
        # 更新压缩级别标签
        if options_layout.itemAt(2).layout() and options_layout.itemAt(2).layout().itemAt(0).widget() and isinstance(options_layout.itemAt(2).layout().itemAt(0).widget(), QLabel):
            options_layout.itemAt(2).layout().itemAt(0).widget().setText(self.lang_pack["lbl_compression_level"])
        
        # 更新压缩格式标签
        if options_layout.itemAt(3).widget() and isinstance(options_layout.itemAt(3).widget(), QLabel):
            options_layout.itemAt(3).widget().setText(self.lang_pack["lbl_compression_format"])
        
        # 更新分析结果分组框标题
        if bottom_layout.itemAt(0).widget() and isinstance(bottom_layout.itemAt(0).widget(), QGroupBox):
            bottom_layout.itemAt(0).widget().setTitle(self.lang_pack["group_analysis_results"])
        
    def add_files(self):
        """添加文件"""
        files, _ = QFileDialog.getOpenFileNames(self, LANGUAGE_PACKS[self.current_lang]["dialog_add_files"])
        for file in files:
            if file not in [self.list_files.item(i).text() for i in range(self.list_files.count())]:
                self.list_files.addItem(file)
    
    def add_folder(self):
        """添加文件夹"""
        folder = QFileDialog.getExistingDirectory(self, LANGUAGE_PACKS[self.current_lang]["dialog_add_folder"])
        if folder and folder not in [self.list_files.item(i).text() for i in range(self.list_files.count())]:
            self.list_files.addItem(folder)
    
    def clear_list(self):
        """清空列表"""
        self.list_files.clear()
    
    def start_analysis_thread(self):
        """在新线程中开始分析"""
        if self.list_files.count() == 0:
            QMessageBox.warning(self, LANGUAGE_PACKS[self.current_lang]["warning"], LANGUAGE_PACKS[self.current_lang]["warn_no_files_selected"])
            return
        
        # 获取选择的文件/文件夹
        paths = [self.list_files.item(i).text() for i in range(self.list_files.count())]
        
        # 禁用按钮
        self.btn_start_analyze.setEnabled(False)
        self.btn_add_files.setEnabled(False)
        self.btn_add_folder.setEnabled(False)
        self.btn_clear_list.setEnabled(False)
        
        # 清空之前的结果
        self.analysis_results = []
        self.results_list.clear()
        
        # 重置进度条
        self.pb_analyze.setValue(0)
        
        # 启动分析线程
        threading.Thread(target=self._analyze_in_thread, args=(paths,), daemon=True).start()
    
    def _analyze_in_thread(self, paths):
        """在后台线程中执行分析"""
        try:
            algorithm = self.cb_algorithm.currentText()
            level = int(self.cb_level.currentText())
            format = self.cb_format.currentText()
            
            total_items = len(paths)
            processed_items = 0
            
            for path in paths:
                # 检查取消状态
                if self.compressor.is_cancelled:
                    self.log_signal.emit(LANGUAGE_PACKS[self.current_lang]["log_analysis_cancelled"], "warning")
                    break
                    
                # 分析单个文件/文件夹
                result = self._analyze_item(path, algorithm, level, format)
                if result:
                    self.analysis_results.append(result)
                    
                    # 更新结果列表
                    self.results_list.addItem(f"{result['name']} - 压缩率: {result['compression_ratio']:.2f}% ({result['original_size']} → {result['compressed_size']})")
                
                processed_items += 1
                progress = int((processed_items / total_items) * 100)
                self.progress_signal.emit(progress, f"正在分析: {os.path.basename(path)}")
            
            # 绘制图表
            self._draw_chart()
            
            # 完成分析
            self.log_signal.emit(LANGUAGE_PACKS[self.current_lang]["log_analysis_completed"], "success")
            self.analyze_done.emit((True, self.analysis_results))
            
        except Exception as e:
            self.log_signal.emit(f"{LANGUAGE_PACKS[self.current_lang]["log_analysis_error"]}: {e}", "error")
            self.analyze_done.emit((False, None))
        finally:
            # 恢复按钮状态
            self.btn_start_analyze.setEnabled(True)
            self.btn_add_files.setEnabled(True)
            self.btn_add_folder.setEnabled(True)
            self.btn_clear_list.setEnabled(True)
    
    def _analyze_item(self, path, algorithm, level, format):
        """分析单个文件/文件夹的压缩率"""
        try:
            import tempfile
            import os
            
            # 获取原始大小
            if os.path.isfile(path):
                original_size = os.path.getsize(path)
                name = os.path.basename(path)
            else:
                original_size = self._get_folder_size(path)
                name = os.path.basename(path)
            
            # 创建临时输出文件
            with tempfile.NamedTemporaryFile(suffix=f".{format}", delete=False) as f:
                temp_output = f.name
            
            try:
                # 执行压缩
                success, output_path, logs = self.compressor.compress_to_format(
                    [path], temp_output, format, {
                        "compression_level": level,
                        "algorithm": algorithm,
                        "password": None,
                        "split_size": None
                    }
                )
                
                for log, level in logs:
                    self.log_signal.emit(log, level)
                
                if success and os.path.exists(output_path):
                    compressed_size = os.path.getsize(output_path)
                    compression_ratio = ((original_size - compressed_size) / original_size) * 100 if original_size > 0 else 0
                    
                    return {
                        "name": name,
                        "path": path,
                        "original_size": _human_readable_size(original_size),
                        "original_size_bytes": original_size,
                        "compressed_size": _human_readable_size(compressed_size),
                        "compressed_size_bytes": compressed_size,
                        "compression_ratio": compression_ratio,
                        "algorithm": algorithm,
                        "level": level,
                        "format": format
                    }
                else:
                    return None
                    
            finally:
                # 清理临时文件
                if os.path.exists(temp_output):
                    os.unlink(temp_output)
                    
        except Exception as e:
            self.log_signal.emit(f"{LANGUAGE_PACKS[self.current_lang]["log_analyze_item_error"]}: {e}", "error")
            return None
    
    def _get_folder_size(self, folder_path):
        """计算文件夹大小"""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(folder_path):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                total_size += os.path.getsize(file_path)
        return total_size
    
    def _draw_chart(self):
        """绘制压缩率对比图表"""
        if not self.analysis_results:
            return
            
        # 清空图表
        self.figure.clear()
        
        # 创建子图
        ax = self.figure.add_subplot(111)
        
        # 准备数据
        names = [result["name"] for result in self.analysis_results]
        original_sizes = [result["original_size_bytes"] for result in self.analysis_results]
        compressed_sizes = [result["compressed_size_bytes"] for result in self.analysis_results]
        compression_ratios = [result["compression_ratio"] for result in self.analysis_results]
        
        # 设置图表大小
        self.figure.set_figwidth(10)
        self.figure.set_figheight(6)
        
        # 创建条形图
        x = range(len(names))
        width = 0.35
        
        ax.bar([i - width/2 for i in x], original_sizes, width, label="原始大小")
        ax.bar([i + width/2 for i in x], compressed_sizes, width, label="压缩后大小")
        
        # 添加压缩率标签
        for i, ratio in enumerate(compression_ratios):
            ax.text(i, max(original_sizes[i], compressed_sizes[i]) + 1024, f"{ratio:.1f}%", 
                    ha='center', va='bottom', fontsize=8)
        
        # 设置x轴标签和旋转
        ax.set_xticks(x)
        ax.set_xticklabels(names, rotation=45, ha='right')
        
        # 设置标题和标签
        ax.set_title(LANGUAGE_PACKS[self.current_lang]["chart_title"])
        ax.set_ylabel(LANGUAGE_PACKS[self.current_lang]["chart_label_size"])
        
        # 添加图例
        ax.legend()
        
        # 调整布局
        self.figure.tight_layout()
        
        # 更新画布
        self.canvas.draw()
    
    def _handle_progress(self, p, msg):
        """处理进度更新"""
        self.progress_signal.emit(p, msg)
    
    def _handle_log(self, log, level):
        """处理日志消息"""
        self.log_signal.emit(log, level)
    
    def cancel_analysis(self):
        """取消分析操作"""
        self.compressor.cancel_operation()