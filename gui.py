"""
main_gui.py - 使用 PySide6 重写的主界面（替换原 tkinter 实现）
保留与 core_func.CustomCompressor 的接口与多线程调用逻辑。
注意：utils.py 中针对 tkinter 的 UI 函数不再使用，界面内使用 Qt 对话框与控件。
"""
import os
import threading
import tempfile
from datetime import datetime

from PySide6 import QtCore, QtWidgets, QtGui
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QPushButton, QFileDialog, QListWidget, QTextEdit, QProgressBar,
    QLabel, QLineEdit, QTabWidget, QCheckBox, QComboBox, QTreeWidget,
    QTreeWidgetItem, QMessageBox, QSpinBox, QDialog, QTextBrowser, QInputDialog,
    QDateEdit
)

from core_func import CustomCompressor, load_config, save_config
from utils import play_sound

# 从gui_utils导入通用工具
from gui_utils import LOG_COLORS, LANGUAGE_PACKS, DARK_THEME_STYLE, LIGHT_THEME_STYLE, _human_readable_size
from gui_compress import CompressPage
from gui_decompress import DecompressPage
from gui_modify import ModifyPage
from gui_analyzer import AnalyzerPage
from gui_history import HistoryPage

# 兼容旧代码
_LOG_COLORS = LOG_COLORS
LANGUAGE_PACKS = LANGUAGE_PACKS


class CompressionGUI(QMainWindow):
    progress_signal = QtCore.Signal(int, str)           # progress, message
    log_signal = QtCore.Signal(str, str)               # log, level
    preview_signal = QtCore.Signal(object, object)     # file_info_list, is_encrypted
    compress_done = QtCore.Signal(object)              # (result, logs)

    def __init__(self):
        super().__init__()
        self.resize(900, 650)  # 增大默认窗口大小
        self.setMinimumSize(700, 500)  # 设置最小窗口大小，确保界面元素正常显示

        self.config = load_config()
        self.setWindowTitle(self.tr(LANGUAGE_PACKS[self.config['language']]['window_title']))
        self.compressor = CustomCompressor()
        # compressor 回调 -> 发射 Qt 信号（线程安全）
        self.compressor.progress_callback = self._progress_emitter

        self._setup_ui()
        self._connect_signals()
        self.restore_config()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        
        # 顶部工具栏
        top_layout = QHBoxLayout()
        
        # 主题切换控件
        self.lbl_theme = QLabel(self.tr(LANGUAGE_PACKS[self.config['language']]['theme_label']))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems([
            self.tr(LANGUAGE_PACKS[self.config['language']]['theme_system']),
            self.tr(LANGUAGE_PACKS[self.config['language']]['theme_light']),
            self.tr(LANGUAGE_PACKS[self.config['language']]['theme_dark'])
        ])
        self.theme_combo.currentIndexChanged.connect(self.change_theme)
        top_layout.addWidget(self.lbl_theme)
        top_layout.addWidget(self.theme_combo)
        
        # 语言切换控件
        self.lbl_language = QLabel(self.tr(LANGUAGE_PACKS[self.config['language']]['language_label']))
        self.language_combo = QComboBox()
        self.language_combo.addItems([
            self.tr(LANGUAGE_PACKS[self.config['language']]['language_zh']),
            self.tr(LANGUAGE_PACKS[self.config['language']]['language_en'])
        ])
        self.language_combo.currentIndexChanged.connect(self.change_language)
        top_layout.addWidget(self.lbl_language)
        top_layout.addWidget(self.language_combo)
        
        # 帮助按钮
        self.btn_help = QPushButton(self.tr(LANGUAGE_PACKS[self.config['language']]['btn_help']))
        self.btn_help.clicked.connect(self.show_help)
        top_layout.addWidget(self.btn_help)
        
        top_layout.addStretch(1)  # 填充空白
        main_layout.addLayout(top_layout)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs, 1)  # 设置伸缩因子，让标签页占满剩余空间
        
        # --- 压缩页 ---
        current_lang = self.config.get("language", "zh")
        self.page_compress = CompressPage(self.compressor, self.config, current_lang)
        # 连接信号
        self.page_compress.progress_signal.connect(self._update_progress)
        self.page_compress.log_signal.connect(self._add_log)
        self.page_compress.compress_done.connect(self._compress_done)
        
        self.tabs.addTab(self.page_compress, LANGUAGE_PACKS[current_lang]["tab_compress"])

        # --- 解压页 ---
        self.page_decompress = DecompressPage(self.compressor, self.config, current_lang)
        # 连接信号
        self.page_decompress.progress_signal.connect(self._update_progress)
        self.page_decompress.log_signal.connect(self._add_log)
        self.page_decompress.decompress_done.connect(self._decompress_done)
        
        self.tabs.addTab(self.page_decompress, LANGUAGE_PACKS[current_lang]["tab_decompress"])

        # --- 修改页 ---
        self.page_modify = ModifyPage(self.compressor, self.config, current_lang)
        # 连接信号
        self.page_modify.progress_signal.connect(self._update_progress)
        self.page_modify.log_signal.connect(self._add_log)
        self.page_modify.modify_done.connect(self._modify_done)
        
        self.tabs.addTab(self.page_modify, LANGUAGE_PACKS[current_lang]["tab_modify"])
        
        # --- 压缩率分析页 ---
        self.page_analyzer = AnalyzerPage(self.compressor, self.config, current_lang)
        # 连接信号
        self.page_analyzer.progress_signal.connect(self._update_progress)
        self.page_analyzer.log_signal.connect(self._add_log)
        self.page_analyzer.analyze_done.connect(self._analyzer_done)
        
        self.tabs.addTab(self.page_analyzer, LANGUAGE_PACKS[current_lang]["tab_analyze"])
        
        # --- 历史记录页 ---
        self.page_history = HistoryPage(self.compressor, self.config, current_lang)
        # 连接信号
        self.page_history.progress_signal.connect(self._update_progress)
        self.page_history.log_signal.connect(self._add_log)
        self.page_history.reexecute_signal.connect(self._reexecute_operation)
        
        self.tabs.addTab(self.page_history, LANGUAGE_PACKS[current_lang]["tab_history"])


    def _connect_signals(self):
        self.progress_signal.connect(self._on_progress)
        self.log_signal.connect(self._on_log)
        self.preview_signal.connect(self._on_preview_ready)
        self.compress_done.connect(self._on_compress_done)
        
        # 添加快捷操作
        self._setup_shortcuts()
    
    # 兼容页面组件的信号
    def _update_progress(self, p, msg):
        self._on_progress(p, msg)
    
    def _add_log(self, log, level):
        self._on_log(log, level)
    
    def _compress_done(self, result_logs):
        self._on_compress_done(result_logs)
    
    def _decompress_done(self, result_logs):
        pass
    
    def _modify_done(self, result_logs):
        pass
        
    def _analyzer_done(self, result):
        pass
        
    def _reexecute_operation(self, history_item):
        """处理历史记录重新执行"""
        # 根据操作类型切换到对应的标签页
        if history_item["operation_type"] == "compress":
            self.tabs.setCurrentIndex(0)  # 切换到压缩页
            # 填充压缩参数
            self.page_compress.list_paths.clear()
            for source in history_item["source_files"]:
                self.page_compress.list_paths.addItem(source)
            self.page_compress.edit_output.setText(history_item["target_file"])
            
        elif history_item["operation_type"] == "decompress":
            self.tabs.setCurrentIndex(1)  # 切换到解压页
            # 填充解压参数
            if history_item["source_files"]:
                self.page_decompress.edit_archive_path.setText(history_item["source_files"][0])
            self.page_decompress.edit_extract_path.setText(os.path.dirname(history_item["target_file"]))

    # ---------- 信号槽 ----------
    def _progress_emitter(self, p, msg):
        self.progress_signal.emit(int(p), str(msg))
        
    def _drag_enter_event(self, event):
        """处理拖拽进入事件"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def _drop_event(self, event):
        """处理拖拽放下事件（单行编辑框）"""
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            event.widget.setText(path)
    
    def _list_drop_event(self, event):
        """处理文件列表的拖拽放下事件"""
        urls = event.mimeData().urls()
        if urls:
            for url in urls:
                path = url.toLocalFile()
                # 检查路径是否已存在于列表中
                if not any(self.list_paths.item(i).text() == path for i in range(self.list_paths.count())):
                    self.list_paths.addItem(path)
    
    def _validate_path(self, line_edit):
        """验证路径有效性并给出即时提示"""
        path = line_edit.text().strip()
        if not path:
            line_edit.setStyleSheet("border: 1px solid #ccc;")
            return
        
        # 检查路径是否存在
        if os.path.exists(path):
            line_edit.setStyleSheet("border: 1px solid #00ff00;")
        else:
            # 检查是否是有效的路径格式（对于尚未创建的路径）
            try:
                # 尝试获取目录部分
                dir_part = os.path.dirname(path) if os.path.isfile(path) else path
                if dir_part and not os.path.exists(dir_part):
                    line_edit.setStyleSheet("border: 1px solid #ff0000;")
                else:
                    line_edit.setStyleSheet("border: 1px solid #00ff00;")
            except:
                line_edit.setStyleSheet("border: 1px solid #ff0000;")
        
    def toggle_pause(self):
        """切换操作的暂停/继续状态"""
        self.compressor.pause_operation()
        # 更新按钮文本
        idx = self.tabs.currentIndex()
        if idx == 0:
            self.btn_pause.setText("继续" if self.btn_pause.text() == "暂停" else "暂停")
        elif idx == 1:
            self.btn_decompress_pause.setText("继续" if self.btn_decompress_pause.text() == "暂停" else "暂停")
        elif idx == 2:
            self.btn_modify_pause.setText("继续" if self.btn_modify_pause.text() == "暂停" else "暂停")
        
    def cancel_operation(self):
        """取消当前操作"""
        self.compressor.cancel_operation()
    
    def _reset_operation_buttons(self, tab_index):
        """重置操作按钮的状态"""
        if tab_index == 0:  # 压缩页
            self.btn_pause.setEnabled(False)
            self.btn_pause.setText("暂停")
            self.btn_cancel.setEnabled(False)
        elif tab_index == 1:  # 解压页
            self.btn_decompress_pause.setEnabled(False)
            self.btn_decompress_pause.setText("暂停")
            self.btn_decompress_cancel.setEnabled(False)
        elif tab_index == 2:  # 修改压缩包页
            self.btn_modify_pause.setEnabled(False)
            self.btn_modify_pause.setText("暂停")
            self.btn_modify_cancel.setEnabled(False)

    @QtCore.Slot(int, str)
    def _on_progress(self, p, msg):
        self.statusBar().showMessage(msg)
        idx = self.tabs.currentIndex()
        if idx == 0:
            self.pb_compress.setValue(p)
        elif idx == 1:
            self.pb_decompress.setValue(p)
        elif idx == 2:
            self.pb_modify.setValue(p)
    
    def _on_compression_level_changed(self, text):
        """压缩级别变化时保存配置"""
        try:
            level = int(text)
            self.config["default_compression_level"] = level
            save_config(self.config)
        except ValueError:
            pass
    
    def _on_compression_algorithm_changed(self, text):
        """压缩算法变化时保存配置"""
        self.config["default_compression_algorithm"] = text
        save_config(self.config)
    
    def toggle_auto_split(self, checked):
        """切换自动适应设备模式"""
        self.btn_choose_device.setEnabled(checked)
        self.spin_split.setEnabled(not checked)
        self.combo_split_unit.setEnabled(not checked)
    
    def choose_device(self):
        """选择目标设备"""
        from PySide6.QtWidgets import QFileDialog
        device_path = QFileDialog.getExistingDirectory(self, "选择目标设备", "/")
        if device_path:
            # 获取设备可用空间
            import shutil
            try:
                total, used, free = shutil.disk_usage(device_path)
                # 留10%的空间作为缓冲
                available = int(free * 0.9)
                
                # 自动计算合适的分卷大小
                if available < 1024 * 1024:
                    # 小于1MB，用KB
                    self.spin_split.setValue(available // 1024)
                    self.combo_split_unit.setCurrentIndex(0)
                elif available < 1024 * 1024 * 1024:
                    # 小于1GB，用MB
                    self.spin_split.setValue(available // (1024 * 1024))
                    self.combo_split_unit.setCurrentIndex(1)
                else:
                    # 大于等于1GB，用GB
                    self.spin_split.setValue(available // (1024 * 1024 * 1024))
                    self.combo_split_unit.setCurrentIndex(2)
                    
                QMessageBox.information(self, "提示", f"已根据设备空间设置分卷大小为: {self.spin_split.value()}{self.combo_split_unit.currentText()}")
            except:
                QMessageBox.warning(self, "警告", "无法获取设备信息")
    
    def _setup_shortcuts(self):
        """设置快捷键"""
        # Ctrl+A 添加文件
        shortcut_add_files = QtGui.QShortcut(QtGui.QKeySequence.StandardKey.SelectAll, self)
        shortcut_add_files.activated.connect(self.add_files)
        
        # Ctrl+S 开始压缩
        shortcut_start_compress = QtGui.QShortcut(QtGui.QKeySequence.StandardKey.Save, self)
        shortcut_start_compress.activated.connect(self.start_compression_thread)
        
        # ESC 取消操作
        shortcut_cancel = QtGui.QShortcut(QtGui.QKeySequence.StandardKey.Cancel, self)
        shortcut_cancel.activated.connect(self.cancel_operation)

    @QtCore.Slot(str, str)
    def _on_log(self, log, level="info"):
        """处理日志信号"""
        color = _LOG_COLORS.get(level, "#000000")
        # 从当前页面获取日志组件
        current_page = self.tabs.currentWidget()
        if hasattr(current_page, "txt_log"):
            w = current_page.txt_log
            w.setTextColor(QtGui.QColor(color))
            w.append(log)
            w.setTextColor(QtGui.QColor("#000000"))

    @QtCore.Slot(object, object)
    def _on_preview_ready(self, file_info_list, is_encrypted):
        # 弹窗展示树状结构，并支持查看文件内容
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("预览")
        dlg.resize(900, 600)
        layout = QVBoxLayout(dlg)
        
        # 主布局：树状结构和查看按钮
        main_layout = QVBoxLayout()
        
        # 树状结构
        tree = QTreeWidget()
        tree.setHeaderLabels(["文件/目录", "大小", "修改时间"])
        main_layout.addWidget(tree, 1)
        
        # 构建树
        nodes = {}
        self.preview_file_info_map = {}
        for fi in file_info_list:
            rel = fi.get("relative_path", fi.get("file_name", ""))
            parts = rel.replace("\\", "/").split('/')
            parent_item = None
            path_acc = ""
            for i, part in enumerate(parts):
                path_acc = "/".join([path_acc, part]) if path_acc else part
                if path_acc not in nodes:
                    item = QTreeWidgetItem([part, "" if i < len(parts)-1 else self._human_readable_size(fi.get("file_size",0)),
                                            "" if i < len(parts)-1 else datetime.fromtimestamp(fi.get("modified_time",0)).strftime("%Y-%m-%d %H:%M:%S") if fi.get("modified_time",0) else ""])
                    if parent_item is None:
                        tree.addTopLevelItem(item)
                    else:
                        parent_item.addChild(item)
                    nodes[path_acc] = item
                    # 保存文件信息映射
                    self.preview_file_info_map[path_acc] = fi
                parent_item = nodes[path_acc]
        
        # 查看内容按钮
        btn_layout = QHBoxLayout()
        self.btn_preview_content = QPushButton("查看选中文件内容")
        btn_layout.addWidget(self.btn_preview_content)
        btn_layout.addStretch(1)
        main_layout.addLayout(btn_layout)
        
        layout.addLayout(main_layout)
        
        # 连接按钮事件
        self.btn_preview_content.clicked.connect(lambda: self._preview_file_content(tree, file_info_list, is_encrypted))
        
        dlg.exec()

    @QtCore.Slot(object)
    def _on_compress_done(self, result_logs):
        # result_logs is (result, logs)
        result, logs = result_logs
        for log, level in logs:
            self.log_signal.emit(log, level)
        
        if result:
                QMessageBox.information(self, "成功", "压缩完成")
                play_sound("success")
        else:
            # 分析错误类型并提供更精准的错误提示
            error_msg = "压缩失败，请查看日志"
            error_type = ""
            solution = ""
            
            for log, level in logs:
                if level == "error":
                    if "权限不足" in log:
                        error_type = "权限错误"
                        solution = "请检查文件/目录的访问权限，确保您有足够的权限进行压缩操作。"
                    elif "磁盘空间不足" in log:
                        error_type = "磁盘空间不足"
                        solution = "请清理磁盘空间，确保有足够的空间进行压缩操作。"
                    elif "文件被占用" in log:
                        error_type = "文件被占用"
                        solution = "请关闭正在使用这些文件的程序，然后重试。"
                    elif "密码" in log:
                        error_type = "密码错误"
                        solution = "请检查输入的密码是否正确。"
                    elif "格式" in log:
                        error_type = "格式错误"
                        solution = "请检查文件格式是否支持压缩。"
                    break
            
            if error_type:
                error_msg = f"压缩失败 ({error_type})\n{solution}\n\n详细信息请查看日志"
            
            QMessageBox.critical(self, "失败", error_msg)
            play_sound("error")

    # ---------- UI 操作 ----------
    def add_files(self):
        files = self._select_files("选择文件")
        
        # 添加文件到列表
        for f in files:
            if f and not any(self.list_paths.item(i).text() == f for i in range(self.list_paths.count())):
                self.list_paths.addItem(f)

    def add_folders(self):
        folder = self._select_directory("选择文件夹")
        if folder:
            if not any(self.list_paths.item(i).text() == folder for i in range(self.list_paths.count())):
                self.list_paths.addItem(folder)

    def remove_selected(self):
        for it in self.list_paths.selectedItems():
            self.list_paths.takeItem(self.list_paths.row(it))
    
    def select_all_files(self):
        """全选文件列表中的所有项"""
        for i in range(self.list_paths.count()):
            item = self.list_paths.item(i)
            item.setSelected(True)
    
    def deselect_all_files(self):
        """取消选择所有项"""
        for i in range(self.list_paths.count()):
            item = self.list_paths.item(i)
            item.setSelected(False)
    
    def toggle_select_files(self):
        """切换选择状态"""
        all_selected = True
        # 检查是否所有项都已选中
        for i in range(self.list_paths.count()):
            item = self.list_paths.item(i)
            if not item.isSelected():
                all_selected = False
                break
        
        # 如果所有项都已选中，则取消选择所有项；否则选择所有项
        if all_selected:
            self.deselect_all_files()
        else:
            self.select_all_files()

    def choose_output_path(self):
        fn = self._save_file("保存压缩文件", "STZ (*.stz)")
        if fn:
            if fn.lower().endswith(".stz"):
                fn = fn[:-4]
            self.edit_output.setText(fn)
            # 添加到最近路径
            from utils import add_to_recent_paths
            add_to_recent_paths(self.config, "compress", fn)
            save_config(self.config)

    def choose_compress_file(self):
        fn = self._select_file("选择压缩包", "STZ (*.stz)")
        if fn:
            self.edit_compress_file.setText(fn)
            # 添加到最近路径
            from utils import add_to_recent_paths
            add_to_recent_paths(self.config, "compress", fn)
            save_config(self.config)

    def choose_decompress_dir(self):
        folder = self._select_directory("选择解压目录")
        if folder:
            self.edit_decompress_dir.setText(folder)
            # 添加到最近路径
            from utils import add_to_recent_paths
            add_to_recent_paths(self.config, "decompress", folder)
            save_config(self.config)

    def choose_modify_archive(self):
        fn = self._select_file("选择压缩包", "STZ (*.stz)")
        if fn:
            self.edit_modify_archive.setText(fn)
            # 添加到最近路径
            from utils import add_to_recent_paths
            add_to_recent_paths(self.config, "modify", fn)
            save_config(self.config)

    def load_archive_content(self):
        archive = self.edit_modify_archive.text().strip()
        if not archive:
            QMessageBox.warning(self, "警告", "请选择压缩包")
            play_sound("warning")
            return
        file_info_list, logs, is_encrypted = self.compressor.read_archive_info(archive)
        self.tree_archive.clear()
        # 记录当前打开的压缩包与原始文件列表，重置临时变更集合
        self.current_archive = archive
        self.current_archive_encrypted = is_encrypted
        self.current_archive_files = []
        self.files_to_add = {}     # src_abspath -> relative_path_in_archive
        self.files_to_delete = []  # list of relative_path
        if file_info_list:
            for fi in file_info_list:
                rel = fi.get("relative_path", fi.get("file_name", ""))
                self.current_archive_files.append(rel)
                self.tree_archive.addItem(rel)
        for log, level in logs:
            self.log_signal.emit(log, level)
    
    def preview_archive_content(self):
        archive = self.edit_compress_file.text().strip()
        if not archive:
            QMessageBox.warning(self, "警告", "请选择压缩包")
            play_sound("warning")
            return
        # 读取归档信息并预览
        file_info_list, logs, is_encrypted = self.compressor.read_archive_info(archive)
        
        # 检查是否成功读取归档信息
        if file_info_list is None:
            QMessageBox.warning(self, "警告", "无法读取压缩包信息，请确保压缩包格式正确且未损坏")
            play_sound("warning")
            return
            
        # 创建预览对话框
        dlg = QDialog(self)
        dlg.setWindowTitle(f"预览压缩包内容: {os.path.basename(archive)}")
        dlg.resize(800, 600)
        layout = QVBoxLayout(dlg)
        
        tree = QTreeWidget()
        tree.setHeaderLabels(["文件路径"])
        layout.addWidget(tree)
        
        # 创建文件树
        for fi in file_info_list:
            rel = fi.get("relative_path", fi.get("file_name", ""))
            parts = rel.split("/")
            parent_item = None
            
            for part in parts:
                if not part:
                    continue
                
                found = False
                if parent_item:
                    child_count = parent_item.childCount()
                    for i in range(child_count):
                        if parent_item.child(i).text(0) == part:
                            parent_item = parent_item.child(i)
                            found = True
                            break
                else:
                    root_count = tree.topLevelItemCount()
                    for i in range(root_count):
                        if tree.topLevelItem(i).text(0) == part:
                            parent_item = tree.topLevelItem(i)
                            found = True
                            break
                
                if not found:
                    new_item = QTreeWidgetItem([part])
                    if parent_item:
                        parent_item.addChild(new_item)
                    else:
                        tree.addTopLevelItem(new_item)
                    parent_item = new_item
        
        # 添加查看内容按钮
        btn_layout = QHBoxLayout()
        self.btn_view_content = QPushButton("查看选中文件内容")
        btn_layout.addWidget(self.btn_view_content)
        btn_layout.addStretch(1)
        layout.addLayout(btn_layout)
        
        # 显示日志
        for log, level in logs:
            self.log_signal.emit(log, level)
        
        # 按钮点击事件
        def on_view_content():
            selected_item = tree.currentItem()
            if not selected_item:
                QMessageBox.information(self, "提示", "请先选择要查看的文件")
                return
            
            # 获取选中项目的路径
            path_acc = selected_item.text(0)
            # 遍历树结构找到完整路径
            parent = selected_item.parent()
            while parent:
                path_acc = parent.text(0) + "/" + path_acc
                parent = parent.parent()
            
            # 如果压缩包已加密，需要输入密码
            password = None
            if is_encrypted:
                password, ok = QInputDialog.getText(self, "输入密码", "压缩包已加密，请输入密码:", QLineEdit.Password)
                if not ok:
                    return
            
            # 使用统一的预览方法
            self._show_file_content(archive, path_acc, password)
        
        self.btn_view_content.clicked.connect(on_view_content)
        
        dlg.exec()

    def _preview_file_content(self, tree, file_info_list, is_encrypted):
        selected_item = tree.currentItem()
        if not selected_item:
            return
        
        # 获取选中项目的路径
        path_acc = selected_item.text(0)
        # 遍历树结构找到完整路径
        parent = selected_item.parent()
        while parent:
            path_acc = parent.text(0) + "/" + path_acc
            parent = parent.parent()
        
        archive = self.edit_modify_archive.text().strip()
        
        # 如果压缩包已加密，需要输入密码
        password = None
        if is_encrypted:
            password, ok = QInputDialog.getText(self, "输入密码", "压缩包已加密，请输入密码:", QLineEdit.Password)
            if not ok:
                return
        
        # 使用统一的预览方法
        self._show_file_content(archive, path_acc, password)
    
    def search_archive_content(self):
        archive = self.edit_modify_archive.text().strip()
        search_text = self.edit_search.text().strip()
        
        if not archive:
            QMessageBox.warning(self, "警告", "请选择压缩包")
            play_sound("warning")
            return
        
        if not search_text:
            QMessageBox.warning(self, "警告", "请输入搜索文本")
            play_sound("warning")
            return
        
        # 如果压缩包已加密，需要输入密码
        password = None
        if self.current_archive_encrypted:
            password, ok = QInputDialog.getText(self, "输入密码", "压缩包已加密，请输入密码:", QLineEdit.Password)
            if not ok:
                return
        
        # 执行搜索
        results, logs = self.compressor.search_in_archive(archive, search_text, password)
        
        # 显示日志
        for log, level in logs:
            self.log_signal.emit(log, level)
        
        # 显示搜索结果
        self._show_search_results(results)
    
    def _show_search_results(self, results):
        dlg = QDialog(self)
        dlg.setWindowTitle("搜索结果")
        dlg.resize(800, 500)
        layout = QVBoxLayout(dlg)
        
        if not results:
            layout.addWidget(QLabel("未找到匹配的内容"))
        else:
            tree = QTreeWidget()
            tree.setHeaderLabels(["文件路径", "匹配次数"])
            layout.addWidget(tree)
            
            for rel_path, match_positions in results:
                item = QTreeWidgetItem([rel_path, str(len(match_positions))])
                tree.addTopLevelItem(item)
            
            # 添加查看内容按钮
            btn_layout = QHBoxLayout()
            self.btn_view_content = QPushButton("查看选中文件内容")
            self.btn_view_content.clicked.connect(lambda: self._view_file_content(tree, results))
            btn_layout.addWidget(self.btn_view_content)
            btn_layout.addStretch(1)
            layout.addLayout(btn_layout)
        
        dlg.exec()
    
    def _view_file_content(self, tree, results):
        selected_item = tree.currentItem()
        if not selected_item:
            return
        
        rel_path = selected_item.text(0)
        archive = self.edit_modify_archive.text().strip()
        
        # 如果压缩包已加密，需要输入密码
        password = None
        if self.current_archive_encrypted:
            password, ok = QInputDialog.getText(self, "输入密码", "压缩包已加密，请输入密码:", QLineEdit.Password)
            if not ok:
                return
        
        # 使用统一的预览方法
        self._show_file_content(archive, rel_path, password)
    
    def _show_file_content(self, archive, rel_path, password):
        # 提取文件内容
        content, logs = self.compressor.extract_file_content(archive, rel_path, password)
        
        # 显示日志
        for log, level in logs:
            self.log_signal.emit(log, level)
        
        if content:
            dlg = QDialog(self)
            dlg.setWindowTitle(f"查看文件内容: {rel_path}")
            dlg.resize(800, 600)
            layout = QVBoxLayout(dlg)
            
            # 根据文件类型显示内容
            _, ext = os.path.splitext(rel_path.lower())
            
            # 图片文件
            if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg']:
                label = QLabel()
                pixmap = QtGui.QPixmap()
                pixmap.loadFromData(content)
                label.setPixmap(pixmap.scaled(700, 500, QtCore.Qt.KeepAspectRatio))
                label.setAlignment(QtCore.Qt.AlignCenter)
                layout.addWidget(label)
            # 文本文件
            elif ext in ['.txt', '.py', '.java', '.cpp', '.h', '.c', '.hpp', '.js', 
                        '.html', '.css', '.xml', '.json', '.md', '.csv', '.ini', '.yml', '.yaml']:
                text_edit = QTextEdit()
                text_edit.setReadOnly(True)
                # 尝试将二进制内容转换为文本
                try:
                    text = content.decode('utf-8')
                except UnicodeDecodeError:
                    # 如果无法解码为UTF-8，尝试使用其他编码
                    try:
                        text = content.decode('gbk')
                    except UnicodeDecodeError:
                        # 如果还是无法解码，显示十六进制内容
                        text = content.hex()
                text_edit.setText(text)
                layout.addWidget(text_edit)
            # 其他文件类型
            else:
                # 显示为十六进制内容
                text_edit = QTextEdit()
                text_edit.setReadOnly(True)
                text_edit.setText(content.hex())
                layout.addWidget(text_edit)
            
            dlg.exec()
    
    def delete_selected_file(self):
        # 标记删除并从列表中移除
        if not hasattr(self, "files_to_delete"):
            self.files_to_delete = []
        sel = [it for it in self.tree_archive.selectedItems()]
        if not sel:
            QMessageBox.information(self, "提示", "请先选择要删除的文件")
            return
        for it in sel:
            rel = it.text()
            # 若该文件是新增（在 files_to_add 值中），同时移除新增映射
            # 先从 files_to_add 找到对应的 src 并删除
            to_remove_srcs = [s for s, r in getattr(self, "files_to_add", {}).items() if r == rel]
            for s in to_remove_srcs:
                try:
                    del self.files_to_add[s]
                except KeyError:
                    pass
            # 如果不是新增，则标记为删除
            if rel in getattr(self, "current_archive_files", []):
                self.files_to_delete.append(rel)
            row = self.tree_archive.row(it)
            self.tree_archive.takeItem(row)
            self.log_signal.emit(f"标记删除：{rel}", "info")

    def add_new_file(self):
        files = self._select_files("选择要添加的文件")
        if not files:
            return
        if not hasattr(self, "files_to_add"):
            self.files_to_add = {}
        for src in files:
            # 默认放到压缩包根目录，文件名作为相对路径；可在此扩展为弹窗让用户指定相对路径
            rel = os.path.basename(src)
            # 如果已存在同名项，改为询问或自动重命名：这里简单使用 basename 或覆盖标记
            # 记录映射并在列表中显示 "相对路径 (新增)"
            self.files_to_add[src] = rel.replace("\\", "/")
            self.tree_archive.addItem(rel + "  (新增)")
            self.log_signal.emit(f"标记新增：{rel} <- {src}", "info")
    
    def extract_selected_file(self):
        # 从压缩包中提取选中的文件
        archive = getattr(self, "current_archive", "")
        if not archive:
            archive = self.edit_modify_archive.text().strip()
        if not archive:
            QMessageBox.warning(self, "警告", "请先选择或加载压缩包")
            return
        
        # 获取选中的文件
        sel = [it.text() for it in self.tree_archive.selectedItems()]
        if not sel:
            QMessageBox.information(self, "提示", "请先选择要提取的文件")
            return
        
        # 选择提取目标目录
        target_dir = self._select_directory("选择提取目录")
        if not target_dir:
            return
        
        # 使用compressor.extract方法提取文件
        password = None if not getattr(self, "current_archive_encrypted", False) else None
        success, logs = self.compressor.extract(archive, target_dir, sel, password)
        
        # 输出日志
        for log, level in logs:
            self.log_signal.emit(log, level)
        
        if success:
            QMessageBox.information(self, "成功", f"已成功提取{len(sel)}个文件")
        else:
            # 分析错误类型并提供更精准的错误提示
            error_msg = "提取文件失败，请查看日志"
            error_type = ""
            solution = ""
            
            for log, level in logs:
                if level == "error":
                    if "权限不足" in log:
                        error_type = "权限错误"
                        solution = "请检查压缩包或目标目录的访问权限，确保您有足够的权限进行提取操作。"
                    elif "磁盘空间不足" in log:
                        error_type = "磁盘空间不足"
                        solution = "请清理磁盘空间，确保有足够的空间进行提取操作。"
                    elif "文件被占用" in log:
                        error_type = "文件被占用"
                        solution = "请关闭正在使用该压缩包的程序，然后重试。"
                    elif "密码" in log:
                        error_type = "密码错误"
                        solution = "请检查输入的密码是否正确。"
                    elif "格式" in log:
                        error_type = "格式错误"
                        solution = "请检查压缩包格式是否正确，确保是有效的STZ文件。"
                    break
            
            if error_type:
                error_msg = f"提取文件失败 ({error_type})\n{solution}\n\n详细信息请查看日志"
            
            QMessageBox.critical(self, "失败", error_msg)

    def replace_selected_file(self):
        sel = self.tree_archive.selectedItems()
        if not sel:
            QMessageBox.information(self, "提示", "请选择要替换的目标（单选）")
            return
        if len(sel) > 1:
            QMessageBox.information(self, "提示", "请只选择一个要替换的目标")
            return
        target_item = sel[0]
        target_rel = target_item.text().replace("  (新增)", "").strip()
        src = self._select_file("选择用于替换的本地文件")
        if not src:
            return
        if not hasattr(self, "files_to_add"):
            self.files_to_add = {}
        # 记录替换：用 src 替换 archive 内的 target_rel
        self.files_to_add[src] = target_rel.replace("\\", "/")
        # 更新列表显示，标注为将被替换
        row = self.tree_archive.row(target_item)
        self.tree_archive.takeItem(row)
        self.tree_archive.insertItem(row, target_rel + "  (将被替换)")
        self.log_signal.emit(f"标记替换：{target_rel} <- {src}", "info")

    def start_modify_thread(self):
        """将已标记的新增/替换/删除应用到当前压缩包（在后台线程执行）"""
        if not getattr(self, "current_archive", None):
            QMessageBox.warning(self, "警告", "请先加载要修改的压缩包")
            return

        archive = self.current_archive
        new_files = getattr(self, "files_to_add", {}) or {}
        delete_files = getattr(self, "files_to_delete", []) or []

        if not new_files and not delete_files:
            QMessageBox.information(self, "提示", "未检测到任何修改（新增/替换/删除）")
            return

        # 禁用保存按钮或设置状态
        self.statusBar().showMessage("正在保存修改...")
        self.pb_modify.setValue(0)
        self.txt_log_modify.clear()
        # 启用暂停和取消按钮
        self.btn_modify_pause.setEnabled(True)
        self.btn_modify_cancel.setEnabled(True)

        def worker():
            tempdir = tempfile.mkdtemp()
            try:
                success, logs = self.compressor.modify_archive(
                    archive, tempdir,
                    new_files=new_files if new_files else None,
                    delete_files=delete_files if delete_files else None,
                    password=None if not getattr(self, "current_archive_encrypted", False) else None
                )
                for log, level in logs:
                    self.log_signal.emit(log, level)
                # 刷新列表（回到主线程）
                QtCore.QTimer.singleShot(0, self.load_archive_content)
                if success:
                    self.log_signal.emit("修改已保存", "success")
                    self.statusBar().showMessage("修改已保存")
                    QtCore.QTimer.singleShot(0, lambda: QMessageBox.information(self, "成功", "修改压缩包成功"))
                    play_sound("success")
                else:
                    self.log_signal.emit("修改失败，请查看日志", "error")
                    self.statusBar().showMessage("修改失败")
                    
                    # 分析错误类型并提供更精准的错误提示
                    error_msg = "修改压缩包失败，请查看日志"
                    error_type = ""
                    solution = ""
                    
                    for log, level in logs:
                        if level == "error":
                            if "权限不足" in log:
                                error_type = "权限错误"
                                solution = "请检查压缩包或临时目录的访问权限，确保您有足够的权限进行修改操作。"
                            elif "磁盘空间不足" in log:
                                error_type = "磁盘空间不足"
                                solution = "请清理磁盘空间，确保有足够的空间进行修改操作。"
                            elif "文件被占用" in log:
                                error_type = "文件被占用"
                                solution = "请关闭正在使用该压缩包的程序，然后重试。"
                            elif "密码" in log:
                                error_type = "密码错误"
                                solution = "请检查输入的密码是否正确。"
                            elif "格式" in log:
                                error_type = "格式错误"
                                solution = "请检查压缩包格式是否正确，确保是有效的STZ文件。"
                            break
                    
                    if error_type:
                        error_msg = f"修改压缩包失败 ({error_type})\n{solution}\n\n详细信息请查看日志"
                    
                    QtCore.QTimer.singleShot(0, lambda: QMessageBox.critical(self, "失败", error_msg))
                    play_sound("error")
            finally:
                try:
                    shutil.rmtree(tempdir, ignore_errors=True)
                except:
                    pass
                # 禁用暂停和取消按钮，重置状态
                QtCore.QTimer.singleShot(0, lambda: self._reset_operation_buttons(2))

        threading.Thread(target=worker, daemon=True).start()

    # ---------- 压缩/解压线程 ----------
    def start_compression_thread(self):
        if self.tabs.currentIndex() != 0:
            self.tabs.setCurrentIndex(0)
        if self.list_paths.count() == 0:
            QMessageBox.warning(self, "警告", "请添加待压缩的文件或文件夹")
            play_sound("warning")
            return
        out = self.edit_output.text().strip()
        if not out:
            QMessageBox.warning(self, "警告", "请选择输出路径")
            return
        password = self.edit_password.text() if self.chk_encrypt.isChecked() else None
        compression_level = int(self.combo_level.currentText())
        compression_algorithm = self.combo_algorithm.currentText()
        self.compressor.compression_level = compression_level
        self.compressor.compression_algorithm = compression_algorithm
        # 设置智能压缩选项
        self.compressor.use_smart_compression = self.chk_smart_compress.isChecked()
        # 计算分卷大小
        split_value = int(self.spin_split.value())
        if split_value > 0:
            unit = self.combo_split_unit.currentText()
            if unit == "KB":
                split_size = split_value * 1024
            elif unit == "MB":
                split_size = split_value * 1024 * 1024
            elif unit == "GB":
                split_size = split_value * 1024 * 1024 * 1024
        else:
            split_size = None
        only_new = self.chk_only_new.isChecked()
        delete_source = self.chk_delete_source.isChecked()

        paths = [self.list_paths.item(i).text() for i in range(self.list_paths.count())]

        # 清日志与进度
        self.txt_log.clear()
        self.pb_compress.setValue(0)
        self.statusBar().showMessage("正在压缩...")
        # 启用暂停和取消按钮
        self.btn_pause.setEnabled(True)
        self.btn_cancel.setEnabled(True)

        def worker():
            try:
                result, logs = self.compressor.compress(paths, out, password, split_size=split_size, delete_source=delete_source, only_new=only_new)
                
                # 显示结果
                for log, level in logs:
                    self.log_signal.emit(log, level)
                
                if not result:
                    error_msg = "压缩失败，请查看日志"
                    error_type = ""
                    solution = ""
                    
                    for log, level in logs:
                        if level == "error":
                            if "权限不足" in log:
                                error_type = "权限错误"
                                solution = "请检查输出目录的访问权限，确保您有足够的权限进行压缩操作。"
                            elif "磁盘空间不足" in log:
                                error_type = "磁盘空间不足"
                                solution = "请清理磁盘空间，确保有足够的空间进行压缩操作。"
                            elif "文件被占用" in log:
                                error_type = "文件被占用"
                                solution = "请关闭正在使用相关文件的程序，然后重试。"
                            elif "密码" in log:
                                error_type = "密码错误"
                                solution = "请检查密码设置是否符合要求。"
                            elif "格式" in log:
                                error_type = "格式错误"
                                solution = "请检查文件格式是否支持压缩。"
                            break
                    
                    if error_type:
                        error_msg = f"压缩失败 ({error_type})\n{solution}\n\n详细信息请查看日志"
                    
                    QtCore.QTimer.singleShot(0, lambda: QMessageBox.critical(self, "失败", error_msg))
                else:
                    QtCore.QTimer.singleShot(0, lambda: self.statusBar().showMessage("压缩完成"))
            finally:
                # 禁用暂停和取消按钮，重置状态
                QtCore.QTimer.singleShot(0, lambda: self._reset_operation_buttons(0))

        threading.Thread(target=worker, daemon=True).start()

    def start_decompression_thread(self):
        fn = self.edit_compress_file.text().strip()
        outdir = self.edit_decompress_dir.text().strip()
        if not fn or not outdir:
            QMessageBox.warning(self, "警告", "请选择压缩包和目标目录")
            play_sound("warning")
            return
        pwd = None
        # 清日志
        self.txt_log_decompress.clear()
        self.pb_decompress.setValue(0)
        self.statusBar().showMessage("正在解压...")
        # 启用暂停和取消按钮
        self.btn_decompress_pause.setEnabled(True)
        self.btn_decompress_cancel.setEnabled(True)

        def worker():
            try:
                ok, logs = self.compressor.decompress(fn, outdir, pwd)
                for log, level in logs:
                    self.log_signal.emit(log, level)
                
                # 分析错误类型并提供更精准的错误提示
                if not ok:
                    error_msg = "解压失败，请查看日志"
                    error_type = ""
                    solution = ""
                    
                    for log, level in logs:
                        if level == "error":
                            if "权限不足" in log:
                                error_type = "权限错误"
                                solution = "请检查压缩包或输出目录的访问权限，确保您有足够的权限进行解压操作。"
                            elif "磁盘空间不足" in log:
                                error_type = "磁盘空间不足"
                                solution = "请清理磁盘空间，确保有足够的空间进行解压操作。"
                            elif "文件被占用" in log:
                                error_type = "文件被占用"
                                solution = "请关闭正在使用该压缩包的程序，然后重试。"
                            elif "密码" in log:
                                error_type = "密码错误"
                                solution = "请检查输入的密码是否正确。"
                            elif "格式" in log:
                                error_type = "格式错误"
                                solution = "请检查压缩包格式是否正确，确保是有效的STZ文件。"
                            break
                    
                    if error_type:
                        error_msg = f"解压失败 ({error_type})\n{solution}\n\n详细信息请查看日志"
                    
                    QtCore.QTimer.singleShot(0, lambda: QMessageBox.critical(self, "失败", error_msg))
            finally:
                # 禁用暂停和取消按钮，重置状态
                QtCore.QTimer.singleShot(0, lambda: self._reset_operation_buttons(1))

        threading.Thread(target=worker, daemon=True).start()

    # zip<->stz 简单封装（使用 core_func 的方法）
    def stz_to_zip(self):
        stz = self._select_file("选择 STZ 文件", "STZ (*.stz)")
        if not stz:
            return
        
        zip_out = self._save_file("保存为 ZIP", "ZIP (*.zip)")
        if not zip_out:
            return

        self.txt_log_decompress.clear()

        def worker():
            ok, logs = self.compressor.stz_to_zip(stz, zip_out, None)
            for log, level in logs:
                self.log_signal.emit(log, level)
            if ok:
                QMessageBox.information(self, "完成", f"已生成：{zip_out}")
            else:
                QMessageBox.critical(self, "失败", "转换失败")

        threading.Thread(target=worker, daemon=True).start()

    def zip_to_stz(self):
        zipf = self._select_file("选择 ZIP 文件", "ZIP (*.zip)")
        if not zipf:
            return
        
        stz_out = self._save_file("保存为 STZ", "STZ (*.stz)")
        if not stz_out:
            return

        self.txt_log_decompress.clear()

        def worker():
            res, logs = self.compressor.zip_to_stz(zipf, stz_out, None)
            for log, level in logs:
                self.log_signal.emit(log, level)
            if res:
                QMessageBox.information(self, "完成", f"已生成：{stz_out}")
            else:
                QMessageBox.critical(self, "失败", "转换失败")

        threading.Thread(target=worker, daemon=True).start()

    def batch_decompress(self):
        files = self._select_files("选择多个 STZ 文件", "STZ (*.stz)")
        if not files:
            return
        
        target = self._select_directory("选择目标目录")
        if not target:
            return

        self.txt_log_decompress.clear()

        def worker():
            ok, logs = self.compressor.batch_decompress(files, target, None)
            for log, level in logs:
                self.log_signal.emit(log, level)
            if ok:
                QMessageBox.information(self, "完成", "批量解压完成")
            else:
                QMessageBox.critical(self, "失败", "批量解压失败")

        threading.Thread(target=worker, daemon=True).start()

    # 工具
    def _human_readable_size(self, size_bytes):
        """将字节大小转换为人类可读的格式"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def _select_files(self, title="选择文件", filter="所有文件 (*.*)"):
        """选择多个文件的通用方法
        
        参数:
            title: 对话框标题
            filter: 文件过滤器
            
        返回:
            list: 选中的文件路径列表
        """
        files, _ = QFileDialog.getOpenFileNames(self, title, filter=filter)
        return files
    
    def _select_file(self, title="选择文件", filter="所有文件 (*.*)"):
        """选择单个文件的通用方法
        
        参数:
            title: 对话框标题
            filter: 文件过滤器
            
        返回:
            str: 选中的文件路径，如果用户取消则返回空字符串
        """
        file, _ = QFileDialog.getOpenFileName(self, title, filter=filter)
        return file
    
    def _select_directory(self, title="选择目录"):
        """选择目录的通用方法
        
        参数:
            title: 对话框标题
            
        返回:
            str: 选中的目录路径，如果用户取消则返回空字符串
        """
        directory = QFileDialog.getExistingDirectory(self, title)
        return directory
    
    def _save_file(self, title="保存文件", filter="所有文件 (*.*)"):
        """保存文件的通用方法
        
        参数:
            title: 对话框标题
            filter: 文件过滤器
            
        返回:
            str: 保存的文件路径，如果用户取消则返回空字符串
        """
        file, _ = QFileDialog.getSaveFileName(self, title, filter=filter)
        return file

    def restore_config(self):
        """恢复用户配置，包括压缩级别、最近路径、主题和语言设置等"""
        # 配置项字典，包含默认值和恢复方法
        config_items = {
            # 压缩级别
            "compression_level": {
                "default": 6,
                "restore_func": lambda value: self.page_compress.combo_level.setCurrentText(str(value))
            },
            # 压缩算法
            "compression_algorithm": {
                "default": "zlib",
                "restore_func": lambda value: self.page_compress.combo_algorithm.setCurrentText(value)
            },
            # 最近路径
            "recent_compress_paths": {
                "default": [],
                "restore_func": lambda value: self.page_compress.edit_output.setText(value[0] if value else "")
            },
            "recent_decompress_paths": {
                "default": [],
                "restore_func": lambda value: self.page_decompress.edit_decompress_dir.setText(value[0] if value else "")
            },
            "recent_modify_paths": {
                "default": [],
                "restore_func": lambda value: self.page_modify.edit_modify_archive.setText(value[0] if value else "")
            },
            # 主题设置
            "theme": {
                "default": "system",
                "restore_func": lambda value: [
                    self.theme_combo.setCurrentIndex({"system": 0, "light": 1, "dark": 2}.get(value, 0)),
                    self.apply_theme(value)
                ]
            },
            # 语言设置
            "language": {
                "default": "zh",
                "restore_func": lambda value: self.language_combo.setCurrentIndex({"zh": 0, "en": 1}.get(value, 0))
            }
        }
        
        # 遍历配置项进行恢复
        for config_key, config_info in config_items.items():
            value = self.config.get(config_key, config_info["default"])
            try:
                config_info["restore_func"](value)
            except Exception as e:
                # 如果恢复失败，使用默认值
                self.log_signal.emit(f"配置恢复失败 ({config_key}): {e}", "warning")
                self.config[config_key] = config_info["default"]
                
        # 检查是否首次启动，显示引导提示
        if self.config.get("first_launch", True):
            self.show_guide()
            # 标记为非首次启动
            self.config["first_launch"] = False
        
        save_config(self.config)
    
    def show_guide(self):
        """显示操作引导提示"""
        current_lang = self.config.get("language", "zh")
        lang_pack = LANGUAGE_PACKS.get(current_lang, LANGUAGE_PACKS["zh"])
        
        guide_dlg = QMessageBox()
        guide_dlg.setWindowTitle(lang_pack["guide_title"])
        guide_dlg.setText(lang_pack["guide_welcome"])
        guide_dlg.setInformativeText(lang_pack["guide_steps"])
        guide_dlg.setStandardButtons(QMessageBox.Ok)
        guide_dlg.exec()
    
    def change_language(self, index):
        """语言切换处理"""
        # 防止循环调用
        self.language_combo.currentIndexChanged.disconnect(self.change_language)
        try:
            lang_map = {0: "zh", 1: "en"}
            language = lang_map.get(index, "zh")
            self.load_language(language)
            # 保存语言设置
            self.config["language"] = language
            save_config(self.config)
        finally:
            # 重新连接信号
            self.language_combo.currentIndexChanged.connect(self.change_language)
    
    def load_language(self, language):
        """加载语言包"""
        try:
            lang_pack = LANGUAGE_PACKS.get(language, LANGUAGE_PACKS["zh"])
            
            # 更新界面文本
            self.setWindowTitle(lang_pack["window_title"])
            self.tabs.setTabText(0, lang_pack["tab_compress"])
            self.tabs.setTabText(1, lang_pack["tab_decompress"])
            self.tabs.setTabText(2, lang_pack["tab_modify"])
            self.tabs.setTabText(3, lang_pack["tab_analyze"])
            self.tabs.setTabText(4, lang_pack["tab_history"])
            
            # 更新主题切换控件
            if hasattr(self, 'lbl_theme'):
                self.lbl_theme.setText(lang_pack["theme_label"])
            self.theme_combo.clear()
            self.theme_combo.addItems([lang_pack["theme_system"], lang_pack["theme_light"], lang_pack["theme_dark"]])
        
            # 更新语言切换控件
            if hasattr(self, 'lbl_language'):
                self.lbl_language.setText(lang_pack["language_label"])
            self.language_combo.clear()
            self.language_combo.addItems([lang_pack["language_zh"], lang_pack["language_en"]])
            
            # 更新帮助按钮文本
            if hasattr(self, 'btn_help'):
                self.btn_help.setText(lang_pack["btn_help"])
        
            # 更新压缩页控件
            # 文件列表按钮
            if hasattr(self, 'btn_add_files'):
                self.btn_add_files.setText(lang_pack["btn_add_files"])
            if hasattr(self, 'btn_add_folders'):
                self.btn_add_folders.setText(lang_pack["btn_add_folders"])
            if hasattr(self, 'btn_remove'):
                self.btn_remove.setText(lang_pack["btn_remove"])
            if hasattr(self, 'btn_clear'):
                self.btn_clear.setText(lang_pack["btn_clear"])
        
            # 选项区域
            if hasattr(self, 'lbl_compress_level'):
                self.lbl_compress_level.setText(lang_pack["compress_level"])
            if hasattr(self, 'chk_custom_dict'):
                self.chk_custom_dict.setText(lang_pack["use_custom_dictionary"])
            if hasattr(self, 'lbl_password'):
                self.lbl_password.setText(lang_pack["edit_password"])
            if hasattr(self, 'chk_encrypt'):
                self.chk_encrypt.setText(lang_pack["check_password"])
            if hasattr(self, 'lbl_split_size'):
                self.lbl_split_size.setText(lang_pack["split_size"])
            if hasattr(self, 'chk_only_new'):
                self.chk_only_new.setText(lang_pack["only_new"])
            if hasattr(self, 'chk_delete_source'):
                self.chk_delete_source.setText(lang_pack["delete_source"])
        
            # 输出路径与控制
            if hasattr(self, 'lbl_output_file'):
                self.lbl_output_file.setText(lang_pack["output_file"])
            if hasattr(self, 'btn_browse_compress'):
                self.btn_browse_compress.setText(lang_pack["btn_browse"])
            if hasattr(self, 'btn_compress_start'):
                self.btn_compress_start.setText(lang_pack["btn_compress_start"])
            if hasattr(self, 'btn_compress_pause'):
                self.btn_compress_pause.setText(lang_pack["btn_pause"])
            if hasattr(self, 'btn_compress_cancel'):
                self.btn_compress_cancel.setText(lang_pack["btn_cancel"])
        
            # 更新解压页控件
            if hasattr(self, 'lbl_compress_file'):
                self.lbl_compress_file.setText(lang_pack["compress_file"])
            if hasattr(self, 'btn_browse_decompress'):
                self.btn_browse_decompress.setText(lang_pack["btn_browse"])
            if hasattr(self, 'lbl_decompress_dir'):
                self.lbl_decompress_dir.setText(lang_pack["decompress_dir"])
            if hasattr(self, 'btn_choose_decompress_dir'):
                self.btn_choose_decompress_dir.setText(lang_pack["btn_browse"])
            if hasattr(self, 'btn_decompress_start'):
                self.btn_decompress_start.setText(lang_pack["btn_decompress_start"])
            if hasattr(self, 'btn_decompress_pause'):
                self.btn_decompress_pause.setText(lang_pack["btn_pause"])
            if hasattr(self, 'btn_decompress_cancel'):
                self.btn_decompress_cancel.setText(lang_pack["btn_cancel"])
            if hasattr(self, 'btn_stz_to_zip'):
                self.btn_stz_to_zip.setText(lang_pack["btn_stz_to_zip"])
            if hasattr(self, 'btn_zip_to_stz'):
                self.btn_zip_to_stz.setText(lang_pack["btn_zip_to_stz"])
            if hasattr(self, 'btn_batch_decompress'):
                self.btn_batch_decompress.setText(lang_pack["btn_batch_decompress"])
        
            # 更新修改压缩包页控件
            if hasattr(self, 'lbl_modify_archive'):
                self.lbl_modify_archive.setText(lang_pack["compress_file"])
            if hasattr(self, 'btn_browse_modify'):
                self.btn_browse_modify.setText(lang_pack["btn_browse"])
            if hasattr(self, 'btn_load_content'):
                self.btn_load_content.setText(lang_pack["btn_load_content"])
            if hasattr(self, 'btn_preview_content'):
                self.btn_preview_content.setText(lang_pack["btn_preview_content"])
            if hasattr(self, 'btn_extract'):
                self.btn_extract.setText(lang_pack["btn_extract"])
            if hasattr(self, 'btn_delete'):
                self.btn_delete.setText(lang_pack["btn_delete"])
            if hasattr(self, 'btn_addnew'):
                self.btn_addnew.setText(lang_pack["btn_addnew"])
            if hasattr(self, 'btn_replace'):
                self.btn_replace.setText(lang_pack["btn_replace"])
            if hasattr(self, 'btn_save_modify'):
                self.btn_save_modify.setText(lang_pack["btn_save_modify"])
        except Exception:
            pass
        
        # 更新各个页面的语言
        pages = [
            ('page_compress', self.page_compress),
            ('page_decompress', self.page_decompress),
            ('page_modify', self.page_modify),
            ('page_analyzer', self.page_analyzer),
            ('page_history', self.page_history)
        ]
        for page_name, page in pages:
            try:
                if hasattr(page, 'change_language') and callable(page.change_language):
                    page.change_language(language)
            except Exception as e:
                print(f"更新{page_name}语言时出错: {e}")
            
        # 保持当前语言设置
        if language == "zh":
            self.language_combo.setCurrentIndex(0)
        else:
            self.language_combo.setCurrentIndex(1)

    # 退出时保存配置
    def change_theme(self, index):
        """切换主题"""
        theme_map = {0: "system", 1: "light", 2: "dark"}
        if index in theme_map:  # 添加索引检查，避免清空时触发的-1索引
            theme = theme_map[index]
            self.config["theme"] = theme
            save_config(self.config)
            self.apply_theme(theme)
    
    def apply_theme(self, theme):
        """应用主题"""
        # 获取应用程序
        app = QApplication.instance()
        
        # 如果主题是系统默认，使用系统主题
        if theme == "system":
            # PySide6 5.15+ 支持系统主题
            if hasattr(QtCore.Qt, "ColorScheme_Dark"):
                # 设置为跟随系统
                app.setStyle("Fusion")
                # 清除可能存在的样式表
                app.setStyleSheet("")
            return
        
        # 应用浅色或深色主题
        app.setStyle("Fusion")
        
        if theme == "dark":
            # 深色主题样式
            dark_palette = QtGui.QPalette()
            dark_palette.setColor(QtGui.QPalette.Window, QtGui.QColor(53, 53, 53))
            dark_palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(255, 255, 255))
            dark_palette.setColor(QtGui.QPalette.Base, QtGui.QColor(25, 25, 25))
            dark_palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(53, 53, 53))
            dark_palette.setColor(QtGui.QPalette.ToolTipBase, QtGui.QColor(255, 255, 255))
            dark_palette.setColor(QtGui.QPalette.ToolTipText, QtGui.QColor(255, 255, 255))
            dark_palette.setColor(QtGui.QPalette.Text, QtGui.QColor(255, 255, 255))
            dark_palette.setColor(QtGui.QPalette.Button, QtGui.QColor(53, 53, 53))
            dark_palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor(255, 255, 255))
            dark_palette.setColor(QtGui.QPalette.BrightText, QtGui.QColor(255, 0, 0))
            dark_palette.setColor(QtGui.QPalette.Link, QtGui.QColor(42, 130, 218))
            dark_palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(42, 130, 218))
            dark_palette.setColor(QtGui.QPalette.HighlightedText, QtGui.QColor(0, 0, 0))
            app.setPalette(dark_palette)
            
            # 深色主题样式表（控件美化）
            app.setStyleSheet("""
                /* 滚动条样式 */
                QScrollBar:vertical {
                    background: #535353;
                    width: 10px;
                }
                QScrollBar::handle:vertical {
                    background: #888;
                    border-radius: 5px;
                }
                QScrollBar::handle:vertical:hover {
                    background: #aaa;
                }
                QScrollBar::add-line:vertical,
                QScrollBar::sub-line:vertical {
                    background: none;
                }
                
                QScrollBar:horizontal {
                    background: #535353;
                    height: 10px;
                }
                QScrollBar::handle:horizontal {
                    background: #888;
                    border-radius: 5px;
                }
                QScrollBar::handle:horizontal:hover {
                    background: #aaa;
                }
                QScrollBar::add-line:horizontal,
                QScrollBar::sub-line:horizontal {
                    background: none;
                }
                
                /* 按钮样式 */
                QPushButton {
                    background: #535353;
                    border: 1px solid #777;
                    padding: 5px 10px;
                    border-radius: 3px;
                    color: white;
                }
                QPushButton:hover {
                    background: #666;
                    border-color: #999;
                }
                QPushButton:pressed {
                    background: #444;
                }
                QPushButton:disabled {
                    background: #333;
                    color: #666;
                    border-color: #555;
                }
                
                /* 列表控件样式 */
                QListWidget {
                    background: #252525;
                    border: 1px solid #555;
                    border-radius: 3px;
                }
                QListWidget::item {
                    padding: 3px;
                    border-radius: 2px;
                }
                QListWidget::item:selected {
                    background: #2a5caa;
                    color: white;
                }
                QListWidget::item:hover {
                    background: #3a6cba;
                }
                
                /* 文本编辑框样式 */
                QTextEdit {
                    background: #252525;
                    border: 1px solid #555;
                    border-radius: 3px;
                    color: white;
                }
                
                /* 进度条样式 */
                QProgressBar {
                    background: #535353;
                    border: 1px solid #777;
                    border-radius: 3px;
                    text-align: center;
                    color: white;
                }
                QProgressBar::chunk {
                    background: #4282d3;
                    border-radius: 2px;
                }
            """)
        else:
            # 浅色主题样式
            light_palette = QtGui.QPalette()
            app.setPalette(light_palette)  # 使用默认浅色主题
            
            # 浅色主题样式表（控件美化）
            app.setStyleSheet("""
                /* 滚动条样式 */
                QScrollBar:vertical {
                    background: #f0f0f0;
                    width: 10px;
                }
                QScrollBar::handle:vertical {
                    background: #bbb;
                    border-radius: 5px;
                }
                QScrollBar::handle:vertical:hover {
                    background: #999;
                }
                QScrollBar::add-line:vertical,
                QScrollBar::sub-line:vertical {
                    background: none;
                }
                
                QScrollBar:horizontal {
                    background: #f0f0f0;
                    height: 10px;
                }
                QScrollBar::handle:horizontal {
                    background: #bbb;
                    border-radius: 5px;
                }
                QScrollBar::handle:horizontal:hover {
                    background: #999;
                }
                QScrollBar::add-line:horizontal,
                QScrollBar::sub-line:horizontal {
                    background: none;
                }
                
                /* 按钮样式 */
                QPushButton {
                    background: #f0f0f0;
                    border: 1px solid #ccc;
                    padding: 5px 10px;
                    border-radius: 3px;
                    color: black;
                }
                QPushButton:hover {
                    background: #e0e0e0;
                    border-color: #bbb;
                }
                QPushButton:pressed {
                    background: #d0d0d0;
                }
                QPushButton:disabled {
                    background: #f5f5f5;
                    color: #999;
                    border-color: #ddd;
                }
                
                /* 列表控件样式 */
                QListWidget {
                    background: white;
                    border: 1px solid #ccc;
                    border-radius: 3px;
                }
                QListWidget::item {
                    padding: 3px;
                    border-radius: 2px;
                }
                QListWidget::item:selected {
                    background: #4282d3;
                    color: white;
                }
                QListWidget::item:hover {
                    background: #e0ebf7;
                }
                
                /* 文本编辑框样式 */
                QTextEdit {
                    background: white;
                    border: 1px solid #ccc;
                    border-radius: 3px;
                    color: black;
                }
                
                /* 进度条样式 */
                QProgressBar {
                    background: #f0f0f0;
                    border: 1px solid #ccc;
                    border-radius: 3px;
                    text-align: center;
                    color: black;
                }
                QProgressBar::chunk {
                    background: #4282d3;
                    border-radius: 2px;
                }
            """)
            
    def closeEvent(self, event):
        try:
            self.config["default_compression_level"] = int(self.combo_level.currentText())
            self.config["window_geometry"] = f"{self.width()}x{self.height()}"
            # 保存主题设置
            theme_index = self.theme_combo.currentIndex()
            theme_map = {0: "system", 1: "light", 2: "dark"}
            self.config["theme"] = theme_map[theme_index]
            # 保存语言设置
            lang_index = self.language_combo.currentIndex()
            lang_map = {0: "zh", 1: "en"}
            self.config["language"] = lang_map[lang_index]
            # 保存首次启动标记
            if "first_launch" in self.config:
                self.config["first_launch"] = self.config["first_launch"]
            save_config(self.config)
        except:
            pass
        super().closeEvent(event)
    
    def show_help(self):
        """显示帮助文档"""
        help_dialog = QDialog(self)
        help_dialog.setWindowTitle("帮助文档")
        help_dialog.resize(800, 600)
        
        # 创建布局
        layout = QVBoxLayout(help_dialog)
        
        # 创建文本浏览器
        text_browser = QTextBrowser()
        
        # 读取并显示帮助文档
        # 获取程序目录，处理打包后的情况
        import sys
        if hasattr(sys, '_MEIPASS'):
            # 打包后的情况
            help_file_path = os.path.join(sys._MEIPASS, "help.html")
        else:
            # 未打包的情况
            help_file_path = os.path.join(os.path.dirname(__file__), "help.html")
        
        if os.path.exists(help_file_path):
            with open(help_file_path, "r", encoding="utf-8") as f:
                text_browser.setHtml(f.read())
        else:
            text_browser.setHtml("<h1>帮助文档未找到</h1><p>请确保help.html文件存在于程序目录中。</p>")
        
        layout.addWidget(text_browser)
        help_dialog.exec_()


class ResponsiveCompressionGUI(CompressionGUI):
    """响应式布局的压缩工具GUI"""
    def __init__(self):
        super().__init__()
        
        # 设置窗口大小变化事件
        self.resizeEvent = self._on_resize
        
        # 设置最小窗口大小
        self.setMinimumSize(800, 600)
        self.setMaximumSize(800, 600)
        
        # 应用初始布局
        self._adjust_layouts()
    
    def handle_stz_file(self, file_path):
        """处理双击STZ文件的操作"""
        # 切换到解压标签页
        self.tabs.setCurrentIndex(1)  # 假设解压标签页是第二个标签
        
        # 设置压缩文件路径和默认解压目录
        self.page_decompress.handle_stz_file(file_path)
    
    def _on_resize(self, event):
        """窗口大小变化时调整布局"""
        super().resizeEvent(event)
        self._adjust_layouts()
    
    def _adjust_layouts(self):
        """根据窗口大小调整布局"""
        width = self.width()
        
        # 调整压缩页的选项布局
        if hasattr(self, "page_compress"):
            # 这里可以根据窗口宽度调整控件的显示方式
            # 例如，当窗口变窄时，可以将水平布局改为垂直布局
            pass
        
        # 调整解压页的布局
        if hasattr(self, "page_decompress"):
            pass
        
        # 调整修改压缩包页的布局
        if hasattr(self, "page_modify"):
            pass