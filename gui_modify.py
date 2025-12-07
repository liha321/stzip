"""
gui_modify.py - 修改页面功能模块
"""
import os
from PySide6 import QtCore, QtWidgets, QtGui
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QTextEdit, QProgressBar, QLabel, QLineEdit, 
    QTreeWidget, QTreeWidgetItem, QMenu, QFileDialog,
    QSplitter, QMessageBox
)

from core_func import CustomCompressor
from gui_utils import LANGUAGE_PACKS

class ModifyPage(QWidget):
    """修改压缩包内容功能页面"""
    progress_signal = QtCore.Signal(int, str)           # progress, message
    log_signal = QtCore.Signal(str, str)               # log, level
    modify_done = QtCore.Signal(object)                # (result, logs)

    def __init__(self, compressor: CustomCompressor, config: dict, language="zh"):
        super().__init__()
        self.compressor = compressor
        self.config = config
        self.language = language
        self.lang_pack = LANGUAGE_PACKS.get(language, LANGUAGE_PACKS["zh"])
        
        self.current_archive_path = ""
        self.file_tree_items = []  # 保存文件树项与路径的映射
        
        # compressor 回调 -> 发射 Qt 信号（线程安全）
        self.compressor.progress_callback = self._progress_emitter
        
        self.setup_ui()
        self.load_config()

    def setup_ui(self):
        """设置修改页面UI"""
        main_layout = QVBoxLayout(self)

        # 压缩包选择
        mf_layout = QHBoxLayout()
        self.lbl_modify_archive = QLabel(self.lang_pack["compress_file"])
        mf_layout.addWidget(self.lbl_modify_archive)
        
        self.edit_modify_archive = QLineEdit()
        # 压缩包选择输入框支持拖拽
        self.edit_modify_archive.setAcceptDrops(True)
        self.edit_modify_archive.dragEnterEvent = self._drag_enter_event
        self.edit_modify_archive.dropEvent = self._drop_event
        mf_layout.addWidget(self.edit_modify_archive, 1)
        
        self.btn_browse_modify = QPushButton(self.lang_pack["btn_browse"])
        self.btn_browse_modify.clicked.connect(self.choose_modify_archive)
        mf_layout.addWidget(self.btn_browse_modify)
        
        main_layout.addLayout(mf_layout)

        # 内容加载按钮
        load_layout = QHBoxLayout()
        self.btn_load_archive = QPushButton(self.lang_pack["btn_load_archive"])
        self.btn_load_archive.clicked.connect(self.load_archive_content)
        load_layout.addWidget(self.btn_load_archive)
        
        # 搜索框
        self.lbl_search = QLabel(self.lang_pack["search"])
        load_layout.addWidget(self.lbl_search)
        
        self.edit_search = QLineEdit()
        self.edit_search.textChanged.connect(self.search_files)
        load_layout.addWidget(self.edit_search, 1)
        
        main_layout.addLayout(load_layout)

        # 文件列表树与日志
        splitter = QSplitter(QtCore.Qt.Orientation.Horizontal)
        
        # 文件列表树
        self.tree_files = QTreeWidget()
        self.tree_files.setColumnCount(4)
        self.tree_files.setHeaderLabels(["文件名", "大小", "修改时间", "压缩率"])
        
        # 设置列宽
        self.tree_files.setColumnWidth(0, 300)
        self.tree_files.setColumnWidth(1, 100)
        self.tree_files.setColumnWidth(2, 200)
        self.tree_files.setColumnWidth(3, 100)
        
        # 设置右键菜单
        self.tree_files.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tree_files.customContextMenuRequested.connect(self.show_context_menu)
        
        splitter.addWidget(self.tree_files)
        
        # 日志与操作按钮
        log_oper_layout = QVBoxLayout()
        
        # 日志文本框
        self.txt_log_modify = QTextEdit()
        self.txt_log_modify.setReadOnly(True)
        log_oper_layout.addWidget(self.txt_log_modify, 1)
        
        # 操作按钮
        oper_layout = QHBoxLayout()
        self.btn_extract_file = QPushButton(self.lang_pack["btn_extract_file"])
        self.btn_extract_file.clicked.connect(self.extract_selected_file)
        oper_layout.addWidget(self.btn_extract_file)
        
        self.btn_delete_file = QPushButton(self.lang_pack["btn_delete_file"])
        self.btn_delete_file.clicked.connect(self.delete_selected_file)
        oper_layout.addWidget(self.btn_delete_file)
        
        self.btn_add_file = QPushButton(self.lang_pack["btn_add_file"])
        self.btn_add_file.clicked.connect(self.add_file)
        oper_layout.addWidget(self.btn_add_file)
        
        self.btn_replace_file = QPushButton(self.lang_pack["btn_replace_file"])
        self.btn_replace_file.clicked.connect(self.replace_selected_file)
        oper_layout.addWidget(self.btn_replace_file)
        
        log_oper_layout.addLayout(oper_layout)
        
        # 保存修改按钮
        self.btn_save_modify = QPushButton(self.lang_pack["btn_save_modify"])
        self.btn_save_modify.clicked.connect(self.save_modifications)
        log_oper_layout.addWidget(self.btn_save_modify)
        
        # 创建日志操作容器
        log_oper_widget = QWidget()
        log_oper_widget.setLayout(log_oper_layout)
        splitter.addWidget(log_oper_widget)
        
        # 设置分割比例
        splitter.setSizes([500, 300])
        
        main_layout.addWidget(splitter, 1)

    def load_config(self):
        """加载配置"""
        pass  # 暂时不需要加载特定配置

    def _select_file(self, title, file_filter="所有文件 (*.*)"):
        """选择单个文件
        
        参数:
            title: 对话框标题
            file_filter: 文件过滤器
            
        返回:
            选中的文件路径
        """
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            self.lang_pack.get(title, title), 
            "", 
            file_filter
        )
        return file_path

    def _select_files(self, title, file_filter="所有文件 (*.*)"):
        """选择多个文件
        
        参数:
            title: 对话框标题
            file_filter: 文件过滤器
            
        返回:
            选中的文件路径列表
        """
        files, _ = QFileDialog.getOpenFileNames(
            self, 
            self.lang_pack.get(title, title), 
            "", 
            file_filter
        )
        return files

    def _select_directory(self, title):
        """选择目录
        
        参数:
            title: 对话框标题
            
        返回:
            选中的目录路径
        """
        return QFileDialog.getExistingDirectory(
            self, 
            self.lang_pack.get(title, title), 
            "",
            QFileDialog.Option.ShowDirsOnly
        )

    def _save_file(self, title, file_filter="所有文件 (*.*)"):
        """保存文件
        
        参数:
            title: 对话框标题
            file_filter: 文件过滤器
            
        返回:
            保存的文件路径
        """
        file_path, _ = QFileDialog.getSaveFileName(
            self, 
            self.lang_pack.get(title, title), 
            "", 
            file_filter
        )
        return file_path

    def _drag_enter_event(self, event):
        """处理拖拽进入事件"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def _drop_event(self, event):
        """处理拖拽释放事件（针对QLineEdit）"""
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self.edit_modify_archive.setText(path)
            event.acceptProposedAction()

    def choose_modify_archive(self):
        """选择要修改的压缩包"""
        file_path = self._select_file("select_stz_file", "STZ压缩文件 (*.stz)")
        if file_path:
            self.edit_modify_archive.setText(file_path)

    def load_archive_content(self):
        """加载压缩包内容"""
        archive_path = self.edit_modify_archive.text()
        if not archive_path or not os.path.exists(archive_path):
            self.log_signal.emit(self.lang_pack["select_valid_archive"], "warning")
            return
        
        try:
            # 加载压缩包内容
            self.current_archive_path = archive_path
            file_info_list = self.compressor.preview_archive(archive_path)
            
            if file_info_list:
                # 清空当前文件树
                self.tree_files.clear()
                self.file_tree_items.clear()
                
                # 创建文件树结构
                self._build_file_tree(file_info_list)
                
                self.log_signal.emit(f"{self.lang_pack['load_archive_success']}: {len(file_info_list)} {self.lang_pack['files_folders']}", "success")
            else:
                self.log_signal.emit(self.lang_pack["archive_empty_or_corrupted"], "warning")
                
        except Exception as e:
            self.log_signal.emit(f"{self.lang_pack['load_archive_fail']}: {e}", "error")

    def _build_file_tree(self, file_info_list):
        """构建文件树结构"""
        # 创建根目录映射
        root_dirs = {}
        
        for file_info in file_info_list:
            file_path = file_info["name"]
            
            # 分割路径
            path_parts = file_path.split("/")
            current_parent = None
            current_path = ""
            
            for i, part in enumerate(path_parts):
                is_last = (i == len(path_parts) - 1)
                current_path += part if current_path == "" else f"/{part}"
                
                if is_last:
                    # 处理文件
                    size = self._human_readable_size(file_info["size"])
                    mod_time = file_info["mod_time"]
                    compression_ratio = f"{file_info['compression_ratio']:.1f}%"
                    
                    item = QTreeWidgetItem([part, size, mod_time, compression_ratio])
                    item.setData(0, QtCore.Qt.UserRole, current_path)
                    item.setData(0, QtCore.Qt.UserRole + 1, "file")
                    
                    if current_parent:
                        current_parent.addChild(item)
                    else:
                        self.tree_files.addTopLevelItem(item)
                    
                    self.file_tree_items.append(item)
                else:
                    # 处理目录
                    if current_path not in root_dirs:
                        dir_item = QTreeWidgetItem([part])
                        dir_item.setData(0, QtCore.Qt.UserRole, current_path)
                        dir_item.setData(0, QtCore.Qt.UserRole + 1, "dir")
                        
                        if current_parent:
                            current_parent.addChild(dir_item)
                        else:
                            self.tree_files.addTopLevelItem(dir_item)
                        
                        root_dirs[current_path] = dir_item
                        self.file_tree_items.append(dir_item)
                    
                    current_parent = root_dirs[current_path]
        
        # 展开所有节点
        self.tree_files.expandAll()

    def search_files(self, search_text):
        """搜索文件"""
        if not search_text:
            # 如果搜索文本为空，显示所有项
            for item in self.file_tree_items:
                item.setHidden(False)
            return
        
        # 搜索匹配的项
        search_text_lower = search_text.lower()
        for item in self.file_tree_items:
            file_name = item.text(0).lower()
            item.setHidden(search_text_lower not in file_name)

    def show_context_menu(self, position):
        """显示右键菜单"""
        menu = QMenu(self)
        
        # 获取当前选中项
        selected_items = self.tree_files.selectedItems()
        if not selected_items:
            return
            
        current_item = selected_items[0]
        item_type = current_item.data(0, QtCore.Qt.UserRole + 1)
        
        # 添加菜单项
        if item_type == "file":
            menu.addAction(self.lang_pack["menu_extract_file"], self.extract_selected_file)
            menu.addAction(self.lang_pack["menu_delete_file"], self.delete_selected_file)
            menu.addAction(self.lang_pack["menu_replace_file"], self.replace_selected_file)
        elif item_type == "dir":
            menu.addAction(self.lang_pack["menu_extract_folder"], self.extract_selected_file)
            menu.addAction(self.lang_pack["menu_delete_folder"], self.delete_selected_file)
        
        menu.exec(self.tree_files.viewport().mapToGlobal(position))

    def extract_selected_file(self):
        """提取选中文件"""
        selected_items = self.tree_files.selectedItems()
        if not selected_items:
            self.log_signal.emit(self.lang_pack["select_file_folder_first"], "warning")
            return
            
        if not self.current_archive_path:
            self.log_signal.emit(self.lang_pack["load_archive_first"], "warning")
            return
        
        # 选择提取目录
        extract_dir = self._select_directory("select_extract_dir")
        if not extract_dir:
            return
        
        try:
            for item in selected_items:
                file_path = item.data(0, QtCore.Qt.UserRole)
                
                # 提取文件
                self.compressor.extract_specific_files(self.current_archive_path, [file_path], extract_dir)
            
            self.log_signal.emit(f"{self.lang_pack['extract_success']}: {len(selected_items)} {self.lang_pack['items_to']} {extract_dir}", "success")
            
        except Exception as e:
            self.log_signal.emit(f"{self.lang_pack['extract_fail']}: {e}", "error")

    def delete_selected_file(self):
        """删除选中文件"""
        selected_items = self.tree_files.selectedItems()
        if not selected_items:
            self.log_signal.emit(self.lang_pack["select_file_folder_first"], "warning")
            return
            
        if not self.current_archive_path:
            self.log_signal.emit(self.lang_pack["load_archive_first"], "warning")
            return
        
        # 确认删除
        reply = QMessageBox.question(
            self, 
            self.lang_pack["confirm_delete"], 
            f"{self.lang_pack['confirm_delete_items']}: {len(selected_items)} {self.lang_pack['items']}？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
        
        try:
            # 获取要删除的文件路径
            delete_files = []
            for item in selected_items:
                file_path = item.data(0, QtCore.Qt.UserRole)
                delete_files.append(file_path)
                
                # 从文件树中移除
                parent = item.parent()
                if parent:
                    parent.removeChild(item)
                else:
                    self.tree_files.takeTopLevelItem(self.tree_files.indexOfTopLevelItem(item))
                
                self.file_tree_items.remove(item)
            
            # 从压缩包中删除文件
            self.compressor.remove_files_from_archive(self.current_archive_path, delete_files)
            
            self.log_signal.emit(f"{self.lang_pack['delete_success']}: {len(delete_files)} {self.lang_pack['items']}", "success")
            
        except Exception as e:
            self.log_signal.emit(f"{self.lang_pack['delete_fail']}: {e}", "error")

    def add_file(self):
        """添加文件"""
        if not self.current_archive_path:
            self.log_signal.emit(self.lang_pack["load_archive_first"], "warning")
            return
        
        # 选择要添加的文件
        files_to_add = self._select_files("select_files_to_add", "所有文件 (*.*)")
        if not files_to_add:
            return
        
        try:
            # 添加文件到压缩包
            for file_path in files_to_add:
                file_name = os.path.basename(file_path)
                self.compressor.add_file_to_archive(self.current_archive_path, file_path, file_name)
                
            # 重新加载压缩包内容
            self.load_archive_content()
            
            self.log_signal.emit(f"{self.lang_pack['add_success']}: {len(files_to_add)} {self.lang_pack['files']}", "success")
            
        except Exception as e:
            self.log_signal.emit(f"{self.lang_pack['add_fail']}: {e}", "error")

    def replace_selected_file(self):
        """替换选中文件"""
        selected_items = self.tree_files.selectedItems()
        if not selected_items:
            self.log_signal.emit(self.lang_pack["select_file_first"], "warning")
            return
            
        if not self.current_archive_path:
            self.log_signal.emit(self.lang_pack["load_archive_first"], "warning")
            return
        
        # 只处理第一个选中的文件
        current_item = selected_items[0]
        item_type = current_item.data(0, QtCore.Qt.UserRole + 1)
        if item_type != "file":
            self.log_signal.emit(self.lang_pack["can_only_replace_files"], "warning")
            return
        
        # 获取原文件路径
        original_file_path = current_item.data(0, QtCore.Qt.UserRole)
        
        # 选择替换文件
        replace_file = self._select_file("select_replace_file", "所有文件 (*.*)")
        if not replace_file:
            return
        
        try:
            # 替换文件
            self.compressor.replace_file_in_archive(self.current_archive_path, original_file_path, replace_file)
            
            # 重新加载压缩包内容
            self.load_archive_content()
            
            self.log_signal.emit(f"{self.lang_pack['replace_success']}: {os.path.basename(original_file_path)}", "success")
            
        except Exception as e:
            self.log_signal.emit(f"{self.lang_pack['replace_fail']}: {e}", "error")

    def save_modifications(self):
        """保存修改"""
        if not self.current_archive_path:
            self.log_signal.emit(self.lang_pack["load_archive_first"], "warning")
            return
        
        try:
            # 保存修改
            self.compressor.save_archive_modifications(self.current_archive_path)
            self.log_signal.emit(self.lang_pack["save_modifications_success"], "success")
            
        except Exception as e:
            self.log_signal.emit(f"{self.lang_pack['save_modifications_fail']}: {e}", "error")

    def _human_readable_size(self, size_bytes: int) -> str:
        """
        将字节大小转换为人类可读的格式
        
        参数:
            size_bytes: 字节大小
            
        返回:
            人类可读的大小字符串
        """
        if size_bytes == 0:
            return "0 B"
        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = 0
        size = float(size_bytes)
        while size >= 1024 and i < len(size_name) - 1:
            size /= 1024
            i += 1
        return f"{size:.2f} {size_name[i]}"

    def _progress_emitter(self, progress, message, log_level="info"):
        """进度发射器"""
        self.progress_signal.emit(progress, message)
        self.log_signal.emit(message, log_level)

    def change_language(self, language):
        """更改语言"""
        self.language = language
        self.lang_pack = LANGUAGE_PACKS.get(language, LANGUAGE_PACKS["zh"])
        
        # 更新UI文本
        self.lbl_modify_archive.setText(self.lang_pack["compress_file"])
        self.btn_browse_modify.setText(self.lang_pack["btn_browse"])
        self.btn_load_archive.setText(self.lang_pack["btn_load_archive"])
        self.lbl_search.setText(self.lang_pack["search"])
        self.btn_extract_file.setText(self.lang_pack["btn_extract_file"])
        self.btn_delete_file.setText(self.lang_pack["btn_delete_file"])
        self.btn_add_file.setText(self.lang_pack["btn_add_file"])
        self.btn_replace_file.setText(self.lang_pack["btn_replace_file"])
        self.btn_save_modify.setText(self.lang_pack["btn_save_modify"])
