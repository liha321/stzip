"""
gui_compress.py - 压缩页面功能模块
"""
import os
from PySide6 import QtCore, QtWidgets, QtGui
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QPushButton, 
    QListWidget, QTextEdit, QProgressBar, QLabel, QLineEdit, 
    QCheckBox, QComboBox, QSpinBox, QFileDialog
)

from core_func import CustomCompressor
from gui_utils import LANGUAGE_PACKS

class CompressPage(QWidget):
    """压缩功能页面"""
    progress_signal = QtCore.Signal(int, str)           # progress, message
    log_signal = QtCore.Signal(str, str)               # log, level
    compress_done = QtCore.Signal(object)              # (result, logs)

    def __init__(self, compressor: CustomCompressor, config: dict, language="zh"):
        super().__init__()
        self.compressor = compressor
        self.config = config
        self.language = language
        self.lang_pack = LANGUAGE_PACKS.get(language, LANGUAGE_PACKS["zh"])
        
        self.is_paused = False
        self.is_cancelled = False
        
        # compressor 回调 -> 发射 Qt 信号（线程安全）
        self.compressor.progress_callback = self._progress_emitter
        
        self.setup_ui()
        self.load_config()

    def setup_ui(self):
        """设置压缩页面UI"""
        main_layout = QVBoxLayout(self)
        
        # 文件列表
        hl = QHBoxLayout()
        self.list_paths = QListWidget()
        # 为文件列表添加拖拽支持
        self.list_paths.setAcceptDrops(True)
        self.list_paths.dragEnterEvent = self._drag_enter_event
        self.list_paths.dropEvent = self._list_drop_event
        hl.addWidget(self.list_paths, 3)
        
        vbtn = QVBoxLayout()
        self.btn_add_files = QPushButton(self.lang_pack["btn_add_files"])
        self.btn_add_files.clicked.connect(self.add_files)
        self.btn_add_folders = QPushButton(self.lang_pack["btn_add_folders"])
        self.btn_add_folders.clicked.connect(self.add_folders)
        self.btn_remove = QPushButton(self.lang_pack["btn_remove"])
        self.btn_remove.clicked.connect(self.remove_selected)
        self.btn_clear = QPushButton(self.lang_pack["btn_clear"])
        self.btn_clear.clicked.connect(lambda: self.list_paths.clear())
        
        vbtn.addWidget(self.btn_add_files)
        vbtn.addWidget(self.btn_add_folders)
        vbtn.addWidget(self.btn_remove)
        vbtn.addWidget(self.btn_clear)
        vbtn.addStretch(1)
        hl.addLayout(vbtn, 1)
        main_layout.addLayout(hl)
        
        # 选项区域 - 使用QGridLayout来更好地组织控件
        opt_widget = QWidget()
        opt_widget.setStyleSheet("border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9;")
        opt_layout = QGridLayout(opt_widget)
        opt_layout.setContentsMargins(15, 15, 15, 15)
        opt_layout.setSpacing(15)  # 增加间距，提高可读性
        
        # 第一行：压缩级别和算法
        row = 0
        self.lbl_compress_level = QLabel(self.lang_pack["compress_level"])
        opt_layout.addWidget(self.lbl_compress_level, row, 0, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        
        self.combo_level = QComboBox()
        self.combo_level.addItems([str(i) for i in range(1, 10)])
        self.combo_level.setFixedWidth(80)
        opt_layout.addWidget(self.combo_level, row, 1, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        
        self.lbl_compress_algorithm = QLabel(self.lang_pack["lbl_algorithm"])
        opt_layout.addWidget(self.lbl_compress_algorithm, row, 2, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        self.combo_algorithm = QComboBox()
        self.combo_algorithm.addItems(["zlib", "lzma", "brotli", "zstandard"])
        self.combo_algorithm.setFixedWidth(100)
        opt_layout.addWidget(self.combo_algorithm, row, 3, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        
        # 第五行：压缩格式选择
        row += 1
        self.lbl_compress_format = QLabel(self.lang_pack["lbl_compression_format"])
        opt_layout.addWidget(self.lbl_compress_format, row, 0, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        
        self.combo_format = QComboBox()
        self.combo_format.addItems(["stz", "zip", "7z", "tar", "tar.gz", "tar.bz2", "tar.xz"])
        self.combo_format.setFixedWidth(100)
        opt_layout.addWidget(self.combo_format, row, 1, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        
        self.chk_batch_compress = QCheckBox(self.lang_pack["chk_batch_compress"])
        self.chk_batch_compress.setToolTip(self.lang_pack["tooltip_batch_compress"])
        opt_layout.addWidget(self.chk_batch_compress, row, 2, 1, 2, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)

        # 第二行：加密选项
        row += 1
        self.chk_encrypt = QCheckBox(self.lang_pack["check_password"])
        opt_layout.addWidget(self.chk_encrypt, row, 0, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        
        self.lbl_password = QLabel(self.lang_pack["edit_password"])
        opt_layout.addWidget(self.lbl_password, row, 2, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        
        self.edit_password = QLineEdit()
        self.edit_password.setEchoMode(QLineEdit.Password)
        self.edit_password.setFixedWidth(150)
        opt_layout.addWidget(self.edit_password, row, 3, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)

        # 第三行：分卷压缩选项
        row += 1
        self.lbl_split_size = QLabel(self.lang_pack["split_size"])
        opt_layout.addWidget(self.lbl_split_size, row, 0, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        
        # 分卷大小设置，添加单位选择
        split_layout = QHBoxLayout()
        split_layout.setSpacing(5)
        split_layout.setContentsMargins(0, 0, 0, 0)
        
        self.spin_split = QSpinBox()
        self.spin_split.setRange(0, 10240)
        self.spin_split.setValue(0)
        self.spin_split.setFixedWidth(80)
        split_layout.addWidget(self.spin_split)
        
        self.combo_split_unit = QComboBox()
        self.combo_split_unit.addItems(["KB", "MB", "GB"])
        self.combo_split_unit.setCurrentIndex(1)  # 默认MB
        self.combo_split_unit.setFixedWidth(60)
        split_layout.addWidget(self.combo_split_unit)
        split_layout.setAlignment(QtCore.Qt.AlignLeft)
        
        opt_layout.addLayout(split_layout, row, 1, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        
        self.chk_auto_split = QCheckBox(self.lang_pack["chk_auto_split"])
        self.chk_auto_split.clicked.connect(self.toggle_auto_split)
        opt_layout.addWidget(self.chk_auto_split, row, 2, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        
        self.btn_choose_device = QPushButton(self.lang_pack["btn_choose_device"])
        self.btn_choose_device.clicked.connect(self.choose_device)
        self.btn_choose_device.setEnabled(False)
        self.btn_choose_device.setFixedWidth(80)
        opt_layout.addWidget(self.btn_choose_device, row, 3, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        
        # 第四行：其他选项
        row += 1
        self.chk_smart_compress = QCheckBox(self.lang_pack["chk_smart_compress"])
        self.chk_smart_compress.setToolTip(self.lang_pack["tooltip_smart_compress"])
        opt_layout.addWidget(self.chk_smart_compress, row, 0, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)

        self.chk_only_new = QCheckBox(self.lang_pack["only_new"])
        opt_layout.addWidget(self.chk_only_new, row, 1, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        
        self.chk_delete_source = QCheckBox(self.lang_pack["delete_source"])
        opt_layout.addWidget(self.chk_delete_source, row, 2, 1, 1, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)

        main_layout.addWidget(opt_widget)

        # 输出路径与控制
        out_layout = QHBoxLayout()
        self.lbl_output_file = QLabel(self.lang_pack["output_file"])
        out_layout.addWidget(self.lbl_output_file)
        
        self.edit_output = QLineEdit()
        # 路径输入框支持拖拽
        self.edit_output.setAcceptDrops(True)
        self.edit_output.dragEnterEvent = self._drag_enter_event
        self.edit_output.dropEvent = self._drop_event
        out_layout.addWidget(self.edit_output, 1)
        
        self.btn_browse_compress = QPushButton(self.lang_pack["btn_browse"])
        self.btn_browse_compress.clicked.connect(self.choose_output_path)
        out_layout.addWidget(self.btn_browse_compress)
        
        self.btn_compress_start = QPushButton(self.lang_pack["btn_compress_start"])
        self.btn_compress_start.clicked.connect(self.start_compression)
        out_layout.addWidget(self.btn_compress_start)
        
        self.btn_compress_pause = QPushButton(self.lang_pack["btn_pause"])
        self.btn_compress_pause.clicked.connect(self.toggle_pause)
        self.btn_compress_pause.setEnabled(False)
        out_layout.addWidget(self.btn_compress_pause)
        
        self.btn_compress_cancel = QPushButton(self.lang_pack["btn_cancel"])
        self.btn_compress_cancel.clicked.connect(self.cancel_operation)
        self.btn_compress_cancel.setEnabled(False)
        out_layout.addWidget(self.btn_compress_cancel)
        
        main_layout.addLayout(out_layout)

        # 进度与日志
        self.pb_compress = QProgressBar()
        self.pb_compress.setValue(0)
        main_layout.addWidget(self.pb_compress)
        
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        main_layout.addWidget(self.txt_log, 2)

    def load_config(self):
        """加载配置"""
        # 设置压缩级别
        self.combo_level.setCurrentText(str(self.config.get("compression_level", 6)))
        
        # 设置压缩算法
        self.combo_algorithm.setCurrentText(self.config.get("compression_algorithm", "zlib"))

    def _select_files(self, title, file_filter="所有文件 (*.*)", select_multiple=True):
        """选择文件的通用方法
        
        参数:
            title: 对话框标题
            file_filter: 文件过滤器
            select_multiple: 是否允许选择多个文件
            
        返回:
            选中的文件路径列表
        """
        if select_multiple:
            files, _ = QFileDialog.getOpenFileNames(
                self, 
                self.lang_pack.get(title, title), 
                "", 
                file_filter
            )
        else:
            file_path, _ = QFileDialog.getOpenFileName(
                self, 
                self.lang_pack.get(title, title), 
                "", 
                file_filter
            )
            files = [file_path] if file_path else []
        
        return files

    def _select_file(self, title, file_filter="所有文件 (*.*)"):
        """选择单个文件
        
        参数:
            title: 对话框标题
            file_filter: 文件过滤器
            
        返回:
            选中的文件路径
        """
        return self._select_files(title, file_filter, select_multiple=False)[0] if self._select_files(title, file_filter, select_multiple=False) else None

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
            if hasattr(self, 'edit_output') and self.sender() == self.edit_output:
                self.edit_output.setText(path)
            elif hasattr(self, 'edit_compress_file') and self.sender() == self.edit_compress_file:
                self.edit_compress_file.setText(path)
            elif hasattr(self, 'edit_decompress_dir') and self.sender() == self.edit_decompress_dir:
                self.edit_decompress_dir.setText(path)
            elif hasattr(self, 'edit_modify_archive') and self.sender() == self.edit_modify_archive:
                self.edit_modify_archive.setText(path)
            event.acceptProposedAction()

    def _list_drop_event(self, event):
        """处理拖拽释放事件（针对QListWidget）"""
        urls = event.mimeData().urls()
        if urls:
            paths = [url.toLocalFile() for url in urls]
            for path in paths:
                if os.path.isfile(path) or os.path.isdir(path):
                    self.list_paths.addItem(path)
            event.acceptProposedAction()

    def add_files(self):
        """添加文件"""
        files = self._select_files("select_files", "所有文件 (*.*)", True)
        for file in files:
            if file:
                self.list_paths.addItem(file)

    def add_folders(self):
        """添加文件夹"""
        directory = self._select_directory("select_folder")
        if directory:
            self.list_paths.addItem(directory)

    def remove_selected(self):
        """移除选中项"""
        for item in self.list_paths.selectedItems():
            self.list_paths.takeItem(self.list_paths.row(item))

    def choose_output_path(self):
        """选择输出路径"""
        # 根据选择的格式动态设置文件过滤器
        current_format = self.combo_format.currentText()
        filters = {
            "stz": "STZ压缩文件 (*.stz)",
            "zip": "ZIP压缩文件 (*.zip)",
            "7z": "7Z压缩文件 (*.7z)",
            "tar": "TAR文件 (*.tar)",
            "tar.gz": "GZIP压缩文件 (*.tar.gz)",
            "tar.bz2": "BZIP2压缩文件 (*.tar.bz2)",
            "tar.xz": "XZ压缩文件 (*.tar.xz)"
        }
        
        filter_text = filters.get(current_format, "所有文件 (*.*)")
        title = self.lang_pack.get("save_file", "保存{current_format.upper()}文件").format(current_format=current_format)
        
        if self.chk_batch_compress.isChecked():
            # 批量压缩时选择输出目录
            path = self._select_directory("select_output_dir")
            if path:
                self.edit_output.setText(path)
        else:
            # 单个压缩文件时选择文件路径
            path = self._save_file(title, filter_text)
            if path:
                # 确保文件扩展名正确
                expected_ext = {
                    "stz": ".stz",
                    "zip": ".zip",
                    "7z": ".7z",
                    "tar": ".tar",
                    "tar.gz": ".tar.gz",
                    "tar.bz2": ".tar.bz2",
                    "tar.xz": ".tar.xz"
                }[current_format]
                
                if not path.endswith(expected_ext):
                    path += expected_ext
                self.edit_output.setText(path)

    def start_compression(self):
        """开始压缩"""
        # 验证输入
        paths = [self.list_paths.item(i).text() for i in range(self.list_paths.count())]
        if not paths:
            self.log_signal.emit("请先添加文件或文件夹", "warning")
            return
            
        output_path = self.edit_output.text()
        if not output_path:
            self.log_signal.emit("请选择输出路径", "warning")
            return
            
        # 设置压缩参数
        params = {
            "compression_level": int(self.combo_level.currentText()),
            "compression_algorithm": self.combo_algorithm.currentText(),
            "password": self.edit_password.text() if self.chk_encrypt.isChecked() else None,
            "smart_compress": self.chk_smart_compress.isChecked(),
            "only_new": self.chk_only_new.isChecked(),
            "delete_source": self.chk_delete_source.isChecked()
        }
        
        # 分卷压缩设置
        if self.chk_auto_split.isChecked():
            params["auto_split"] = True
            params["target_device"] = self.target_device if hasattr(self, 'target_device') else None
        else:
            split_size = self.spin_split.value()
            if split_size > 0:
                unit = self.combo_split_unit.currentText()
                if unit == "KB":
                    params["split_size"] = split_size * 1024
                elif unit == "MB":
                    params["split_size"] = split_size * 1024 * 1024
                elif unit == "GB":
                    params["split_size"] = split_size * 1024 * 1024 * 1024
        
        # 更新UI状态
        self.btn_compress_start.setEnabled(False)
        self.btn_compress_pause.setEnabled(True)
        self.btn_compress_cancel.setEnabled(True)
        
        # 开始压缩线程
        self.is_paused = False
        self.is_cancelled = False
        
        current_format = self.combo_format.currentText()
        
        if self.chk_batch_compress.isChecked():
            # 批量压缩：为每个文件创建单独的压缩包
            if not os.path.isdir(output_path):
                self.log_signal.emit("批量压缩时输出路径必须是目录", "error")
                return
                
            self.compressor.batch_compress(paths, output_path, current_format, params)
        else:
            # 单个压缩文件
            self.compressor.compress_to_format(paths, output_path, current_format, params)

    def toggle_pause(self):
        """切换暂停状态"""
        pass  # 实现暂停逻辑

    def cancel_operation(self):
        """取消操作"""
        pass  # 实现取消逻辑

    def toggle_auto_split(self):
        """切换自动分卷状态"""
        self.btn_choose_device.setEnabled(self.chk_auto_split.isChecked())

    def choose_device(self):
        """选择设备"""
        device_path = self._select_directory("select_target_device")
        if device_path:
            self.target_device = device_path

    def _progress_emitter(self, progress, message, log_level="info"):
        """进度发射器"""
        self.progress_signal.emit(progress, message)
        self.log_signal.emit(message, log_level)
        
    def change_language(self, language):
        """更改语言"""
        self.language = language
        self.lang_pack = LANGUAGE_PACKS.get(language, LANGUAGE_PACKS["zh"])
        
        # 更新UI文本
        self.btn_add_files.setText(self.lang_pack["btn_add_files"])
        self.btn_add_folders.setText(self.lang_pack["btn_add_folders"])
        self.btn_remove.setText(self.lang_pack["btn_remove"])
        self.btn_clear.setText(self.lang_pack["btn_clear"])
        self.chk_encrypt.setText(self.lang_pack["check_password"])
        self.lbl_password.setText(self.lang_pack["edit_password"])
        self.lbl_compress_level.setText(self.lang_pack["compress_level"])
        self.lbl_compress_algorithm.setText(self.lang_pack["lbl_algorithm"])
        self.lbl_compress_format.setText(self.lang_pack["lbl_compression_format"])
        self.chk_batch_compress.setText(self.lang_pack["chk_batch_compress"])
        self.chk_batch_compress.setToolTip(self.lang_pack["tooltip_batch_compress"])
        self.chk_auto_split.setText(self.lang_pack["chk_auto_split"])
        self.btn_choose_device.setText(self.lang_pack["btn_choose_device"])
        self.chk_smart_compress.setText(self.lang_pack["chk_smart_compress"])
        self.chk_smart_compress.setToolTip(self.lang_pack["tooltip_smart_compress"])
        self.btn_compress_pause.setText(self.lang_pack["btn_pause"])
        self.btn_compress_cancel.setText(self.lang_pack["btn_cancel"])
        self.lbl_split_size.setText(self.lang_pack["split_size"])
        self.chk_only_new.setText(self.lang_pack["only_new"])
        self.chk_delete_source.setText(self.lang_pack["delete_source"])
        self.lbl_output_file.setText(self.lang_pack["output_file"])
        self.btn_browse_compress.setText(self.lang_pack["btn_browse"])
        self.btn_compress_start.setText(self.lang_pack["btn_compress_start"])
