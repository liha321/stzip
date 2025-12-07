"""
gui_decompress.py - 解压页面功能模块
"""
import os
from PySide6 import QtCore, QtWidgets, QtGui
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QTextEdit, QProgressBar, QLabel, QLineEdit, 
    QFileDialog
)

from core_func import CustomCompressor
from gui_utils import LANGUAGE_PACKS

class DecompressPage(QWidget):
    """解压功能页面"""
    progress_signal = QtCore.Signal(int, str)           # progress, message
    log_signal = QtCore.Signal(str, str)               # log, level
    decompress_done = QtCore.Signal(object)            # (result, logs)

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
        """设置解压页面UI"""
        main_layout = QVBoxLayout(self)

        # 解压文件选择
        df_layout = QHBoxLayout()
        self.lbl_compress_file = QLabel("选择压缩包 (.stz):")
        df_layout.addWidget(self.lbl_compress_file)
        
        self.edit_compress_file = QLineEdit()
        # 压缩包选择输入框支持拖拽
        self.edit_compress_file.setAcceptDrops(True)
        self.edit_compress_file.dragEnterEvent = self._drag_enter_event
        self.edit_compress_file.dropEvent = self._drop_event
        df_layout.addWidget(self.edit_compress_file, 1)
        
        self.btn_browse_decompress = QPushButton(self.lang_pack["btn_browse"])
        self.btn_browse_decompress.clicked.connect(self.choose_compress_file)
        df_layout.addWidget(self.btn_browse_decompress)
        
        main_layout.addLayout(df_layout)

        # 解压目录选择
        dd_layout = QHBoxLayout()
        self.lbl_decompress_dir = QLabel("解压目录:")
        dd_layout.addWidget(self.lbl_decompress_dir)
        
        self.edit_decompress_dir = QLineEdit()
        # 解压路径输入框支持拖拽
        self.edit_decompress_dir.setAcceptDrops(True)
        self.edit_decompress_dir.dragEnterEvent = self._drag_enter_event
        self.edit_decompress_dir.dropEvent = self._drop_event
        dd_layout.addWidget(self.edit_decompress_dir, 1)
        
        self.btn_choose_decompress_dir = QPushButton(self.lang_pack["btn_browse"])
        self.btn_choose_decompress_dir.clicked.connect(self.choose_decompress_dir)
        dd_layout.addWidget(self.btn_choose_decompress_dir)
        
        self.btn_decompress_start = QPushButton(self.lang_pack["btn_decompress_start"])
        self.btn_decompress_start.clicked.connect(self.start_decompression)
        dd_layout.addWidget(self.btn_decompress_start)
        
        self.btn_preview_content = QPushButton(self.lang_pack["btn_preview_content"])
        self.btn_preview_content.clicked.connect(self.preview_archive_content)
        dd_layout.addWidget(self.btn_preview_content)
        
        self.btn_decompress_pause = QPushButton("暂停")
        self.btn_decompress_pause.clicked.connect(self.toggle_pause)
        self.btn_decompress_pause.setEnabled(False)
        dd_layout.addWidget(self.btn_decompress_pause)
        
        self.btn_decompress_cancel = QPushButton("取消")
        self.btn_decompress_cancel.clicked.connect(self.cancel_operation)
        self.btn_decompress_cancel.setEnabled(False)
        dd_layout.addWidget(self.btn_decompress_cancel)
        
        main_layout.addLayout(dd_layout)

        # 进度与日志
        self.pb_decompress = QProgressBar()
        main_layout.addWidget(self.pb_decompress)
        
        self.txt_log_decompress = QTextEdit()
        self.txt_log_decompress.setReadOnly(True)
        main_layout.addWidget(self.txt_log_decompress, 2)

        # 转换 & 批量操作按钮
        conv_layout = QHBoxLayout()
        self.btn_stz_to_zip = QPushButton("STZ -> ZIP")
        self.btn_stz_to_zip.clicked.connect(self.stz_to_zip)
        
        self.btn_zip_to_stz = QPushButton("ZIP -> STZ")
        self.btn_zip_to_stz.clicked.connect(self.zip_to_stz)
        
        self.btn_batch_decompress = QPushButton("批量解压多个STZ")
        self.btn_batch_decompress.clicked.connect(self.batch_decompress)
        
        # 新增：校验和修复按钮
        self.btn_verify_archive = QPushButton("验证压缩包")
        self.btn_verify_archive.clicked.connect(self.verify_archive)
        
        self.btn_repair_archive = QPushButton("修复压缩包")
        self.btn_repair_archive.clicked.connect(self.repair_archive)
        
        self.btn_calculate_checksum = QPushButton("计算校验值")
        self.btn_calculate_checksum.clicked.connect(self.calculate_checksum)
        
        conv_layout.addWidget(self.btn_stz_to_zip)
        conv_layout.addWidget(self.btn_zip_to_stz)
        conv_layout.addWidget(self.btn_batch_decompress)
        conv_layout.addWidget(self.btn_verify_archive)
        conv_layout.addWidget(self.btn_repair_archive)
        conv_layout.addWidget(self.btn_calculate_checksum)
        conv_layout.addStretch(1)
        
        main_layout.addLayout(conv_layout)

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
            title, 
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
            title, 
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
            title, 
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
            title, 
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
            if self.sender() == self.edit_compress_file:
                self.edit_compress_file.setText(path)
            elif self.sender() == self.edit_decompress_dir:
                self.edit_decompress_dir.setText(path)
            event.acceptProposedAction()

    def choose_compress_file(self):
        """选择压缩文件"""
        file_path = self._select_file("选择STZ文件", "STZ压缩文件 (*.stz)")
        if file_path:
            self.edit_compress_file.setText(file_path)

    def choose_decompress_dir(self):
        """选择解压目录"""
        directory = self._select_directory("选择解压目录")
        if directory:
            self.edit_decompress_dir.setText(directory)

    def start_decompression(self):
        """开始解压"""
        # 验证输入
        compress_file = self.edit_compress_file.text()
        if not compress_file or not os.path.exists(compress_file):
            self.log_signal.emit(self.lang_pack["select_valid_archive"], "warning")
            return
            
        decompress_dir = self.edit_decompress_dir.text()
        if not decompress_dir:
            # 使用压缩文件所在目录
            decompress_dir = os.path.dirname(compress_file)
            self.edit_decompress_dir.setText(decompress_dir)
        
        # 确保解压目录存在
        if not os.path.exists(decompress_dir):
            try:
                os.makedirs(decompress_dir)
            except Exception as e:
                self.log_signal.emit(f"创建解压目录失败: {e}", "error")
                return
        
        # 设置解压参数
        params = {}
        
        # 更新UI状态
        self.btn_decompress_start.setEnabled(False)
        self.btn_decompress_pause.setEnabled(True)
        self.btn_decompress_cancel.setEnabled(True)
        
        # 开始解压线程
        self.is_paused = False
        self.is_cancelled = False
        
        self.compressor.decompress_path(compress_file, decompress_dir, params)

    def toggle_pause(self):
        """切换暂停状态"""
        pass  # 实现暂停逻辑

    def cancel_operation(self):
        """取消操作"""
        pass  # 实现取消逻辑

    def preview_archive_content(self):
        """预览压缩包内容"""
        compress_file = self.edit_compress_file.text()
        if not compress_file or not os.path.exists(compress_file):
            self.log_signal.emit("请选择有效的STZ压缩文件", "warning")
            return
        
        try:
            # 预览压缩包内容
            file_info_list = self.compressor.preview_archive(compress_file)
            
            if file_info_list:
                # 显示预览信息
                preview_text = "压缩包内容预览:\n"
                total_size = 0
                for file_info in file_info_list:
                    name = file_info.get("name", "未知")
                    size = file_info.get("size", 0)
                    total_size += size
                    preview_text += f"  - {name} ({self._human_readable_size(size)})\n"
                preview_text += f"\n总计: {len(file_info_list)} 个文件/文件夹, 总大小: {self._human_readable_size(total_size)}"
                
                self.log_signal.emit(preview_text, "info")
            else:
                self.log_signal.emit("压缩包为空或无法读取", "warning")
                
        except Exception as e:
            self.log_signal.emit(f"预览失败: {e}", "error")

    def stz_to_zip(self):
        """STZ转ZIP"""
        stz_file = self._select_file("选择STZ文件", "STZ压缩文件 (*.stz)")
        if stz_file:
            zip_file = self._save_file("保存ZIP文件", "ZIP压缩文件 (*.zip)")
            if zip_file:
                if not zip_file.endswith('.zip'):
                    zip_file += '.zip'
                
                try:
                    # 转换为ZIP
                    self.compressor.stz_to_zip(stz_file, zip_file)
                    self.log_signal.emit(f"转换成功: {stz_file} -> {zip_file}", "success")
                except Exception as e:
                    self.log_signal.emit(f"转换失败: {e}", "error")

    def zip_to_stz(self):
        """ZIP转STZ"""
        zip_file = self._select_file("选择ZIP文件", "ZIP压缩文件 (*.zip)")
        if zip_file:
            stz_file = self._save_file("保存STZ文件", "STZ压缩文件 (*.stz)")
            if stz_file:
                if not stz_file.endswith('.stz'):
                    stz_file += '.stz'
                
                try:
                    # 转换为STZ
                    self.compressor.zip_to_stz(zip_file, stz_file)
                    self.log_signal.emit(f"转换成功: {zip_file} -> {stz_file}", "success")
                except Exception as e:
                    self.log_signal.emit(f"转换失败: {e}", "error")

    def batch_decompress(self):
        """批量解压多个STZ文件"""
        stz_files = self._select_files("选择多个STZ文件", "STZ压缩文件 (*.stz)")
        if stz_files:
            output_dir = self._select_directory("选择批量解压目标目录")
            if output_dir:
                try:
                    for stz_file in stz_files:
                        # 为每个文件创建单独的解压目录
                        file_name = os.path.basename(stz_file)
                        file_name_without_ext = os.path.splitext(file_name)[0]
                        file_output_dir = os.path.join(output_dir, file_name_without_ext)
                        
                        # 确保目录存在
                        if not os.path.exists(file_output_dir):
                            os.makedirs(file_output_dir)
                        
                        # 解压文件
                        self.compressor.decompress_path(stz_file, file_output_dir, {})
                        self.log_signal.emit(f"解压完成: {file_name}", "success")
                    
                    self.log_signal.emit(f"批量解压完成，共处理 {len(stz_files)} 个文件", "success")
                    
                except Exception as e:
                    self.log_signal.emit(f"批量解压失败: {e}", "error")
    
    def handle_stz_file(self, file_path):
        """处理双击STZ文件的操作"""
        # 设置压缩文件路径
        self.edit_compress_file.setText(file_path)
        
        # 设置默认解压目录（文件所在目录）
        default_out_dir = os.path.dirname(file_path)
        self.edit_decompress_dir.setText(default_out_dir)
    
    def verify_archive(self):
        """验证压缩包完整性"""
        compress_file = self.edit_compress_file.text()
        if not compress_file or not os.path.exists(compress_file):
            self.log_signal.emit("请选择有效的压缩文件", "warning")
            return
        
        try:
            self.log_signal.emit(f"开始验证压缩包: {compress_file}", "info")
            success, is_valid, logs = self.compressor.verify_archive(compress_file)
            
            # 显示日志
            for log, level in logs:
                self.log_signal.emit(log, level)
            
            if success:
                if is_valid:
                    self.log_signal.emit("压缩包验证通过，文件完整", "success")
                else:
                    self.log_signal.emit("压缩包验证失败，文件可能已损坏", "error")
        except Exception as e:
            self.log_signal.emit(f"验证失败: {e}", "error")
    
    def repair_archive(self):
        """修复损坏的压缩包"""
        compress_file = self.edit_compress_file.text()
        if not compress_file or not os.path.exists(compress_file):
            self.log_signal.emit("请选择有效的压缩文件", "warning")
            return
        
        try:
            # 获取保存路径
            repaired_file = self._save_file("保存修复后的文件", "所有文件 (*.*)")
            if not repaired_file:
                return
            
            self.log_signal.emit(f"开始修复压缩包: {compress_file}", "info")
            success, repaired_path, logs = self.compressor.repair_archive(compress_file, repaired_file)
            
            # 显示日志
            for log, level in logs:
                self.log_signal.emit(log, level)
            
            if success and repaired_path:
                self.log_signal.emit(f"压缩包修复完成，已保存为: {repaired_path}", "success")
            else:
                self.log_signal.emit("压缩包修复失败", "error")
        except Exception as e:
            self.log_signal.emit(f"修复失败: {e}", "error")
    
    def calculate_checksum(self):
        """计算文件校验值"""
        compress_file = self.edit_compress_file.text()
        if not compress_file or not os.path.exists(compress_file):
            self.log_signal.emit("请选择有效的文件", "warning")
            return
        
        try:
            # 弹出选择算法对话框
            from PySide6.QtWidgets import QMessageBox
            
            algorithms = ["CRC32", "MD5", "SHA-1", "SHA-256"]
            algorithm, ok = QtWidgets.QInputDialog.getItem(
                self, 
                "选择校验算法", 
                "请选择校验算法:", 
                algorithms,
                1, 
                False
            )
            
            if not ok:
                return
            
            # 转换为小写
            algorithm_lower = algorithm.replace("-", "").lower()
            
            self.log_signal.emit(f"开始计算 {algorithm} 校验值: {compress_file}", "info")
            success, checksum_value, logs = self.compressor.calculate_checksum(compress_file, algorithm_lower)
            
            # 显示日志
            for log, level in logs:
                self.log_signal.emit(log, level)
            
            if success and checksum_value:
                # 显示校验值，支持复制
                msg_box = QMessageBox()
                msg_box.setWindowTitle(f"{algorithm} 校验值")
                msg_box.setText(f"文件: {os.path.basename(compress_file)}\n{algorithm}: {checksum_value}")
                msg_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Copy)
                
                result = msg_box.exec()
                if result == QMessageBox.Copy:
                    # 复制到剪贴板
                    clipboard = QtGui.QGuiApplication.clipboard()
                    clipboard.setText(checksum_value)
                    self.log_signal.emit(f"{algorithm} 校验值已复制到剪贴板", "info")
        except Exception as e:
            self.log_signal.emit(f"计算校验值失败: {e}", "error")

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
        self.lbl_compress_file.setText(self.lang_pack["compress_file"])
        self.btn_browse_decompress.setText(self.lang_pack["btn_browse"])
        self.lbl_decompress_dir.setText(self.lang_pack["decompress_dir"])
        self.btn_choose_decompress_dir.setText(self.lang_pack["btn_browse"])
        self.btn_decompress_start.setText(self.lang_pack["btn_decompress_start"])
        self.btn_preview_content.setText(self.lang_pack["btn_preview_content"])
        self.btn_decompress_pause.setText(self.lang_pack["btn_pause"])
        self.btn_decompress_cancel.setText(self.lang_pack["btn_cancel"])
        self.btn_stz_to_zip.setText(self.lang_pack["btn_stz_to_zip"])
        self.btn_zip_to_stz.setText(self.lang_pack["btn_zip_to_stz"])
        self.btn_batch_decompress.setText(self.lang_pack["btn_batch_decompress"])
        self.btn_verify_archive.setText(self.lang_pack["btn_verify_archive"])
        self.btn_repair_archive.setText(self.lang_pack["btn_repair_archive"])
        self.btn_calculate_checksum.setText(self.lang_pack["btn_calculate_checksum"])
