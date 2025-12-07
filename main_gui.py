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
    QPushButton, QFileDialog, QListWidget, QTextEdit, QProgressBar,
    QLabel, QLineEdit, QTabWidget, QCheckBox, QComboBox, QTreeWidget,
    QTreeWidgetItem, QMessageBox, QSpinBox
)

from core_func import CustomCompressor, load_config, save_config

# 简化：日志级别颜色映射
_LOG_COLORS = {
    "info": "#000000",
    "warning": "#c07a00",
    "error": "#c00000",
    "success": "#008000"
}


class CompressionGUI(QMainWindow):
    progress_signal = QtCore.Signal(int, str)           # progress, message
    log_signal = QtCore.Signal(str, str)               # log, level
    preview_signal = QtCore.Signal(object, object)     # file_info_list, is_encrypted
    compress_done = QtCore.Signal(object)              # (result, logs)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("STZ压缩解压工具（PySide6）")
        self.resize(1000, 700)

        self.config = load_config()
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

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # --- 压缩页 ---
        self.page_compress = QWidget()
        cp_layout = QVBoxLayout(self.page_compress)

        # 文件列表
        hl = QHBoxLayout()
        self.list_paths = QListWidget()
        hl.addWidget(self.list_paths, 3)
        vbtn = QVBoxLayout()
        btn_add_files = QPushButton("添加文件")
        btn_add_files.clicked.connect(self.add_files)
        btn_add_folders = QPushButton("添加文件夹")
        btn_add_folders.clicked.connect(self.add_folders)
        btn_remove = QPushButton("移除选中")
        btn_remove.clicked.connect(self.remove_selected)
        btn_clear = QPushButton("清空")
        btn_clear.clicked.connect(lambda: self.list_paths.clear())
        vbtn.addWidget(btn_add_files)
        vbtn.addWidget(btn_add_folders)
        vbtn.addWidget(btn_remove)
        vbtn.addWidget(btn_clear)
        vbtn.addStretch(1)
        hl.addLayout(vbtn, 1)
        cp_layout.addLayout(hl)

        # 选项区域
        opt_layout = QHBoxLayout()
        opt_layout.addWidget(QLabel("压缩级别:"))
        self.combo_level = QComboBox()
        self.combo_level.addItems([str(i) for i in range(1, 10)])
        self.combo_level.setCurrentText(str(self.config.get("default_compression_level", 6)))
        opt_layout.addWidget(self.combo_level)

        self.chk_encrypt = QCheckBox("使用密码加密")
        opt_layout.addWidget(self.chk_encrypt)
        opt_layout.addWidget(QLabel("密码:"))
        self.edit_password = QLineEdit()
        self.edit_password.setEchoMode(QLineEdit.Password)
        opt_layout.addWidget(self.edit_password)

        opt_layout.addWidget(QLabel("分卷大小 (MB):"))
        self.spin_split = QSpinBox()
        self.spin_split.setRange(0, 10240)
        self.spin_split.setValue(0)
        opt_layout.addWidget(self.spin_split)

        self.chk_only_new = QCheckBox("仅新增/修改 (增量)")
        opt_layout.addWidget(self.chk_only_new)
        self.chk_delete_source = QCheckBox("压缩后删除源文件")
        opt_layout.addWidget(self.chk_delete_source)

        cp_layout.addLayout(opt_layout)

        # 输出路径与控制
        out_layout = QHBoxLayout()
        out_layout.addWidget(QLabel("输出文件 (.stz):"))
        self.edit_output = QLineEdit()
        out_layout.addWidget(self.edit_output, 1)
        btn_out = QPushButton("浏览...")
        btn_out.clicked.connect(self.choose_output_path)
        out_layout.addWidget(btn_out)
        btn_start = QPushButton("开始压缩")
        btn_start.clicked.connect(self.start_compression_thread)
        out_layout.addWidget(btn_start)
        cp_layout.addLayout(out_layout)

        # 进度与日志
        self.pb_compress = QProgressBar()
        self.pb_compress.setValue(0)
        cp_layout.addWidget(self.pb_compress)
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        cp_layout.addWidget(self.txt_log, 2)

        self.tabs.addTab(self.page_compress, "文件压缩")

        # --- 解压页 ---
        self.page_decompress = QWidget()
        dp_layout = QVBoxLayout(self.page_decompress)

        df_layout = QHBoxLayout()
        df_layout.addWidget(QLabel("选择压缩包 (.stz):"))
        self.edit_compress_file = QLineEdit()
        df_layout.addWidget(self.edit_compress_file, 1)
        btn_choose_compress = QPushButton("浏览...")
        btn_choose_compress.clicked.connect(self.choose_compress_file)
        df_layout.addWidget(btn_choose_compress)
        dp_layout.addLayout(df_layout)

        dd_layout = QHBoxLayout()
        dd_layout.addWidget(QLabel("解压目录:"))
        self.edit_decompress_dir = QLineEdit()
        dd_layout.addWidget(self.edit_decompress_dir, 1)
        btn_choose_dir = QPushButton("浏览...")
        btn_choose_dir.clicked.connect(self.choose_decompress_dir)
        dd_layout.addWidget(btn_choose_dir)
        btn_decompress = QPushButton("开始解压")
        btn_decompress.clicked.connect(self.start_decompression_thread)
        dd_layout.addWidget(btn_decompress)
        dp_layout.addLayout(dd_layout)

        self.pb_decompress = QProgressBar()
        dp_layout.addWidget(self.pb_decompress)
        self.txt_log_decompress = QTextEdit()
        self.txt_log_decompress.setReadOnly(True)
        dp_layout.addWidget(self.txt_log_decompress, 2)

        # 转换 & 批量操作按钮
        conv_layout = QHBoxLayout()
        btn_stz_to_zip = QPushButton("STZ -> ZIP")
        btn_stz_to_zip.clicked.connect(self.stz_to_zip)
        btn_zip_to_stz = QPushButton("ZIP -> STZ")
        btn_zip_to_stz.clicked.connect(self.zip_to_stz)
        btn_batch_decompress = QPushButton("批量解压多个STZ")
        btn_batch_decompress.clicked.connect(self.batch_decompress)
        conv_layout.addWidget(btn_stz_to_zip)
        conv_layout.addWidget(btn_zip_to_stz)
        conv_layout.addWidget(btn_batch_decompress)
        conv_layout.addStretch(1)
        dp_layout.addLayout(conv_layout)

        self.tabs.addTab(self.page_decompress, "文件解压")

        # --- 修改页 ---
        self.page_modify = QWidget()
        mp_layout = QVBoxLayout(self.page_modify)

        mf_layout = QHBoxLayout()
        mf_layout.addWidget(QLabel("选择压缩包 (.stz):"))
        self.edit_modify_archive = QLineEdit()
        mf_layout.addWidget(self.edit_modify_archive, 1)
        btn_choose_modify = QPushButton("浏览...")
        btn_choose_modify.clicked.connect(self.choose_modify_archive)
        mf_layout.addWidget(btn_choose_modify)
        btn_load = QPushButton("加载内容")
        btn_load.clicked.connect(self.load_archive_content)
        mf_layout.addWidget(btn_load)
        btn_preview = QPushButton("预览内容")
        btn_preview.clicked.connect(self.preview_archive_content)
        mf_layout.addWidget(btn_preview)
        mp_layout.addLayout(mf_layout)

        self.tree_archive = QListWidget()
        mp_layout.addWidget(self.tree_archive, 2)

        btns = QHBoxLayout()
        btn_extract = QPushButton("提取选中文件")
        btn_extract.clicked.connect(self.extract_selected_file)
        btn_delete = QPushButton("删除选中文件")
        btn_delete.clicked.connect(self.delete_selected_file)
        btn_addnew = QPushButton("添加新文件")
        btn_addnew.clicked.connect(self.add_new_file)
        btn_replace = QPushButton("替换选中文件")
        btn_replace.clicked.connect(self.replace_selected_file)
        btn_save = QPushButton("保存修改")
        btn_save.clicked.connect(self.start_modify_thread)
        btns.addWidget(btn_extract)
        btns.addWidget(btn_delete)
        btns.addWidget(btn_addnew)
        btns.addWidget(btn_replace)
        btns.addStretch(1)
        btns.addWidget(btn_save)
        mp_layout.addLayout(btns)

        self.pb_modify = QProgressBar()
        mp_layout.addWidget(self.pb_modify)
        self.txt_log_modify = QTextEdit()
        self.txt_log_modify.setReadOnly(True)
        mp_layout.addWidget(self.txt_log_modify, 2)

        self.tabs.addTab(self.page_modify, "修改压缩包")

        # 状态栏
        self.status = QLabel("就绪")
        main_layout.addWidget(self.status)

    def _connect_signals(self):
        self.progress_signal.connect(self._on_progress)
        self.log_signal.connect(self._on_log)
        self.preview_signal.connect(self._on_preview_ready)
        self.compress_done.connect(self._on_compress_done)

    # ---------- 信号槽 ----------
    def _progress_emitter(self, p, msg):
        self.progress_signal.emit(int(p), str(msg))

    @QtCore.Slot(int, str)
    def _on_progress(self, p, msg):
        self.status.setText(msg)
        idx = self.tabs.currentIndex()
        if idx == 0:
            self.pb_compress.setValue(p)
        elif idx == 1:
            self.pb_decompress.setValue(p)
        elif idx == 2:
            self.pb_modify.setValue(p)

    @QtCore.Slot(str, str)
    def _on_log(self, log, level):
        color = _LOG_COLORS.get(level, "#000000")
        w = self.txt_log if self.tabs.currentIndex() == 0 else (
            self.txt_log_decompress if self.tabs.currentIndex() == 1 else self.txt_log_modify
        )
        w.setTextColor(QtGui.QColor(color))
        w.append(log)
        w.setTextColor(QtGui.QColor("#000000"))

    @QtCore.Slot(object, object)
    def _on_preview_ready(self, file_info_list, is_encrypted):
        # 弹窗展示树状结构（简单）
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("预览")
        dlg.resize(700, 500)
        layout = QVBoxLayout(dlg)
        tree = QTreeWidget()
        tree.setHeaderLabels(["文件/目录", "大小", "修改时间"])
        layout.addWidget(tree)
        # 构建树
        nodes = {}
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
                parent_item = nodes[path_acc]
        dlg.exec()

    @QtCore.Slot(object)
    def _on_compress_done(self, result_logs):
        # result_logs is (result, logs)
        result, logs = result_logs
        for log, level in logs:
            self.log_signal.emit(log, level)
        if result:
            QMessageBox.information(self, "成功", "压缩完成")
        else:
            QMessageBox.critical(self, "失败", "压缩失败，请查看日志")

    # ---------- UI 操作 ----------
    def add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "选择文件")
        for f in files:
            if f and not any(self.list_paths.item(i).text() == f for i in range(self.list_paths.count())):
                self.list_paths.addItem(f)

    def add_folders(self):
        folder = QFileDialog.getExistingDirectory(self, "选择文件夹")
        if folder:
            if not any(self.list_paths.item(i).text() == folder for i in range(self.list_paths.count())):
                self.list_paths.addItem(folder)

    def remove_selected(self):
        for it in self.list_paths.selectedItems():
            self.list_paths.takeItem(self.list_paths.row(it))

    def choose_output_path(self):
        fn, _ = QFileDialog.getSaveFileName(self, "保存压缩文件", filter="STZ (*.stz)")
        if fn:
            if fn.lower().endswith(".stz"):
                fn = fn[:-4]
            self.edit_output.setText(fn)

    def choose_compress_file(self):
        fn, _ = QFileDialog.getOpenFileName(self, "选择压缩包", filter="STZ (*.stz)")
        if fn:
            self.edit_compress_file.setText(fn)

    def choose_decompress_dir(self):
        folder = QFileDialog.getExistingDirectory(self, "选择解压目录")
        if folder:
            self.edit_decompress_dir.setText(folder)

    def choose_modify_archive(self):
        fn, _ = QFileDialog.getOpenFileName(self, "选择压缩包", filter="STZ (*.stz)")
        if fn:
            self.edit_modify_archive.setText(fn)

    def load_archive_content(self):
        archive = self.edit_modify_archive.text().strip()
        if not archive:
            QMessageBox.warning(self, "警告", "请选择压缩包")
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
        archive = self.edit_modify_archive.text().strip()
        if not archive:
            QMessageBox.warning(self, "警告", "请选择压缩包")
            return
        # 读取归档信息并预览
        file_info_list, logs, is_encrypted = self.compressor.read_archive_info(archive)
        # 发射预览信号
        self.preview_signal.emit(file_info_list, is_encrypted)
        # 输出日志
        for log, level in logs:
            self.log_signal.emit(log, level)

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
        files, _ = QFileDialog.getOpenFileNames(self, "选择要添加的文件")
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
        target_dir = QFileDialog.getExistingDirectory(self, "选择提取目录")
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
            QMessageBox.critical(self, "失败", "提取文件失败，请查看日志")

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
        src, _ = QFileDialog.getOpenFileName(self, "选择用于替换的本地文件")
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
        self.status.setText("正在保存修改...")
        self.pb_modify.setValue(0)
        self.txt_log_modify.clear()

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
                    self.status.setText("修改已保存")
                else:
                    self.log_signal.emit("修改失败，请查看日志", "error")
                    self.status.setText("修改失败")
            finally:
                try:
                    shutil.rmtree(tempdir, ignore_errors=True)
                except:
                    pass

        threading.Thread(target=worker, daemon=True).start()

    # ---------- 压缩/解压线程 ----------
    def start_compression_thread(self):
        if self.tabs.currentIndex() != 0:
            self.tabs.setCurrentIndex(0)
        if self.list_paths.count() == 0:
            QMessageBox.warning(self, "警告", "请添加待压缩的文件或文件夹")
            return
        out = self.edit_output.text().strip()
        if not out:
            QMessageBox.warning(self, "警告", "请选择输出路径")
            return
        password = self.edit_password.text() if self.chk_encrypt.isChecked() else None
        compression_level = int(self.combo_level.currentText())
        self.compressor.compression_level = compression_level
        split_mb = int(self.spin_split.value())
        split_size = split_mb * 1024 * 1024 if split_mb > 0 else None
        only_new = self.chk_only_new.isChecked()
        delete_source = self.chk_delete_source.isChecked()

        paths = [self.list_paths.item(i).text() for i in range(self.list_paths.count())]

        # 清日志与进度
        self.txt_log.clear()
        self.pb_compress.setValue(0)
        self.status.setText("正在压缩...")

        def worker():
            result, logs = self.compressor.compress(paths, out, password, split_size=split_size, delete_source=delete_source, only_new=only_new)
            # 发射结果
            self.compress_done.emit((result, logs))

        threading.Thread(target=worker, daemon=True).start()

    def start_decompression_thread(self):
        fn = self.edit_compress_file.text().strip()
        outdir = self.edit_decompress_dir.text().strip()
        if not fn or not outdir:
            QMessageBox.warning(self, "警告", "请选择压缩包和目标目录")
            return
        pwd = None
        # 清日志
        self.txt_log_decompress.clear()
        self.pb_decompress.setValue(0)
        self.status.setText("正在解压...")

        def worker():
            ok, logs = self.compressor.decompress(fn, outdir, pwd)
            for log, level in logs:
                self.log_signal.emit(log, level)

        threading.Thread(target=worker, daemon=True).start()

    # zip<->stz 简单封装（使用 core_func 的方法）
    def stz_to_zip(self):
        stz, _ = QFileDialog.getOpenFileName(self, "选择 STZ 文件", filter="STZ (*.stz)")
        if not stz:
            return
        zip_out, _ = QFileDialog.getSaveFileName(self, "保存为 ZIP", filter="ZIP (*.zip)")
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
        zipf, _ = QFileDialog.getOpenFileName(self, "选择 ZIP 文件", filter="ZIP (*.zip)")
        if not zipf:
            return
        stz_out, _ = QFileDialog.getSaveFileName(self, "保存为 STZ", filter="STZ (*.stz)")
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
        files, _ = QFileDialog.getOpenFileNames(self, "选择多个 STZ 文件", filter="STZ (*.stz)")
        if not files:
            return
        target = QFileDialog.getExistingDirectory(self, "选择目标目录")
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
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

    def restore_config(self):
        # 恢复压缩级别
        try:
            self.combo_level.setCurrentText(str(self.config.get("default_compression_level", 6)))
        except:
            pass

    # 退出时保存配置
    def closeEvent(self, event):
        try:
            self.config["default_compression_level"] = int(self.combo_level.currentText())
            self.config["window_geometry"] = f"{self.width()}x{self.height()}"
            save_config(self.config)
        except:
            pass
        super().closeEvent(event)


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    win = CompressionGUI()
    win.show()
    sys.exit(app.exec())