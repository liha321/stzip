#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core_func.py - STZ压缩工具核心功能模块
包含所有的数据处理、压缩解压、文件操作等核心功能
完全独立，不包含任何GUI组件
"""

import os
import json
import time
import zlib
import base64
import tempfile
import shutil
import zipfile
from datetime import datetime
from shutil import copy2
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# 导入工具函数
from utils import check_disk_space, check_file_permissions, check_file_in_use, format_bytes

# 配置文件路径
CONFIG_FILE = os.path.join(os.path.expanduser("~"), "stz_compressor_config.json")

class CustomCompressor:
    """STZ压缩器类，处理所有压缩解压逻辑"""
    
    def __init__(self, compression_level=6):
        """
        初始化压缩器
        
        参数:
            compression_level: 压缩级别 (1-9)
        """
        self.compression_level = compression_level
        self.logs = []
        self.salt = b'stz_compression_salt_'
        self.is_cancelled = False  # 取消标记
        self.is_paused = False     # 暂停标记
        self.progress_callback = None  # 进度回调

    def _derive_key(self, password):
        """
        从密码生成加密密钥
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _encrypt_data(self, data, password):
        key = self._derive_key(password)
        fernet = Fernet(key)
        return fernet.encrypt(data)

    def _decrypt_data(self, data, password):
        try:
            key = self._derive_key(password)
            fernet = Fernet(key)
            return fernet.decrypt(data)
        except:
            raise ValueError("密码错误或数据已损坏")

    def _record_log(self, content, level="info"):
        log = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {content}"
        self.logs.append((log, level))
        return log

    def cancel_operation(self):
        self.is_cancelled = True

    def pause_operation(self):
        self.is_paused = not self.is_paused

    def compress(self, targets, output_path, password=None, split_size=None, delete_source=False, only_new=False):
        """
        压缩文件或文件夹，支持分卷、仅新增/修改、删除源文件等
        output_path: 不带 .stz 后缀的目标路径（GUI 使用 asksaveasfilename 时可能包含 .stz）
        split_size: 字节，如 None 则不分卷
        only_new: 若 True 且目标已存在则仅增量添加/替换（调用 modify_archive）
        返回 (output_full_path or None, logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        temp_files = []  # 跟踪临时文件，用于回滚
        files_created = []  # 跟踪创建的文件，用于回滚
        try:
            # 规范输出路径（去掉尾部 .stz 如果用户提供）
            if output_path.lower().endswith(".stz"):
                output_path = output_path[:-4]
            custom_suffix = ".stz"
            output_full_path = f"{output_path}{custom_suffix}"
            
            # 1. 检查输出路径的磁盘空间
            # 预估所需空间（假设压缩率为50%，至少保留100MB的缓冲区）
            estimated_size = 0
            for target in targets:
                if os.path.exists(target):
                    if os.path.isfile(target):
                        estimated_size += os.path.getsize(target)
                    else:
                        for root, _, files in os.walk(target):
                            for file in files:
                                estimated_size += os.path.getsize(os.path.join(root, file))
            # 考虑压缩率和缓冲区
            required_space = int(estimated_size * 1.2) + 100 * 1024 * 1024  # 20% 额外空间 + 100MB 缓冲区
            
            has_space, available, required = check_disk_space(output_full_path, required_space)
            if not has_space:
                log = self._record_log(f"磁盘空间不足：需要 {format_bytes(required)}，可用 {format_bytes(available)}", "error")
                logs.append((log, "error"))
                return None, logs
            
            # 2. 检查输出路径的权限
            if not check_file_permissions(output_path, write=True):
                log = self._record_log(f"权限不足：无法在 {output_path} 路径写入文件", "error")
                logs.append((log, "error"))
                return None, logs
            
            # 3. 检查输出文件是否已存在且被占用
            if os.path.exists(output_full_path):
                if check_file_in_use(output_full_path):
                    log = self._record_log(f"文件被占用：{output_full_path} 正在被其他程序使用", "error")
                    logs.append((log, "error"))
                    return None, logs
            
            # 4. 检查源文件的权限和占用情况
            for target in targets:
                if os.path.exists(target):
                    if not check_file_permissions(target):
                        log = self._record_log(f"权限不足：无法访问源文件/目录 {target}", "error")
                        logs.append((log, "error"))
                        return None, logs
                    if os.path.isfile(target) and check_file_in_use(target):
                        log = self._record_log(f"文件被占用：源文件 {target} 正在被其他程序使用", "error")
                        logs.append((log, "error"))
                        return None, logs

            # 如果 only_new 且目标存在，执行增量修改（只添加/替换已变更文件）
            if only_new and os.path.exists(output_full_path):
                existing_info, read_logs, is_encrypted = self.read_archive_info(output_full_path)
                logs.extend(read_logs)
                existing_map = {}
                if existing_info:
                    for fi in existing_info:
                        existing_map[fi["relative_path"]] = fi
                new_files = {}
                valid_targets = []
                for target in targets:
                    if os.path.exists(target):
                        valid_targets.append(os.path.abspath(target))
                for target in valid_targets:
                    if os.path.isfile(target):
                        rel = os.path.basename(target)
                        mtime = int(os.path.getmtime(target))
                        size = os.path.getsize(target)
                        old = existing_map.get(rel)
                        if not old or old.get("file_size") != size or int(old.get("modified_time",0)) != mtime:
                            new_files[target] = rel
                    else:
                        root_dir = os.path.dirname(target)
                        for root, _, files in os.walk(target):
                            for file in files:
                                file_path = os.path.join(root, file)
                                relative_path = os.path.relpath(file_path, start=root_dir)
                                mtime = int(os.path.getmtime(file_path))
                                size = os.path.getsize(file_path)
                                old = existing_map.get(relative_path)
                                if not old or old.get("file_size") != size or int(old.get("modified_time",0)) != mtime:
                                    new_files[file_path] = relative_path
                if not new_files:
                    log = self._record_log("没有检测到新增或修改的文件，增量操作跳过", "info")
                    logs.append((log, "info"))
                    return output_full_path, logs
                success, mod_logs = self.modify_archive(output_full_path, tempfile.mkdtemp(), new_files=new_files, delete_files=None, password=password)
                logs.extend(mod_logs)
                return (output_full_path, logs) if success else (None, logs)

            # 常规压缩：收集文件信息
            valid_targets = []
            for target in targets:
                if os.path.exists(target):
                    valid_targets.append(os.path.abspath(target))
                else:
                    log = self._record_log(f"警告：目标不存在，已跳过 → {target}", "warning")
                    logs.append((log, "warning"))
            if not valid_targets:
                log = self._record_log("错误：无有效待压缩目标，压缩终止", "error")
                logs.append((log, "error"))
                return None, logs

            file_info_list = []
            total_size = 0
            for target in valid_targets:
                if os.path.isfile(target):
                    size = os.path.getsize(target)
                    mtime = int(os.path.getmtime(target))
                    file_info_list.append({
                        "file_name": os.path.basename(target),
                        "relative_path": os.path.basename(target),
                        "file_size": size,
                        "modified_time": mtime
                    })
                    total_size += size
                else:
                    root_dir = os.path.dirname(target)
                    for root, _, files in os.walk(target):
                        for file in files:
                            file_path = os.path.join(root, file)
                            relative_path = os.path.relpath(file_path, start=root_dir)
                            size = os.path.getsize(file_path)
                            mtime = int(os.path.getmtime(file_path))
                            file_info_list.append({
                                "file_name": file,
                                "relative_path": relative_path.replace("\\", "/"),
                                "file_size": size,
                                "modified_time": mtime
                            })
                            total_size += size

            # 压缩每个文件并按顺序拼接
            compressor = zlib.compressobj(
                level=self.compression_level,
                method=zlib.DEFLATED,
                wbits=15,
                memLevel=8
            )

            compressed_data = b""
            processed_size = 0
            total_files = len(file_info_list)
            processed_files = 0

            for file_info in file_info_list:
                if self.is_cancelled:
                    log = self._record_log("压缩操作已被取消", "warning")
                    logs.append((log, "warning"))
                    return None, logs
                while self.is_paused:
                    time.sleep(0.1)

                # 查找文件路径
                file_path = None
                for target in valid_targets:
                    if os.path.isfile(target):
                        if file_info["relative_path"].replace("\\", "/") == os.path.basename(target):
                            file_path = target
                            break
                    else:
                        candidate = os.path.join(os.path.dirname(target), file_info["relative_path"])
                        if not os.path.exists(candidate):
                            # try with forward slashes
                            candidate = os.path.join(os.path.dirname(target), *file_info["relative_path"].split('/'))
                        if os.path.exists(candidate):
                            file_path = candidate
                            break

                if not file_path:
                    log = self._record_log(f"警告：未找到文件 → {file_info['relative_path']}", "warning")
                    logs.append((log, "warning"))
                    continue

                with open(file_path, "rb") as f:
                    file_content = f.read()
                    compressed_part = compressor.compress(file_content)
                    compressed_data += compressed_part
                    processed_size += file_info["file_size"]
                    processed_files += 1

                    if self.progress_callback:
                        progress = int(processed_size / total_size * 100) if total_size > 0 else 0
                        self.progress_callback(
                            progress, 
                            f"压缩中：{file_info['relative_path']} ({processed_files}/{total_files})"
                        )

                    log = self._record_log(f"已压缩 → {file_info['relative_path']}（{file_info['file_size']}字节）", "info")
                    logs.append((log, "info"))

            if self.is_cancelled:
                log = self._record_log("压缩操作已被取消", "warning")
                logs.append((log, "warning"))
                return None, logs

            compressed_data += compressor.flush()

            if password:
                compressed_data = self._encrypt_data(compressed_data, password)
                log = self._record_log("已使用密码加密数据", "info")
                logs.append((log, "info"))

            info_json = json.dumps(file_info_list, ensure_ascii=False)
            info_json = f'{{"encrypted": {str(bool(password)).lower()}, "files": {info_json}}}'
            info_bin = info_json.encode("utf-8")
            separator = b"###CUSTOM_COMPRESS_SEPARATOR###"
            
            # 写入单一 stz 文件
            with open(output_full_path, "wb") as f:
                f.write(info_bin)
                f.write(separator)
                f.write(compressed_data)

            log = self._record_log(f"压缩完成 → {output_full_path}", "success")
            logs.append((log, "success"))

            # 分卷处理（按字节切分，生成 .stz.001 ...）
            if split_size and os.path.getsize(output_full_path) > split_size:
                part_index = 1
                with open(output_full_path, "rb") as src:
                    data = src.read()
                total_len = len(data)
                offset = 0
                part_files = []
                while offset < total_len:
                    part_data = data[offset: offset + split_size]
                    part_name = f"{output_full_path}.{part_index:03d}"
                    with open(part_name, "wb") as pf:
                        pf.write(part_data)
                    part_files.append(part_name)
                    offset += split_size
                    part_index += 1
                # 删除原始单文件，保留分卷
                os.remove(output_full_path)
                log = self._record_log(f"已按 {split_size} 字节分卷，生成 {len(part_files)} 个分卷", "info")
                logs.append((log, "info"))

            # 可选：删除源文件/文件夹
            if delete_source:
                for target in valid_targets:
                    try:
                        if os.path.isfile(target):
                            os.remove(target)
                        else:
                            shutil.rmtree(target)
                    except Exception as e:
                        log = self._record_log(f"删除源文件失败：{target} -> {e}", "warning")
                        logs.append((log, "warning"))

            if self.progress_callback:
                self.progress_callback(100, "压缩完成")
                
            return output_full_path, logs

        except Exception as e:
            log = self._record_log(f"压缩失败：{str(e)}", "error")
            logs.append((log, "error"))
            return None, logs

    def decompress(self, compress_file, output_dir, password=None):
        """
        解压压缩包
        返回 (success(bool), logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        try:
            if not os.path.exists(compress_file):
                log = self._record_log(f"错误：压缩包不存在 → {compress_file}", "error")
                logs.append((log, "error"))
                return False, logs

            if not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)

            with open(compress_file, "rb") as f:
                all_data = f.read()

            separator = b"###CUSTOM_COMPRESS_SEPARATOR###"
            if separator not in all_data:
                log = self._record_log("错误：不支持的压缩包格式或损坏（未找到分隔符）", "error")
                logs.append((log, "error"))
                return False, logs

            info_bin, compressed_data = all_data.split(separator, 1)
            try:
                info = json.loads(info_bin.decode("utf-8"))
            except Exception as e:
                log = self._record_log(f"读取压缩包信息失败：{e}", "error")
                logs.append((log, "error"))
                return False, logs

            file_info_list = info.get("files", [])
            is_encrypted = info.get("encrypted", False)
            if is_encrypted:
                if not password:
                    log = self._record_log("错误：压缩包已加密，需要密码解密", "error")
                    logs.append((log, "error"))
                    return False, logs
                try:
                    compressed_data = self._decrypt_data(compressed_data, password)
                except ValueError as e:
                    log = self._record_log(str(e), "error")
                    logs.append((log, "error"))
                    return False, logs

            # 解压 zlib 数据，得到所有文件的原始拼接内容
            try:
                raw = zlib.decompress(compressed_data)
            except Exception as e:
                log = self._record_log(f"解压失败：{e}", "error")
                logs.append((log, "error"))
                return False, logs

            offset = 0
            for fi in file_info_list:
                if self.is_cancelled:
                    log = self._record_log("解压操作已被取消", "warning")
                    logs.append((log, "warning"))
                    return False, logs
                while self.is_paused:
                    time.sleep(0.1)

                size = fi.get("file_size", 0)
                rel = fi.get("relative_path", fi.get("file_name", ""))
                # 规范路径，创建父目录
                out_path = os.path.join(output_dir, *rel.split('/'))
                parent_dir = os.path.dirname(out_path)
                if parent_dir and not os.path.exists(parent_dir):
                    os.makedirs(parent_dir, exist_ok=True)
                # 写入切片
                slice_data = raw[offset: offset + size]
                with open(out_path, "wb") as of:
                    of.write(slice_data)
                offset += size
                log = self._record_log(f"已解压 → {rel}", "info")
                logs.append((log, "info"))
                if self.progress_callback:
                    # 简单进度：按文件数计算
                    idx = file_info_list.index(fi) + 1
                    self.progress_callback(int(idx / len(file_info_list) * 100), f"解压中：{rel} ({idx}/{len(file_info_list)})")

            log = self._record_log(f"解压完成 → {output_dir}", "success")
            logs.append((log, "success"))
            return True, logs

        except Exception as e:
            log = self._record_log(f"解压失败：{e}", "error")
            logs.append((log, "error"))
            return False, logs

    def read_archive_info(self, archive_path):
        """
        读取压缩包信息
        返回 (file_info_list, logs, is_encrypted)
        """
        logs = []
        try:
            if not os.path.exists(archive_path):
                log = self._record_log(f"错误：压缩包不存在 → {archive_path}", "error")
                logs.append((log, "error"))
                return None, logs, False
            with open(archive_path, "rb") as f:
                all_data = f.read()
            separator = b"###CUSTOM_COMPRESS_SEPARATOR###"
            if separator not in all_data:
                log = self._record_log("错误：不支持的压缩包格式或损坏（未找到分隔符）", "error")
                logs.append((log, "error"))
                return None, logs, False
            info_bin, _ = all_data.split(separator, 1)
            info = json.loads(info_bin.decode("utf-8"))
            file_info_list = info.get("files", [])
            is_encrypted = info.get("encrypted", False)
            # 兼容历史包：确保每项都有 modified_time
            for fi in file_info_list:
                if "modified_time" not in fi:
                    fi["modified_time"] = 0
                if "file_size" not in fi:
                    fi["file_size"] = 0
            log = self._record_log(f"读取压缩包信息 → {archive_path}", "info")
            logs.append((log, "info"))
            return file_info_list, logs, is_encrypted
        except Exception as e:
            log = self._record_log(f"读取压缩包信息失败：{e}", "error")
            logs.append((log, "error"))
            return None, logs, False

    def modify_archive(self, archive_path, temp_dir, new_files=None, delete_files=None, password=None):
        """
        修改压缩包（添加/删除文件）
        new_files: {src_abspath: relative_path_in_archive}
        delete_files: [relative_path, ...]
        返回 (success(bool), logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        try:
            if not os.path.exists(archive_path):
                log = self._record_log(f"错误：压缩包不存在 → {archive_path}", "error")
                logs.append((log, "error"))
                return False, logs

            # 解出当前包到临时目录
            ok, dl_logs = self.decompress(archive_path, temp_dir, password)
            logs.extend(dl_logs)
            if not ok:
                return False, logs

            # 删除文件
            if delete_files:
                for rf in delete_files:
                    target = os.path.join(temp_dir, *rf.split('/'))
                    try:
                        if os.path.exists(target):
                            os.remove(target)
                            # 尝试清理空目录
                            parent = os.path.dirname(target)
                            while parent and os.path.isdir(parent) and not os.listdir(parent):
                                os.rmdir(parent)
                                parent = os.path.dirname(parent)
                            log = self._record_log(f"已删除压缩包内文件：{rf}", "info")
                            logs.append((log, "info"))
                    except Exception as e:
                        log = self._record_log(f"删除压缩包内文件失败：{rf} -> {e}", "warning")
                        logs.append((log, "warning"))

            # 添加/替换文件
            if new_files:
                for src, rel in new_files.items():
                    dest = os.path.join(temp_dir, *rel.split('/'))
                    dest_dir = os.path.dirname(dest)
                    os.makedirs(dest_dir, exist_ok=True)
                    shutil.copy2(src, dest)
                    log = self._record_log(f"已添加/替换文件：{rel}", "info")
                    logs.append((log, "info"))

            # 重新打包（覆盖原压缩包）
            # 使用 compress 对整个临时目录压缩，输出到同一路径（不含 .stz）
            base_out = archive_path[:-4] if archive_path.lower().endswith(".stz") else archive_path
            result, c_logs = self.compress([temp_dir], base_out, password, split_size=None, delete_source=False, only_new=False)
            logs.extend(c_logs)
            if result:
                # compress 会生成 base_out.stz；把它移回 archive_path（覆盖）
                generated = result
                try:
                    shutil.move(generated, archive_path)
                except Exception:
                    # 如果已经写到同一路径则忽略
                    pass
                log = self._record_log(f"已保存压缩包修改 → {archive_path}", "success")
                logs.append((log, "success"))
                shutil.rmtree(temp_dir, ignore_errors=True)
                return True, logs
            else:
                log = self._record_log("重新打包失败，修改未保存", "error")
                logs.append((log, "error"))
                shutil.rmtree(temp_dir, ignore_errors=True)
                return False, logs

        except Exception as e:
            log = self._record_log(f"修改压缩包失败：{e}", "error")
            logs.append((log, "error"))
            return False, logs

    def stz_to_zip(self, stz_path, zip_path, password=None):
        """将 stz 压缩包转换为 zip 文件（解压 stz 到临时目录再压为 zip）"""
        logs = []
        try:
            if not os.path.exists(stz_path):
                log = self._record_log(f"错误：压缩包不存在 → {stz_path}", "error")
                logs.append((log, "error"))
                return False, logs
            temp_dir = tempfile.mkdtemp()
            success, dl_logs = self.decompress(stz_path, temp_dir, password)
            logs.extend(dl_logs)
            if not success:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return False, logs
            with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        fp = os.path.join(root, file)
                        arcname = os.path.relpath(fp, start=temp_dir)
                        zf.write(fp, arcname)
            shutil.rmtree(temp_dir, ignore_errors=True)
            log = self._record_log(f"已生成 zip → {zip_path}", "success")
            logs.append((log, "success"))
            return True, logs
        except Exception as e:
            log = self._record_log(f"stz->zip 失败：{e}", "error")
            logs.append((log, "error"))
            return False, logs

    def zip_to_stz(self, zip_path, stz_output_path, password=None):
        """将 zip 转换为 stz（先解压 zip 到临时目录再调用 compress）"""
        logs = []
        try:
            if not os.path.exists(zip_path):
                log = self._record_log(f"错误：zip 不存在 → {zip_path}", "error")
                logs.append((log, "error"))
                return None, logs
            temp_dir = tempfile.mkdtemp()
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(temp_dir)
            result, c_logs = self.compress([temp_dir], stz_output_path, password)
            logs.extend(c_logs)
            shutil.rmtree(temp_dir, ignore_errors=True)
            return result, logs
        except Exception as e:
            log = self._record_log(f"zip->stz 失败：{e}", "error")
            logs.append((log, "error"))
            return None, logs

    def batch_decompress(self, stz_list, target_dir, password=None):
        """批量解压多个 stz 到 target_dir，每个压缩包解压到独立子目录（basename）"""
        all_logs = []
        for stz in stz_list:
            if self.is_cancelled:
                all_logs.append((self._record_log("批量解压被取消", "warning"), "warning"))
                break
            name = os.path.splitext(os.path.basename(stz))[0]
            out = os.path.join(target_dir, name)
            success, logs = self.decompress(stz, out, password)
            all_logs.extend(logs)
        return True, all_logs

    def batch_compress(self, groups):
        """
        批量压缩多组。
        groups: 列表，每项为 dict {'targets': [...], 'output': '/path/out', 'password': None, 'split_size': None, 'delete_source': False, 'only_new': False}
        """
        all_logs = []
        for g in groups:
            if self.is_cancelled:
                all_logs.append((self._record_log("批量压缩被取消", "warning"), "warning"))
                break
            res, logs = self.compress(
                g.get('targets', []),
                g.get('output'),
                password=g.get('password', None),
                split_size=g.get('split_size', None),
                delete_source=g.get('delete_source', False),
                only_new=g.get('only_new', False)
            )
            all_logs.extend(logs)
        return True, all_logs


# 配置文件管理函数
def load_config():
    default_config = {
        "recent_compress_paths": [],
        "recent_decompress_paths": [],
        "recent_modify_paths": [],
        "default_compression_level": 6,
        "window_geometry": "900x700"
    }
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                # 合并默认项
                for k, v in default_config.items():
                    if k not in cfg:
                        cfg[k] = v
                return cfg
        return default_config
    except:
        return default_config


def save_config(config):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"保存配置失败：{e}")