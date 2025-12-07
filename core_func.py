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
import platform
import hashlib
import tarfile
import bz2
import lzma
from datetime import datetime
from shutil import copy2
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# 第三方库条件导入
try:
    import py7zr
    PY7ZR_AVAILABLE = True
except ImportError:
    PY7ZR_AVAILABLE = False
try:
    import rarfile
    RARFILE_AVAILABLE = True
except ImportError:
    RARFILE_AVAILABLE = False

# Windows平台特定导入
if platform.system() == "Windows":
    try:
        import winreg
        import ctypes
    except ImportError:
        winreg = None
        ctypes = None
else:
    winreg = None
    ctypes = None

# 导入工具函数
from utils import check_disk_space, check_file_permissions, check_file_in_use, format_bytes

# 配置文件路径
PORTABLE_MODE = False  # 默认非便携模式

# 默认配置
DEFAULT_CONFIG = {
    "recent_compress_paths": [],
    "recent_decompress_paths": [],
    "recent_modify_paths": [],
    "compression_level": 6,  # 压缩级别 (1-9)
    "compression_algorithm": "zlib",  # 默认压缩算法
    "window_geometry": "900x700",
    "theme": "system",  # light, dark, system
    "first_launch": True,  # 首次启动标记
    "language": "zh"  # zh, en
}


def is_admin():
    """
    检测当前用户是否具有管理员权限
    
    返回:
        bool: True if 具有管理员权限, False otherwise
    """
    if platform.system() != "Windows" or ctypes is None:
        return False
    
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def get_app_data_path():
    """
    获取用户AppData目录路径
    
    返回:
        str: 用户AppData目录路径
    """
    if platform.system() == "Windows":
        return os.environ.get("APPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Roaming"))
    else:
        return os.path.expanduser("~")


def get_config_path():
    """
    根据权限和模式确定配置文件路径
    
    返回:
        str: 配置文件路径
    """
    if PORTABLE_MODE:
        # 便携模式：配置文件存放在程序目录
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    
    if platform.system() == "Windows":
        if is_admin():
            # 管理员权限：可写入注册表和程序目录
            return os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        else:
            # 普通用户权限：配置存放在用户AppData目录
            app_data_path = get_app_data_path()
            app_dir = os.path.join(app_data_path, "STZCompressor")
            if not os.path.exists(app_dir):
                os.makedirs(app_dir)
            return os.path.join(app_dir, "config.json")
    else:
        # 非Windows系统：配置存放在用户目录
        return os.path.join(os.path.expanduser("~"), ".stz_compressor_config.json")


def get_log_path():
    """
    根据权限和模式确定日志文件路径
    
    返回:
        str: 日志文件路径
    """
    if PORTABLE_MODE:
        # 便携模式：日志文件存放在程序目录
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    
    if platform.system() == "Windows":
        if is_admin():
            # 管理员权限：日志存放在程序目录
            return os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
        else:
            # 普通用户权限：日志存放在用户AppData目录
            app_data_path = get_app_data_path()
            log_dir = os.path.join(app_data_path, "STZCompressor", "logs")
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            return log_dir
    else:
        # 非Windows系统：日志存放在用户目录
        log_dir = os.path.join(os.path.expanduser("~"), ".stz_compressor", "logs")
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        return log_dir


def get_registry_key():
    """
    获取注册表键路径
    
    返回:
        str: 注册表键路径
    """
    return r"SOFTWARE\STZCompressor"


def read_registry(key_name, default=None):
    """
    从Windows注册表读取值
    
    参数:
        key_name: 键名
        default: 默认值
    
    返回:
        读取的值或默认值
    """
    if platform.system() != "Windows" or winreg is None:
        return default
    
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, get_registry_key(), 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, key_name)
            return value
    except FileNotFoundError:
        return default
    except Exception:
        return default


def write_registry(key_name, value):
    """
    向Windows注册表写入值
    
    参数:
        key_name: 键名
        value: 值
    
    返回:
        bool: True if 写入成功, False otherwise
    """
    if platform.system() != "Windows" or winreg is None:
        return False
    
    try:
        # 尝试创建或打开注册表键
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, get_registry_key(), 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, str(value))
        winreg.CloseKey(key)
        return True
    except Exception:
        return False

# 自修复功能模块
def detect_core_components():
    """
    检测核心组件是否正常工作
    
    返回:
        dict: 包含各组件状态的字典
    """
    components = {
        "zlib": False,
        "bz2": False,
        "lzma": False,
        "cryptography": False,
        "json": False,
        "os": False,
        "shutil": False,
        "zipfile": False
    }
    
    try:
        import zlib
        components["zlib"] = True
    except ImportError:
        pass
    
    try:
        import bz2
        components["bz2"] = True
    except ImportError:
        pass
    
    try:
        import lzma
        components["lzma"] = True
    except ImportError:
        pass
    
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        components["cryptography"] = True
    except ImportError:
        pass
    
    try:
        import json
        components["json"] = True
    except ImportError:
        pass
    
    try:
        import os
        components["os"] = True
    except ImportError:
        pass
    
    try:
        import shutil
        components["shutil"] = True
    except ImportError:
        pass
    
    try:
        import zipfile
        components["zipfile"] = True
    except ImportError:
        pass
    
    return components

def repair_config_file():
    """
    修复配置文件
    
    返回:
        bool: True if 修复成功, False otherwise
    """
    try:
        # 尝试删除损坏的配置文件
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)
        
        # 重置注册表配置（仅Windows）
        if platform.system() == "Windows" and winreg is not None:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, get_registry_key())
            except FileNotFoundError:
                pass
        
        # 保存默认配置
        save_config(DEFAULT_CONFIG.copy())
        return True
    except Exception as e:
        print(f"修复配置文件失败: {e}")
        return False

def check_config_integrity(config):
    """
    检查配置完整性
    
    参数:
        config: 要检查的配置字典
    
    返回:
        bool: True if 配置完整, False otherwise
    """
    if not isinstance(config, dict):
        return False
    
    # 检查所有必要的配置项是否存在
    for key in DEFAULT_CONFIG:
        if key not in config:
            return False
    
    # 检查配置值的类型是否正确
    if not isinstance(config["recent_compress_paths"], list):
        return False
    if not isinstance(config["recent_decompress_paths"], list):
        return False
    if not isinstance(config["recent_modify_paths"], list):
        return False
    if not isinstance(config["default_compression_level"], int):
        return False
    if not isinstance(config["window_geometry"], str):
        return False
    if not isinstance(config["theme"], str):
        return False
    if not isinstance(config["first_launch"], bool):
        return False
    if not isinstance(config["language"], str):
        return False
    
    return True

def self_repair():
    """
    执行自修复功能
    
    返回:
        dict: 包含修复结果的字典
    """
    results = {
        "components": {},
        "config_repaired": False,
        "message": ""
    }
    
    # 1. 检测核心组件
    components = detect_core_components()
    results["components"] = components
    
    # 检查是否有核心组件缺失
    missing_components = [name for name, status in components.items() if not status]
    if missing_components:
        results["message"] = f"检测到缺失的核心组件: {', '.join(missing_components)}"
        # 这里可以添加尝试安装缺失组件的逻辑，但考虑到权限问题，建议提示用户手动安装
    else:
        results["message"] = "所有核心组件正常"
    
    # 2. 检查并修复配置文件
    try:
        config = load_config()
        if not check_config_integrity(config):
            results["config_repaired"] = repair_config_file()
            if results["config_repaired"]:
                results["message"] += "; 配置文件已修复"
            else:
                results["message"] += "; 配置文件修复失败"
        else:
            results["message"] += "; 配置文件完整"
    except Exception as e:
        results["config_repaired"] = repair_config_file()
        if results["config_repaired"]:
            results["message"] += f"; 配置文件已修复（原错误: {e}）"
        else:
            results["message"] += f"; 配置文件修复失败（原错误: {e}）"
    
    return results

# 确定最终的配置文件路径
CONFIG_FILE = get_config_path()

class CustomCompressor:
    """STZ压缩器类，处理所有压缩解压逻辑"""
    
    def __init__(self, compression_level=6, compression_algorithm='zlib'):
        """
        初始化压缩器
        
        参数:
            compression_level: 压缩级别 (1-9)
            compression_algorithm: 压缩算法 ('zlib', 'lzma', 'brotli', 'zstandard')
        """
        self.compression_level = compression_level
        self.compression_algorithm = compression_algorithm
        self.logs = []
        self.salt = b'stz_compression_salt_'
        self.is_cancelled = False  # 取消标记
        self.is_paused = False     # 暂停标记
        self.progress_callback = None  # 进度回调
        self.use_smart_compression = False  # 是否使用智能压缩
        
        # 初始化时检测核心组件
        self.check_components()
    
    def check_components(self):
        """
        检测压缩器核心组件是否正常工作
        
        返回:
            dict: 检测结果，包含状态和信息
        """
        results = {
            "status": True,
            "message": "核心组件检测通过"
        }
        
        try:
            # 1. 检测压缩算法模块
            test_data = b"test data for component detection"
            
            # 测试zlib压缩
            try:
                compressed = zlib.compress(test_data, self.compression_level)
                decompressed = zlib.decompress(compressed)
                if decompressed != test_data:
                    raise Exception("zlib压缩/解压验证失败")
            except Exception as e:
                results["status"] = False
                results["message"] = f"zlib压缩模块异常: {e}"
                self._record_log(results["message"], "error")
                return results
            
            # 测试bz2压缩（如果可用）
            try:
                import bz2
                compressed = bz2.compress(test_data)
                decompressed = bz2.decompress(compressed)
                if decompressed != test_data:
                    raise Exception("bz2压缩/解压验证失败")
            except ImportError:
                # bz2可能在某些环境中不可用，这不是致命错误
                pass
            except Exception as e:
                self._record_log(f"bz2压缩模块异常: {e}", "warning")
            
            # 2. 检测加密模块
            try:
                test_password = "test_password"
                encrypted = self._encrypt_data(test_data, test_password)
                decrypted = self._decrypt_data(encrypted, test_password)
                if decrypted != test_data:
                    raise Exception("加密/解密验证失败")
            except Exception as e:
                results["status"] = False
                results["message"] = f"加密模块异常: {e}"
                self._record_log(results["message"], "error")
                return results
            
            self._record_log("所有核心组件检测通过", "info")
            return results
            
        except Exception as e:
            results["status"] = False
            results["message"] = f"核心组件检测失败: {e}"
            self._record_log(results["message"], "error")
            return results

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
    
    def _get_compression_format(self, file_path):
        """
        根据文件扩展名获取压缩格式
        
        参数:
            file_path: 文件路径
        
        返回:
            str: 压缩格式 (stz, zip, 7z, rar, tar, gz, bz2, xz)
        """
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.stz':
            return 'stz'
        elif ext == '.zip':
            return 'zip'
        elif ext == '.7z':
            return '7z'
        elif ext == '.rar':
            return 'rar'
        elif ext == '.tar':
            return 'tar'
        elif ext == '.gz':
            return 'gz'
        elif ext == '.bz2':
            return 'bz2'
        elif ext == '.xz':
            return 'xz'
        else:
            # 尝试根据双重扩展名判断
            base, first_ext = os.path.splitext(os.path.splitext(file_path)[0])
            if first_ext == '.tar' and ext in ['.gz', '.bz2', '.xz']:
                return f'tar{ext}'
            return None
    
    def compress_to_format(self, targets, output_path, format='stz', password=None, compression_level=6, compression_algorithm='zlib'):
        """
        多格式压缩支持
        
        参数:
            targets: 要压缩的文件或文件夹列表
            output_path: 输出路径
            format: 压缩格式 (stz, zip, 7z, rar, tar, gztar, bztar, xztar)
            password: 密码 (可选)
            compression_level: 压缩级别 (1-9)
            compression_algorithm: 压缩算法 (仅对stz格式有效)
        
        返回:
            tuple: (success, logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        files_created = []
        
        try:
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
                return False, logs
            
            # 根据格式调用不同的压缩方法
            if format == 'stz':
                # 使用原有的stz压缩方法
                self.compression_level = compression_level
                self.compression_algorithm = compression_algorithm
                result, stz_logs = self.compress(valid_targets, output_path, password)
                logs.extend(stz_logs)
                return result, logs
            elif format == 'zip':
                # 使用内置zipfile库
                with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=compression_level) as zf:
                    for target in valid_targets:
                        if os.path.isfile(target):
                            zf.write(target, os.path.basename(target))
                            log = self._record_log(f"已添加到ZIP → {target}", "info")
                            logs.append((log, "info"))
                        else:
                            for root, dirs, files in os.walk(target):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    arcname = os.path.relpath(file_path, os.path.dirname(target))
                                    zf.write(file_path, arcname)
                                    log = self._record_log(f"已添加到ZIP → {file_path}", "info")
                                    logs.append((log, "info"))
                log = self._record_log(f"ZIP压缩完成 → {output_path}", "success")
                logs.append((log, "success"))
                return True, logs
            elif format == '7z' and PY7ZR_AVAILABLE:
                # 使用py7zr库
                options = {
                    'level': compression_level
                }
                with py7zr.SevenZipFile(output_path, 'w', password=password, **options) as zf:
                    for target in valid_targets:
                        if os.path.isfile(target):
                            zf.write(target, os.path.basename(target))
                            log = self._record_log(f"已添加到7Z → {target}", "info")
                            logs.append((log, "info"))
                        else:
                            for root, dirs, files in os.walk(target):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    arcname = os.path.relpath(file_path, os.path.dirname(target))
                                    zf.write(file_path, arcname)
                                    log = self._record_log(f"已添加到7Z → {file_path}", "info")
                                    logs.append((log, "info"))
                log = self._record_log(f"7Z压缩完成 → {output_path}", "success")
                logs.append((log, "success"))
                return True, logs
            elif format == 'rar' and RARFILE_AVAILABLE:
                # 使用rarfile库创建RAR文件
                # 注意：rarfile需要外部rar.exe程序支持
                with rarfile.RarFile(output_path, 'w', compresslevel=compression_level) as rf:
                    for target in valid_targets:
                        if os.path.isfile(target):
                            rf.write(target, os.path.basename(target))
                            log = self._record_log(f"已添加到RAR → {target}", "info")
                            logs.append((log, "info"))
                        else:
                            for root, dirs, files in os.walk(target):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    arcname = os.path.relpath(file_path, os.path.dirname(target))
                                    rf.write(file_path, arcname)
                                    log = self._record_log(f"已添加到RAR → {file_path}", "info")
                                    logs.append((log, "info"))
                log = self._record_log(f"RAR压缩完成 → {output_path}", "success")
                logs.append((log, "success"))
                return True, logs
            elif format in ['tar', 'gztar', 'bztar', 'xztar']:
                # 使用内置tarfile库
                mode = 'w'
                if format == 'gztar':
                    mode = 'w:gz'
                elif format == 'bztar':
                    mode = 'w:bz2'
                elif format == 'xztar':
                    mode = 'w:xz'
                
                with tarfile.open(output_path, mode, compresslevel=compression_level) as tf:
                    for target in valid_targets:
                        if os.path.isfile(target):
                            tf.add(target, os.path.basename(target))
                            log = self._record_log(f"已添加到TAR → {target}", "info")
                            logs.append((log, "info"))
                        else:
                            for root, dirs, files in os.walk(target):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    arcname = os.path.relpath(file_path, os.path.dirname(target))
                                    tf.add(file_path, arcname)
                                    log = self._record_log(f"已添加到TAR → {file_path}", "info")
                                    logs.append((log, "info"))
                log = self._record_log(f"{format.upper()}压缩完成 → {output_path}", "success")
                logs.append((log, "success"))
                return True, logs
            else:
                log = self._record_log(f"错误：不支持的压缩格式 → {format}", "error")
                logs.append((log, "error"))
                return False, logs
        
        except Exception as e:
            log = self._record_log(f"压缩失败：{e}", "error")
            logs.append((log, "error"))
            return False, logs
    
    def decompress_from_format(self, archive_path, output_dir, password=None):
        """
        多格式解压支持
        
        参数:
            archive_path: 压缩包路径
            output_dir: 输出目录
            password: 密码 (可选)
        
        返回:
            tuple: (success, logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        
        try:
            if not os.path.exists(archive_path):
                log = self._record_log(f"错误：压缩包不存在 → {archive_path}", "error")
                logs.append((log, "error"))
                return False, logs
            
            # 获取压缩格式
            format = self._get_compression_format(archive_path)
            if not format:
                log = self._record_log(f"错误：无法识别压缩格式 → {archive_path}", "error")
                logs.append((log, "error"))
                return False, logs
            
            # 根据格式调用不同的解压方法
            if format == 'stz':
                # 使用原有的stz解压方法
                return self.decompress(archive_path, output_dir, password)
            elif format == 'zip':
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    # 检查是否需要密码
                    if zf.namelist() and zf.getinfo(zf.namelist()[0]).flag_bits & 0x1:
                        if not password:
                            log = self._record_log("错误：ZIP文件已加密，需要密码", "error")
                            logs.append((log, "error"))
                            return False, logs
                        try:
                            zf.extractall(output_dir, pwd=password.encode('utf-8') if password else None)
                        except RuntimeError:
                            log = self._record_log("错误：密码错误", "error")
                            logs.append((log, "error"))
                            return False, logs
                    else:
                        zf.extractall(output_dir)
                log = self._record_log(f"ZIP解压完成 → {output_dir}", "success")
                logs.append((log, "success"))
                return True, logs
            elif format == '7z' and PY7ZR_AVAILABLE:
                with py7zr.SevenZipFile(archive_path, mode='r', password=password) as zf:
                    zf.extractall(output_dir)
                log = self._record_log(f"7Z解压完成 → {output_dir}", "success")
                logs.append((log, "success"))
                return True, logs
            elif format == 'rar' and RARFILE_AVAILABLE:
                with rarfile.RarFile(archive_path, mode='r') as rf:
                    if rf.needs_password():
                        if not password:
                            log = self._record_log("错误：RAR文件已加密，需要密码", "error")
                            logs.append((log, "error"))
                            return False, logs
                        rf.setpassword(password)
                    rf.extractall(output_dir)
                log = self._record_log(f"RAR解压完成 → {output_dir}", "success")
                logs.append((log, "success"))
                return True, logs
            elif format in ['tar', 'gz', 'bz2', 'xz'] or format.startswith('tar.'):
                # 使用tarfile处理TAR及其变体
                mode = 'r'
                if format in ['gz', 'targz']:
                    mode = 'r:gz'
                elif format in ['bz2', 'tarbz2']:
                    mode = 'r:bz2'
                elif format in ['xz', 'tarxz']:
                    mode = 'r:xz'
                elif format.startswith('tar'):
                    mode = f'r:{format[3:]}'  # tar.gz -> r:gz
                
                with tarfile.open(archive_path, mode) as tf:
                    tf.extractall(output_dir)
                log = self._record_log(f"{format.upper()}解压完成 → {output_dir}", "success")
                logs.append((log, "success"))
                return True, logs
            else:
                log = self._record_log(f"错误：不支持的解压格式 → {format}", "error")
                logs.append((log, "error"))
                return False, logs
        
        except Exception as e:
            log = self._record_log(f"解压失败：{e}", "error")
            logs.append((log, "error"))
            return False, logs
    
    def convert_format(self, input_path, output_path, password=None, compression_level=6):
        """
        压缩格式转换
        
        参数:
            input_path: 输入压缩包路径
            output_path: 输出压缩包路径
            password: 密码 (可选)
            compression_level: 压缩级别 (1-9)
        
        返回:
            tuple: (success, logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        
        try:
            if not os.path.exists(input_path):
                log = self._record_log(f"错误：输入文件不存在 → {input_path}", "error")
                logs.append((log, "error"))
                return False, logs
            
            # 获取输入和输出格式
            input_format = self._get_compression_format(input_path)
            output_format = self._get_compression_format(output_path)
            
            if not input_format or not output_format:
                log = self._record_log("错误：无法识别压缩格式", "error")
                logs.append((log, "error"))
                return False, logs
            
            # 创建临时目录
            temp_dir = tempfile.mkdtemp()
            
            # 解压输入文件
            log = self._record_log(f"正在解压源文件 → {input_path}", "info")
            logs.append((log, "info"))
            success, extract_logs = self.decompress_from_format(input_path, temp_dir, password)
            logs.extend(extract_logs)
            
            if not success:
                shutil.rmtree(temp_dir)
                return False, logs
            
            # 压缩到输出格式
            log = self._record_log(f"正在压缩到目标格式 → {output_path}", "info")
            logs.append((log, "info"))
            # 获取临时目录中的所有文件和文件夹
            temp_contents = [os.path.join(temp_dir, item) for item in os.listdir(temp_dir)]
            success, compress_logs = self.compress_to_format(temp_contents, output_path, output_format, compression_level=compression_level)
            logs.extend(compress_logs)
            
            # 清理临时目录
            shutil.rmtree(temp_dir)
            
            if success:
                log = self._record_log(f"格式转换完成 → {output_path}", "success")
                logs.append((log, "success"))
                return True, logs
            else:
                return False, logs
        
        except Exception as e:
            log = self._record_log(f"格式转换失败：{e}", "error")
            logs.append((log, "error"))
            return False, logs
    
    def batch_convert_format(self, input_paths, output_dir, target_format, password=None, compression_level=6, delete_source=False):
        """
        批量压缩格式转换
        
        参数:
            input_paths: 输入压缩包路径列表
            output_dir: 输出目录
            target_format: 目标压缩格式 (zip, 7z, rar, tar, gztar, bztar, xztar, stz)
            password: 密码 (可选)
            compression_level: 压缩级别 (1-9)
            delete_source: 是否删除源文件 (默认False)
        
        返回:
            tuple: (success_count, failed_count, logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        success_count = 0
        failed_count = 0
        
        try:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # 为目标格式创建文件扩展名映射
            format_ext_map = {
                'stz': '.stz',
                'zip': '.zip',
                '7z': '.7z',
                'rar': '.rar',
                'tar': '.tar',
                'gztar': '.tar.gz',
                'bztar': '.tar.bz2',
                'xztar': '.tar.xz'
            }
            
            if target_format not in format_ext_map:
                log = self._record_log(f"错误：不支持的目标格式 → {target_format}", "error")
                logs.append((log, "error"))
                return 0, 0, logs
            
            target_ext = format_ext_map[target_format]
            
            log = self._record_log(f"开始批量转换，共 {len(input_paths)} 个文件", "info")
            logs.append((log, "info"))
            
            for i, input_path in enumerate(input_paths):
                if self.is_cancelled:
                    log = self._record_log("批量转换已取消", "warning")
                    logs.append((log, "warning"))
                    break
                
                # 检查是否暂停
                while self.is_paused:
                    time.sleep(0.5)
                
                log = self._record_log(f"正在处理 ({i+1}/{len(input_paths)}) → {input_path}", "info")
                logs.append((log, "info"))
                
                if not os.path.exists(input_path):
                    log = self._record_log(f"警告：文件不存在，已跳过 → {input_path}", "warning")
                    logs.append((log, "warning"))
                    failed_count += 1
                    continue
                
                # 生成输出文件名
                input_name = os.path.splitext(os.path.basename(input_path))[0]
                # 移除可能存在的其他扩展名
                input_name = os.path.splitext(input_name)[0] if any(ext in input_name for ext in ['.tar', '.gz', '.bz2', '.xz']) else input_name
                output_path = os.path.join(output_dir, input_name + target_ext)
                
                # 转换文件
                success, file_logs = self.convert_format(input_path, output_path, password, compression_level)
                logs.extend(file_logs)
                
                if success:
                    success_count += 1
                    # 删除源文件
                    if delete_source:
                        try:
                            os.remove(input_path)
                            log = self._record_log(f"已删除源文件 → {input_path}", "info")
                            logs.append((log, "info"))
                        except Exception as e:
                            log = self._record_log(f"删除源文件失败：{e}", "warning")
                            logs.append((log, "warning"))
                else:
                    failed_count += 1
            
            log = self._record_log(f"批量转换完成：成功 {success_count} 个，失败 {failed_count} 个", "success")
            logs.append((log, "success"))
            return success_count, failed_count, logs
        
        except Exception as e:
            log = self._record_log(f"批量转换失败：{e}", "error")
            logs.append((log, "error"))
            return success_count, failed_count + 1, logs
    
    def calculate_checksum(self, file_path, algorithm='md5'):
        """
        计算文件的校验值
        
        参数:
            file_path: 文件路径
            algorithm: 校验算法 (md5, sha1, sha256, crc32)
        
        返回:
            tuple: (success, checksum_value, logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        
        try:
            if not os.path.exists(file_path):
                log = self._record_log(f"错误：文件不存在 → {file_path}", "error")
                logs.append((log, "error"))
                return False, None, logs
            
            if algorithm == 'crc32':
                # 计算CRC32
                checksum = 0
                with open(file_path, 'rb') as f:
                    while True:
                        if self.is_cancelled:
                            log = self._record_log("校验计算已取消", "warning")
                            logs.append((log, "warning"))
                            return False, None, logs
                        
                        # 检查是否暂停
                        while self.is_paused:
                            time.sleep(0.5)
                        
                        data = f.read(8192)
                        if not data:
                            break
                        checksum = zlib.crc32(data, checksum) & 0xffffffff
                checksum_value = f"{checksum:08x}"
            
            elif algorithm in ['md5', 'sha1', 'sha256']:
                # 使用hashlib计算MD5/SHA1/SHA256
                hash_obj = hashlib.new(algorithm)
                with open(file_path, 'rb') as f:
                    while True:
                        if self.is_cancelled:
                            log = self._record_log("校验计算已取消", "warning")
                            logs.append((log, "warning"))
                            return False, None, logs
                        
                        # 检查是否暂停
                        while self.is_paused:
                            time.sleep(0.5)
                        
                        data = f.read(8192)
                        if not data:
                            break
                        hash_obj.update(data)
                checksum_value = hash_obj.hexdigest()
            
            else:
                log = self._record_log(f"错误：不支持的校验算法 → {algorithm}", "error")
                logs.append((log, "error"))
                return False, None, logs
            
            log = self._record_log(f"{algorithm.upper()} 校验值计算完成 → {checksum_value}", "success")
            logs.append((log, "success"))
            return True, checksum_value, logs
        
        except Exception as e:
            log = self._record_log(f"校验计算失败：{e}", "error")
            logs.append((log, "error"))
            return False, None, logs
    
    def verify_archive(self, archive_path, password=None):
        """
        验证压缩包的完整性
        
        参数:
            archive_path: 压缩包路径
            password: 密码 (可选)
        
        返回:
            tuple: (success, is_valid, logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        
        try:
            if not os.path.exists(archive_path):
                log = self._record_log(f"错误：压缩包不存在 → {archive_path}", "error")
                logs.append((log, "error"))
                return False, False, logs
            
            format = self._get_compression_format(archive_path)
            if not format:
                log = self._record_log(f"错误：无法识别压缩格式 → {archive_path}", "error")
                logs.append((log, "error"))
                return False, False, logs
            
            is_valid = False
            
            if format == 'stz':
                # 验证STZ格式
                try:
                    with open(archive_path, 'rb') as f:
                        # 读取文件头
                        header = f.read(4)
                        if header != b'STZ\x01':
                            log = self._record_log("错误：不是有效的STZ文件格式", "error")
                            logs.append((log, "error"))
                            return True, False, logs
                        
                        # 尝试读取元数据
                        f.seek(-16, 2)  # 定位到文件末尾的元数据偏移量
                        metadata_offset = struct.unpack('<Q', f.read(8))[0]
                        f.seek(metadata_offset)
                        metadata_data = f.read()
                        
                        # 尝试解析元数据
                        info_json = json.loads(metadata_data.decode('utf-8'))
                        is_valid = True
                        log = self._record_log("STZ压缩包验证通过", "success")
                        logs.append((log, "success"))
                except Exception as e:
                    log = self._record_log(f"STZ压缩包验证失败：{e}", "error")
                    logs.append((log, "error"))
                    is_valid = False
            
            elif format == 'zip':
                # 验证ZIP格式
                try:
                    with zipfile.ZipFile(archive_path, 'r') as zf:
                        # 检查是否需要密码
                        if password:
                            try:
                                zf.testzip()
                                is_valid = True
                                log = self._record_log("ZIP压缩包验证通过", "success")
                                logs.append((log, "success"))
                            except RuntimeError:
                                log = self._record_log("ZIP压缩包密码错误", "error")
                                logs.append((log, "error"))
                                is_valid = False
                        else:
                            if zf.testzip() is None:
                                is_valid = True
                                log = self._record_log("ZIP压缩包验证通过", "success")
                                logs.append((log, "success"))
                            else:
                                log = self._record_log("ZIP压缩包已损坏", "error")
                                logs.append((log, "error"))
                                is_valid = False
                except Exception as e:
                    log = self._record_log(f"ZIP压缩包验证失败：{e}", "error")
                    logs.append((log, "error"))
                    is_valid = False
            
            elif format == '7z' and PY7ZR_AVAILABLE:
                # 验证7Z格式
                try:
                    with py7zr.SevenZipFile(archive_path, 'r', password=password) as zf:
                        # 检查文件内容
                        for name in zf.getnames():
                            if self.is_cancelled:
                                log = self._record_log("验证已取消", "warning")
                                logs.append((log, "warning"))
                                return False, False, logs
                            
                            # 检查是否暂停
                            while self.is_paused:
                                time.sleep(0.5)
                        
                        is_valid = True
                        log = self._record_log("7Z压缩包验证通过", "success")
                        logs.append((log, "success"))
                except Exception as e:
                    log = self._record_log(f"7Z压缩包验证失败：{e}", "error")
                    logs.append((log, "error"))
                    is_valid = False
            
            elif format == 'rar' and RARFILE_AVAILABLE:
                # 验证RAR格式
                try:
                    with rarfile.RarFile(archive_path, 'r') as rf:
                        if rf.needs_password():
                            if not password:
                                log = self._record_log("RAR压缩包已加密，需要密码", "error")
                                logs.append((log, "error"))
                                return True, False, logs
                            rf.setpassword(password)
                        
                        # 检查文件内容
                        for name in rf.namelist():
                            if self.is_cancelled:
                                log = self._record_log("验证已取消", "warning")
                                logs.append((log, "warning"))
                                return False, False, logs
                            
                            # 检查是否暂停
                            while self.is_paused:
                                time.sleep(0.5)
                        
                        is_valid = True
                        log = self._record_log("RAR压缩包验证通过", "success")
                        logs.append((log, "success"))
                except Exception as e:
                    log = self._record_log(f"RAR压缩包验证失败：{e}", "error")
                    logs.append((log, "error"))
                    is_valid = False
            
            elif format in ['tar', 'gz', 'bz2', 'xz'] or format.startswith('tar.'):
                # 验证TAR及其变体
                try:
                    mode = 'r'
                    if format in ['gz', 'targz']:
                        mode = 'r:gz'
                    elif format in ['bz2', 'tarbz2']:
                        mode = 'r:bz2'
                    elif format in ['xz', 'tarxz']:
                        mode = 'r:xz'
                    elif format.startswith('tar'):
                        mode = f'r:{format[3:]}'
                    
                    with tarfile.open(archive_path, mode) as tf:
                        # 检查文件内容
                        for member in tf.getmembers():
                            if self.is_cancelled:
                                log = self._record_log("验证已取消", "warning")
                                logs.append((log, "warning"))
                                return False, False, logs
                            
                            # 检查是否暂停
                            while self.is_paused:
                                time.sleep(0.5)
                        
                        is_valid = True
                        log = self._record_log(f"{format.upper()}压缩包验证通过", "success")
                        logs.append((log, "success"))
                except Exception as e:
                    log = self._record_log(f"{format.upper()}压缩包验证失败：{e}", "error")
                    logs.append((log, "error"))
                    is_valid = False
            
            else:
                log = self._record_log(f"错误：不支持的验证格式 → {format}", "error")
                logs.append((log, "error"))
                return False, False, logs
            
            return True, is_valid, logs
        
        except Exception as e:
            log = self._record_log(f"验证失败：{e}", "error")
            logs.append((log, "error"))
            return False, False, logs
    
    def repair_archive(self, archive_path, output_path=None, password=None):
        """
        尝试修复损坏的压缩包
        
        参数:
            archive_path: 损坏的压缩包路径
            output_path: 修复后的输出路径 (可选)
            password: 密码 (可选)
        
        返回:
            tuple: (success, repaired_path, logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        
        try:
            if not os.path.exists(archive_path):
                log = self._record_log(f"错误：压缩包不存在 → {archive_path}", "error")
                logs.append((log, "error"))
                return False, None, logs
            
            format = self._get_compression_format(archive_path)
            if not format:
                log = self._record_log(f"错误：无法识别压缩格式 → {archive_path}", "error")
                logs.append((log, "error"))
                return False, None, logs
            
            # 设置默认输出路径
            if not output_path:
                base_name, ext = os.path.splitext(archive_path)
                output_path = f"{base_name}_repaired{ext}"
            
            repaired_path = None
            
            # 根据不同格式尝试修复
            if format == 'stz':
                # STZ格式修复 (简单尝试)
                try:
                    with open(archive_path, 'rb') as f:
                        data = f.read()
                    
                    # 尝试移除可能损坏的文件末尾部分
                    # 定位到STZ文件头
                    if data.startswith(b'STZ\x01'):
                        # 尝试找到元数据
                        try:
                            # 定位到文件末尾的元数据偏移量
                            metadata_offset = struct.unpack('<Q', data[-16:-8])[0]
                            # 提取有效的文件部分
                            valid_data = data[:metadata_offset + 16]  # 包含元数据
                            
                            # 保存修复后的文件
                            with open(output_path, 'wb') as f:
                                f.write(valid_data)
                            
                            repaired_path = output_path
                            log = self._record_log("STZ压缩包修复完成", "success")
                            logs.append((log, "success"))
                        except Exception as e:
                            log = self._record_log(f"STZ元数据修复失败：{e}", "warning")
                            logs.append((log, "warning"))
                            # 尝试简单复制文件
                            shutil.copy2(archive_path, output_path)
                            repaired_path = output_path
                            log = self._record_log("STZ压缩包已复制 (简单修复)", "info")
                            logs.append((log, "info"))
                except Exception as e:
                    log = self._record_log(f"STZ压缩包修复失败：{e}", "error")
                    logs.append((log, "error"))
            
            elif format == 'zip':
                # ZIP格式修复
                try:
                    # 使用zipfile的修复功能（有限支持）
                    with zipfile.ZipFile(archive_path, 'r') as zf:
                        # 尝试提取所有文件
                        temp_dir = tempfile.mkdtemp()
                        zf.extractall(temp_dir, pwd=password.encode('utf-8') if password else None)
                        
                        # 重新创建ZIP文件
                        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as new_zf:
                            for root, dirs, files in os.walk(temp_dir):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    arcname = os.path.relpath(file_path, temp_dir)
                                    new_zf.write(file_path, arcname)
                        
                        repaired_path = output_path
                        shutil.rmtree(temp_dir)
                        log = self._record_log("ZIP压缩包修复完成", "success")
                        logs.append((log, "success"))
                except Exception as e:
                    log = self._record_log(f"ZIP压缩包修复失败：{e}", "error")
                    logs.append((log, "error"))
            
            elif format == '7z' and PY7ZR_AVAILABLE:
                # 7Z格式修复
                try:
                    # 使用py7zr的修复功能
                    temp_dir = tempfile.mkdtemp()
                    
                    # 尝试提取损坏的7Z文件
                    with py7zr.SevenZipFile(archive_path, 'r', password=password) as zf:
                        zf.extractall(temp_dir)
                    
                    # 重新创建7Z文件
                    with py7zr.SevenZipFile(output_path, 'w', password=password) as new_zf:
                        for root, dirs, files in os.walk(temp_dir):
                            for file in files:
                                file_path = os.path.join(root, file)
                                arcname = os.path.relpath(file_path, temp_dir)
                                new_zf.write(file_path, arcname)
                    
                    repaired_path = output_path
                    shutil.rmtree(temp_dir)
                    log = self._record_log("7Z压缩包修复完成", "success")
                    logs.append((log, "success"))
                except Exception as e:
                    log = self._record_log(f"7Z压缩包修复失败：{e}", "error")
                    logs.append((log, "error"))
            
            elif format == 'rar' and RARFILE_AVAILABLE:
                # RAR格式修复
                try:
                    # RAR修复需要外部工具支持，这里尝试简单提取
                    temp_dir = tempfile.mkdtemp()
                    
                    # 尝试提取损坏的RAR文件
                    with rarfile.RarFile(archive_path, 'r') as rf:
                        if rf.needs_password() and password:
                            rf.setpassword(password)
                        rf.extractall(temp_dir)
                    
                    # 重新创建RAR文件
                    with rarfile.RarFile(output_path, 'w') as new_rf:
                        for root, dirs, files in os.walk(temp_dir):
                            for file in files:
                                file_path = os.path.join(root, file)
                                arcname = os.path.relpath(file_path, temp_dir)
                                new_rf.write(file_path, arcname)
                    
                    repaired_path = output_path
                    shutil.rmtree(temp_dir)
                    log = self._record_log("RAR压缩包修复完成", "success")
                    logs.append((log, "success"))
                except Exception as e:
                    log = self._record_log(f"RAR压缩包修复失败：{e}", "error")
                    logs.append((log, "error"))
            
            elif format in ['tar', 'gz', 'bz2', 'xz'] or format.startswith('tar.'):
                # TAR及其变体修复
                try:
                    # 尝试提取损坏的TAR文件
                    temp_dir = tempfile.mkdtemp()
                    
                    mode = 'r'
                    if format in ['gz', 'targz']:
                        mode = 'r:gz'
                    elif format in ['bz2', 'tarbz2']:
                        mode = 'r:bz2'
                    elif format in ['xz', 'tarxz']:
                        mode = 'r:xz'
                    elif format.startswith('tar'):
                        mode = f'r:{format[3:]}'
                    
                    with tarfile.open(archive_path, mode) as tf:
                        tf.extractall(temp_dir)
                    
                    # 重新创建TAR文件
                    new_mode = 'w'
                    if format in ['gz', 'targz']:
                        new_mode = 'w:gz'
                    elif format in ['bz2', 'tarbz2']:
                        new_mode = 'w:bz2'
                    elif format in ['xz', 'tarxz']:
                        new_mode = 'w:xz'
                    elif format.startswith('tar'):
                        new_mode = f'w:{format[3:]}'
                    
                    with tarfile.open(output_path, new_mode) as new_tf:
                        for root, dirs, files in os.walk(temp_dir):
                            for file in files:
                                file_path = os.path.join(root, file)
                                arcname = os.path.relpath(file_path, temp_dir)
                                new_tf.add(file_path, arcname)
                    
                    repaired_path = output_path
                    shutil.rmtree(temp_dir)
                    log = self._record_log(f"{format.upper()}压缩包修复完成", "success")
                    logs.append((log, "success"))
                except Exception as e:
                    log = self._record_log(f"{format.upper()}压缩包修复失败：{e}", "error")
                    logs.append((log, "error"))
            
            else:
                log = self._record_log(f"错误：不支持的修复格式 → {format}", "error")
                logs.append((log, "error"))
                return False, None, logs
            
            if repaired_path:
                return True, repaired_path, logs
            else:
                log = self._record_log("压缩包修复失败，无法恢复数据", "error")
                logs.append((log, "error"))
                return False, None, logs
        
        except Exception as e:
            log = self._record_log(f"修复失败：{e}", "error")
            logs.append((log, "error"))
            return False, None, logs
    
    def create_self_extracting_archive(self, targets, output_exe, password=None, compression_level=6, extract_dir=None, overwrite=False):
        """
        创建自解压可执行文件 (.exe)
        
        参数:
            targets: 要压缩的文件/文件夹路径列表
            output_exe: 输出的EXE文件路径
            password: 密码 (可选)
            compression_level: 压缩级别 (1-9)
            extract_dir: 默认解压目录 (可选，默认为当前目录)
            overwrite: 是否覆盖已存在的文件
        
        返回:
            tuple: (success, output_path, logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        
        try:
            # 检查输出文件是否已存在
            if os.path.exists(output_exe) and not overwrite:
                log = self._record_log(f"错误：文件已存在 → {output_exe}", "error")
                logs.append((log, "error"))
                return False, None, logs
            
            # 检查目标文件/文件夹是否存在
            for target in targets:
                if not os.path.exists(target):
                    log = self._record_log(f"错误：目标不存在 → {target}", "error")
                    logs.append((log, "error"))
                    return False, None, logs
            
            # 创建临时目录
            temp_dir = tempfile.mkdtemp()
            log = self._record_log(f"创建临时目录：{temp_dir}", "info")
            logs.append((log, "info"))
            
            try:
                # 1. 先创建STZ压缩包
                stz_file = os.path.join(temp_dir, "content.stz")
                success, logs_stz = self.compress(targets, stz_file, password=password, compression_level=compression_level)
                logs.extend(logs_stz)
                
                if not success:
                    log = self._record_log("创建STZ压缩包失败", "error")
                    logs.append((log, "error"))
                    return False, None, logs
                
                # 2. 创建自解压脚本
                sfx_script = os.path.join(temp_dir, "sfx.py")
                
                # 生成自解压脚本内容
                sfx_content = f"""
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
自解压可执行文件
此文件包含压缩数据和自动解压脚本
'''


import os
import sys
import tempfile
import shutil
import struct
import json
import zlib
import base64

# 解压配置
EXTRACT_DIR = {extract_dir!r} if extract_dir else os.getcwd()


def extract_self():
    '''从自身提取并解压数据'''
    try:
        # 获取当前脚本路径
        self_path = sys.argv[0]
        
        # 打开自身文件
        with open(self_path, 'rb') as f:
            # 读取文件内容
            content = f.read()
        
        # 查找数据标记
        data_start = content.find(b'\x00\x00\x00\x00STZ_DATA\x00\x00\x00\x00')
        if data_start == -1:
            print("错误：无法找到压缩数据")
            return False
        
        # 跳过标记
        data_start += 16
        
        # 提取压缩数据
        compressed_data = content[data_start:]
        
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.stz', delete=False) as f:
            f.write(compressed_data)
            temp_stz = f.name
        
        try:
            # 确保解压目录存在
            if not os.path.exists(EXTRACT_DIR):
                os.makedirs(EXTRACT_DIR)
            
            # 解压STZ文件
            print(f"正在解压到: {EXTRACT_DIR}")
            
            # 解析STZ文件
            with open(temp_stz, 'rb') as f:
                # 读取文件头
                header = f.read(4)
                if header != b'STZ\x01':
                    print("错误：不是有效的STZ文件")
                    return False
                
                # 读取元数据偏移量
                f.seek(-16, 2)
                metadata_offset = struct.unpack('<Q', f.read(8))[0]
                
                # 读取元数据
                f.seek(metadata_offset)
                metadata = json.loads(f.read().decode('utf-8'))
                
                # 读取加密标志和数据
                f.seek(4)
                encrypted = struct.unpack('<?', f.read(1))[0]
                
                # 解压数据
                if encrypted:
                    print("注意：此文件已加密，需要手动解压")
                    return False
                
                # 读取压缩数据
                data_size = struct.unpack('<Q', f.read(8))[0]
                compressed_data = f.read(data_size)
                
                # 解压
                decompressed_data = zlib.decompress(compressed_data)
                
                # 写入临时文件
                with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
                    f.write(decompressed_data)
                    temp_zip = f.name
                
                try:
                    # 解压ZIP数据
                    import zipfile
                    with zipfile.ZipFile(temp_zip, 'r') as zf:
                        zf.extractall(EXTRACT_DIR)
                    
                    print(f"解压完成！文件已保存到: {EXTRACT_DIR}")
                    return True
                finally:
                    os.unlink(temp_zip)
                    
        finally:
            os.unlink(temp_stz)
            
    except Exception as e:
        print(f"解压失败: {e}")
        return False


if __name__ == "__main__":
    extract_self()
    input("按回车键退出...")
"""
                
                with open(sfx_script, 'w', encoding='utf-8') as f:
                    f.write(sfx_content)
                
                # 3. 使用PyInstaller创建自解压EXE
                # 检查PyInstaller是否可用
                try:
                    import PyInstaller
                    pyinstaller_available = True
                except ImportError:
                    pyinstaller_available = False
                
                if not pyinstaller_available:
                    log = self._record_log("错误：PyInstaller未安装，无法创建自解压EXE", "error")
                    logs.append((log, "error"))
                    return False, None, logs
                
                # 使用PyInstaller打包脚本
                import subprocess
                import sys
                
                pyinstaller_cmd = [
                    sys.executable,
                    "-m", "PyInstaller",
                    "--onefile",
                    "--windowed",  # 无控制台窗口
                    "--name", "temp_sfx",
                    "--distpath", temp_dir,
                    "--workpath", os.path.join(temp_dir, "build"),
                    "--specpath", temp_dir,
                    sfx_script
                ]
                
                log = self._record_log(f"正在创建自解压EXE: {' '.join(pyinstaller_cmd)}", "info")
                logs.append((log, "info"))
                
                # 运行PyInstaller
                result = subprocess.run(pyinstaller_cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    log = self._record_log(f"PyInstaller执行失败: {result.stderr}", "error")
                    logs.append((log, "error"))
                    return False, None, logs
                
                # 4. 合并EXE和STZ数据
                exe_file = os.path.join(temp_dir, "temp_sfx.exe")
                if not os.path.exists(exe_file):
                    log = self._record_log("错误：PyInstaller未生成EXE文件", "error")
                    logs.append((log, "error"))
                    return False, None, logs
                
                # 读取EXE文件
                with open(exe_file, 'rb') as f:
                    exe_data = f.read()
                
                # 读取STZ文件
                with open(stz_file, 'rb') as f:
                    stz_data = f.read()
                
                # 合并数据
                combined_data = exe_data + b'\x00\x00\x00\x00STZ_DATA\x00\x00\x00\x00' + stz_data
                
                # 写入最终EXE文件
                with open(output_exe, 'wb') as f:
                    f.write(combined_data)
                
                log = self._record_log(f"自解压EXE创建完成：{output_exe}", "success")
                logs.append((log, "success"))
                
                return True, output_exe, logs
                
            finally:
                # 清理临时文件
                shutil.rmtree(temp_dir)
                log = self._record_log("清理临时文件", "info")
                logs.append((log, "info"))
                
        except Exception as e:
            log = self._record_log(f"创建自解压EXE失败：{e}", "error")
            logs.append((log, "error"))
            return False, None, logs
            
    def batch_compress(self, paths, output_dir, format, params):
        """
        批量压缩多个文件/文件夹到指定目录
        
        参数:
            paths: 要压缩的文件/文件夹路径列表
            output_dir: 输出目录
            format: 压缩格式 (stz, zip, 7z, tar, etc.)
            params: 压缩参数 (包含compression_level, password等)
        
        返回:
            tuple: (success, results, logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        results = []
        
        try:
            # 检查输出目录是否存在
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                log = self._record_log(f"创建输出目录：{output_dir}", "info")
                logs.append((log, "info"))
            
            total_files = len(paths)
            processed_files = 0
            
            for i, path in enumerate(paths):
                if self.is_cancelled:
                    log = self._record_log("批量压缩已取消", "warning")
                    logs.append((log, "warning"))
                    return False, results, logs
                    
                while self.is_paused:
                    time.sleep(0.5)
                    if self.is_cancelled:
                        log = self._record_log("批量压缩已取消", "warning")
                        logs.append((log, "warning"))
                        return False, results, logs
                
                # 获取文件名（不含扩展名）
                base_name = os.path.basename(path)
                if os.path.isfile(path):
                    base_name, _ = os.path.splitext(base_name)
                
                # 构建输出文件名
                ext_map = {
                    "stz": ".stz",
                    "zip": ".zip",
                    "7z": ".7z",
                    "tar": ".tar",
                    "tar.gz": ".tar.gz",
                    "tar.bz2": ".tar.bz2",
                    "tar.xz": ".tar.xz"
                }
                
                output_file = os.path.join(output_dir, f"{base_name}{ext_map[format]}")
                
                log = self._record_log(f"正在压缩 [{i+1}/{total_files}]: {path} → {output_file}", "info")
                logs.append((log, "info"))
                
                try:
                    # 执行单个文件压缩
                    success, output_path, file_logs = self.compress_to_format([path], output_file, format, params)
                    logs.extend(file_logs)
                    
                    if success:
                        results.append((path, output_path))
                        processed_files += 1
                        
                        # 更新进度
                        progress = int((processed_files / total_files) * 100)
                        if self.progress_callback:
                            self.progress_callback(progress, f"已完成 {processed_files}/{total_files} 个文件", "info")
                    else:
                        log = self._record_log(f"压缩失败：{path}", "error")
                        logs.append((log, "error"))
                        
                except Exception as e:
                    log = self._record_log(f"压缩文件时出错 {path}: {e}", "error")
                    logs.append((log, "error"))
            
            if processed_files == total_files:
                log = self._record_log(f"批量压缩完成，成功压缩 {processed_files}/{total_files} 个文件", "success")
                logs.append((log, "success"))
                return True, results, logs
            else:
                log = self._record_log(f"批量压缩完成，但有 {total_files - processed_files} 个文件压缩失败", "warning")
                logs.append((log, "warning"))
                return False, results, logs
                
        except Exception as e:
            log = self._record_log(f"批量压缩失败：{e}", "error")
            logs.append((log, "error"))
            return False, results, logs

    def _record_log(self, content, level="info"):
        log = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {content}"
        self.logs.append((log, level))
        return log

    def cancel_operation(self):
        self.is_cancelled = True

    def pause_operation(self):
        self.is_paused = not self.is_paused
    
    def _rollback(self, temp_files, files_created, logs):
        """
        执行回滚操作，清理临时文件和创建的文件
        """
        log = self._record_log("执行回滚操作...", "warning")
        logs.append((log, "warning"))
        
        # 删除创建的文件
        for file_path in files_created:
            if os.path.exists(file_path):
                try:
                    if os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                    else:
                        os.remove(file_path)
                    log = self._record_log(f"已删除回滚文件: {file_path}", "warning")
                    logs.append((log, "warning"))
                except Exception as e:
                    log = self._record_log(f"回滚删除文件失败: {file_path} -> {e}", "error")
                    logs.append((log, "error"))
        
        # 清理临时文件
        for temp_path in temp_files:
            if os.path.exists(temp_path):
                try:
                    if os.path.isdir(temp_path):
                        shutil.rmtree(temp_path)
                    else:
                        os.remove(temp_path)
                    log = self._record_log(f"已清理临时文件: {temp_path}", "warning")
                    logs.append((log, "warning"))
                except Exception as e:
                    log = self._record_log(f"清理临时文件失败: {temp_path} -> {e}", "error")
                    logs.append((log, "error"))

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
            
            # 智能压缩：根据文件类型自动选择算法和级别
            if self.use_smart_compression:
                recommended_algo, recommended_level = self._smart_compression_analysis(valid_targets)
                if recommended_algo:
                    self.compression_algorithm = recommended_algo
                    self.compression_level = recommended_level
                    log = self._record_log(f"智能压缩已选择：算法={recommended_algo}，级别={recommended_level}", "info")
                    logs.append((log, "info"))

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
            compressed_data = b""
            
            # 根据选择的算法创建压缩器
            if self.compression_algorithm == 'zlib':
                import zlib
                compressor = zlib.compressobj(
                    level=self.compression_level,
                    method=zlib.DEFLATED,
                    wbits=15,
                    memLevel=8
                )
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
                compressed_data += compressor.flush()
            
            elif self.compression_algorithm == 'lzma':
                import lzma
                lzma_filters = [
                    {
                        "id": lzma.FILTER_LZMA2,
                        "preset": self.compression_level
                    }
                ]
                # LZMA直接压缩整个数据
                all_data = b""
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
                        all_data += file_content
                        processed_size += file_info["file_size"]
                        processed_files += 1

                        if self.progress_callback:
                            progress = int(processed_size / total_size * 100) if total_size > 0 else 0
                            self.progress_callback(
                                progress, 
                                f"读取中：{file_info['relative_path']} ({processed_files}/{total_files})"
                            )

                        log = self._record_log(f"已读取 → {file_info['relative_path']}（{file_info['file_size']}字节）", "info")
                        logs.append((log, "info"))
                
                if self.is_cancelled:
                    log = self._record_log("压缩操作已被取消", "warning")
                    logs.append((log, "warning"))
                    return None, logs
                
                # 使用LZMA压缩整个数据
                compressed_data = lzma.compress(all_data, format=lzma.FORMAT_RAW, filters=lzma_filters)
                log = self._record_log("使用LZMA算法压缩完成", "info")
                logs.append((log, "info"))
            
            elif self.compression_algorithm == 'brotli':
                try:
                    import brotli
                    # Brotli直接压缩整个数据
                    all_data = b""
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
                            all_data += file_content
                            processed_size += file_info["file_size"]
                            processed_files += 1

                            if self.progress_callback:
                                progress = int(processed_size / total_size * 100) if total_size > 0 else 0
                                self.progress_callback(
                                    progress, 
                                    f"读取中：{file_info['relative_path']} ({processed_files}/{total_files})"
                                )

                            log = self._record_log(f"已读取 → {file_info['relative_path']}（{file_info['file_size']}字节）", "info")
                            logs.append((log, "info"))
                    
                    if self.is_cancelled:
                        log = self._record_log("压缩操作已被取消", "warning")
                        logs.append((log, "warning"))
                        return None, logs
                    
                    # 使用Brotli压缩整个数据
                    compressed_data = brotli.compress(all_data, quality=self.compression_level)
                    log = self._record_log("使用Brotli算法压缩完成", "info")
                    logs.append((log, "info"))
                except ImportError:
                    log = self._record_log("警告：Brotli库未安装，已回退到zlib算法", "warning")
                    logs.append((log, "warning"))
                    # 回退到zlib
                    import zlib
                    compressor = zlib.compressobj(
                        level=self.compression_level,
                        method=zlib.DEFLATED,
                        wbits=15,
                        memLevel=8
                    )
                    # 重新读取文件并压缩
                    compressed_data = b""
                    processed_size = 0
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
                    compressed_data += compressor.flush()
            
            elif self.compression_algorithm == 'zstandard':
                try:
                    import zstandard as zstd
                    # Zstandard直接压缩整个数据
                    all_data = b""
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
                            all_data += file_content
                            processed_size += file_info["file_size"]
                            processed_files += 1

                            if self.progress_callback:
                                progress = int(processed_size / total_size * 100) if total_size > 0 else 0
                                self.progress_callback(
                                    progress, 
                                    f"读取中：{file_info['relative_path']} ({processed_files}/{total_files})"
                                )

                            log = self._record_log(f"已读取 → {file_info['relative_path']}（{file_info['file_size']}字节）", "info")
                            logs.append((log, "info"))
                    
                    if self.is_cancelled:
                        log = self._record_log("压缩操作已被取消", "warning")
                        logs.append((log, "warning"))
                        return None, logs
                    
                    # 使用Zstandard压缩整个数据
                    cctx = zstd.ZstdCompressor(level=self.compression_level)
                    compressed_data = cctx.compress(all_data)
                    log = self._record_log("使用Zstandard算法压缩完成", "info")
                    logs.append((log, "info"))
                except ImportError:
                    log = self._record_log("警告：Zstandard库未安装，已回退到zlib算法", "warning")
                    logs.append((log, "warning"))
                    # 回退到zlib
                    import zlib
                    compressor = zlib.compressobj(
                        level=self.compression_level,
                        method=zlib.DEFLATED,
                        wbits=15,
                        memLevel=8
                    )
                    # 重新读取文件并压缩
                    compressed_data = b""
                    processed_size = 0
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
                    compressed_data += compressor.flush()
            
            else:
                # 默认使用zlib
                import zlib
                compressor = zlib.compressobj(
                    level=self.compression_level,
                    method=zlib.DEFLATED,
                    wbits=15,
                    memLevel=8
                )
                # 重新读取文件并压缩
                compressed_data = b""
                processed_size = 0
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
                    compressed_data += compressor.flush()
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
            files_created.append(output_full_path)

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
                    files_created.append(part_name)
                    offset += split_size
                    part_index += 1
                # 删除原始单文件，保留分卷
                os.remove(output_full_path)
                files_created.remove(output_full_path)
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
            
            # 回滚操作
            self._rollback(temp_files, files_created, logs)
            return None, logs
        finally:
            # 清理临时文件
            for temp_file in temp_files:
                if os.path.exists(temp_file):
                    try:
                        if os.path.isdir(temp_file):
                            shutil.rmtree(temp_file)
                        else:
                            os.remove(temp_file)
                    except Exception as e:
                        self._record_log(f"清理临时文件失败: {temp_file} -> {e}", "warning")

    def extract(self, compress_file, output_dir, files_to_extract, password=None):
        """
        从压缩包中提取指定的文件
        
        参数:
            compress_file: 压缩包路径
            output_dir: 输出目录
            files_to_extract: 要提取的文件列表（相对路径）
            password: 密码（如果压缩包已加密）
            
        返回 (success(bool), logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        files_created = []  # 跟踪创建的文件，用于回滚
        try:
            # 1. 检查压缩包文件的权限
            if not check_file_permissions(compress_file):
                log = self._record_log(f"权限不足：无法读取压缩包 {compress_file}", "error")
                logs.append((log, "error"))
                return False, logs
            
            # 2. 检查压缩包文件是否被占用
            if check_file_in_use(compress_file):
                log = self._record_log(f"文件被占用：压缩包 {compress_file} 正在被其他程序使用", "error")
                logs.append((log, "error"))
                return False, logs
            
            if not os.path.exists(compress_file):
                log = self._record_log(f"错误：压缩包不存在 → {compress_file}", "error")
                logs.append((log, "error"))
                return False, logs

            # 3. 检查输出目录的权限
            if not check_file_permissions(output_dir, write=True):
                log = self._record_log(f"权限不足：无法在 {output_dir} 目录写入文件", "error")
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

            # 4. 检查磁盘空间
            total_size = 0
            for fi in file_info_list:
                rel = fi.get("relative_path", fi.get("file_name", ""))
                if rel in files_to_extract:
                    total_size += fi.get("file_size", 0)
            # 考虑额外空间（临时文件和系统开销）
            required_space = total_size + 50 * 1024 * 1024  # 50MB 额外空间
            
            has_space, available, required = check_disk_space(output_dir, required_space)
            if not has_space:
                log = self._record_log(f"磁盘空间不足：需要 {format_bytes(required)}，可用 {format_bytes(available)}", "error")
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
            extracted_count = 0
            for fi in file_info_list:
                if self.is_cancelled:
                    log = self._record_log("提取操作已被取消", "warning")
                    logs.append((log, "warning"))
                    return False, logs
                while self.is_paused:
                    time.sleep(0.1)

                rel = fi.get("relative_path", fi.get("file_name", ""))
                # 如果当前文件在要提取的列表中
                if rel in files_to_extract:
                    size = fi.get("file_size", 0)
                    # 规范路径，创建父目录
                    out_path = os.path.join(output_dir, *rel.split('/'))
                    parent_dir = os.path.dirname(out_path)
                    if parent_dir and not os.path.exists(parent_dir):
                        os.makedirs(parent_dir, exist_ok=True)
                    # 写入切片
                    slice_data = raw[offset: offset + size]
                    with open(out_path, "wb") as of:
                        of.write(slice_data)
                    files_created.append(out_path)
                    extracted_count += 1
                    log = self._record_log(f"已提取 → {rel}", "info")
                    logs.append((log, "info"))
                    if self.progress_callback:
                        # 简单进度：按文件数计算
                        progress = int(extracted_count / len(files_to_extract) * 100) if len(files_to_extract) > 0 else 0
                        self.progress_callback(progress, f"提取中：{rel} ({extracted_count}/{len(files_to_extract)})")
                
                # 无论是否提取，都需要更新偏移量
                offset += fi.get("file_size", 0)

            if extracted_count == 0:
                log = self._record_log(f"未找到要提取的文件", "warning")
                logs.append((log, "warning"))
            else:
                log = self._record_log(f"提取完成 → {output_dir}（共提取 {extracted_count} 个文件）", "success")
                logs.append((log, "success"))
            
            return True, logs

        except Exception as e:
            log = self._record_log(f"提取失败：{e}", "error")
            logs.append((log, "error"))
            
            # 回滚操作
            self._rollback([], files_created, logs)
            return False, logs

    def decompress(self, compress_file, output_dir, password=None):
        """
        解压压缩包
        返回 (success(bool), logs)
        """
        self.is_cancelled = False
        self.is_paused = False
        logs = []
        files_created = []  # 跟踪创建的文件，用于回滚
        try:
            # 1. 检查压缩包文件的权限
            if not check_file_permissions(compress_file):
                log = self._record_log(f"权限不足：无法读取压缩包 {compress_file}", "error")
                logs.append((log, "error"))
                return False, logs
            
            # 2. 检查压缩包文件是否被占用
            if check_file_in_use(compress_file):
                log = self._record_log(f"文件被占用：压缩包 {compress_file} 正在被其他程序使用", "error")
                logs.append((log, "error"))
                return False, logs
            
            if not os.path.exists(compress_file):
                log = self._record_log(f"错误：压缩包不存在 → {compress_file}", "error")
                logs.append((log, "error"))
                return False, logs

            # 3. 检查输出目录的权限
            if not check_file_permissions(output_dir, write=True):
                log = self._record_log(f"权限不足：无法在 {output_dir} 目录写入文件", "error")
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

            # 4. 检查磁盘空间
            total_size = 0
            for fi in file_info_list:
                total_size += fi.get("file_size", 0)
            # 考虑额外空间（临时文件和系统开销）
            required_space = total_size + 50 * 1024 * 1024  # 50MB 额外空间
            
            has_space, available, required = check_disk_space(output_dir, required_space)
            if not has_space:
                log = self._record_log(f"磁盘空间不足：需要 {format_bytes(required)}，可用 {format_bytes(available)}", "error")
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
                files_created.append(out_path)
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
            
            # 回滚操作
            self._rollback([], files_created, logs)
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
            
    def extract_file_content(self, archive_path, relative_path, password=None):
        """
        从压缩包中提取单个文件的内容，而不需要完全解压
        返回 (content, logs)，content为文件内容的二进制数据
        """
        logs = []
        try:
            if not os.path.exists(archive_path):
                log = self._record_log(f"错误：压缩包不存在 → {archive_path}", "error")
                logs.append((log, "error"))
                return None, logs
            
            with open(archive_path, "rb") as f:
                all_data = f.read()
            
            separator = b"###CUSTOM_COMPRESS_SEPARATOR###"
            if separator not in all_data:
                log = self._record_log("错误：不支持的压缩包格式或损坏（未找到分隔符）", "error")
                logs.append((log, "error"))
                return None, logs
            
            info_bin, compressed_data = all_data.split(separator, 1)
            info = json.loads(info_bin.decode("utf-8"))
            file_info_list = info.get("files", [])
            is_encrypted = info.get("encrypted", False)
            
            if is_encrypted:
                if not password:
                    log = self._record_log("错误：压缩包已加密，需要密码解密", "error")
                    logs.append((log, "error"))
                    return None, logs
                try:
                    compressed_data = self._decrypt_data(compressed_data, password)
                except ValueError as e:
                    log = self._record_log(str(e), "error")
                    logs.append((log, "error"))
                    return None, logs
            
            # 查找目标文件信息
            target_file = None
            for fi in file_info_list:
                if fi.get("relative_path") == relative_path:
                    target_file = fi
                    break
            
            if not target_file:
                log = self._record_log(f"错误：压缩包中未找到文件 → {relative_path}", "error")
                logs.append((log, "error"))
                return None, logs
            
            # 解压整个压缩包数据
            try:
                raw = zlib.decompress(compressed_data)
            except Exception as e:
                log = self._record_log(f"解压失败：{e}", "error")
                logs.append((log, "error"))
                return None, logs
            
            # 计算目标文件在解压数据中的位置
            offset = 0
            for fi in file_info_list:
                if fi.get("relative_path") == relative_path:
                    break
                offset += fi.get("file_size", 0)
            
            # 提取目标文件内容
            size = target_file.get("file_size", 0)
            content = raw[offset: offset + size]
            log = self._record_log(f"已提取文件内容 → {relative_path}", "info")
            logs.append((log, "info"))
            return content, logs
            
        except Exception as e:
            log = self._record_log(f"提取文件内容失败：{e}", "error")
            logs.append((log, "error"))
            return None, logs
            
    def search_in_archive(self, archive_path, search_text, password=None):
        """
        在压缩包内搜索文件内容
        返回 (results, logs)，results为匹配的文件列表，每个元素包含(relative_path, match_positions)
        """
        logs = []
        results = []
        try:
            if not os.path.exists(archive_path):
                log = self._record_log(f"错误：压缩包不存在 → {archive_path}", "error")
                logs.append((log, "error"))
                return None, logs
            
            # 读取压缩包信息
            file_info_list, read_logs, is_encrypted = self.read_archive_info(archive_path)
            logs.extend(read_logs)
            
            if not file_info_list:
                log = self._record_log("错误：压缩包内无文件", "error")
                logs.append((log, "error"))
                return None, logs
            
            # 过滤出文本文件（根据扩展名）
            text_extensions = ['.txt', '.py', '.java', '.c', '.cpp', '.h', '.hpp', '.js', '.html', '.css', '.json', '.xml', '.md', '.ini', '.cfg', '.conf', '.log']
            text_files = []
            for fi in file_info_list:
                rel_path = fi.get("relative_path")
                if rel_path and os.path.splitext(rel_path)[1].lower() in text_extensions:
                    text_files.append(fi)
            
            if not text_files:
                log = self._record_log("未找到可搜索的文本文件", "info")
                logs.append((log, "info"))
                return [], logs
            
            log = self._record_log(f"开始搜索，共 {len(text_files)} 个文本文件", "info")
            logs.append((log, "info"))
            
            # 解压整个压缩包数据（比单个文件逐个解压更高效）
            with open(archive_path, "rb") as f:
                all_data = f.read()
            
            separator = b"###CUSTOM_COMPRESS_SEPARATOR###"
            info_bin, compressed_data = all_data.split(separator, 1)
            
            if is_encrypted:
                if not password:
                    log = self._record_log("错误：压缩包已加密，需要密码解密", "error")
                    logs.append((log, "error"))
                    return None, logs
                try:
                    compressed_data = self._decrypt_data(compressed_data, password)
                except ValueError as e:
                    log = self._record_log(str(e), "error")
                    logs.append((log, "error"))
                    return None, logs
            
            try:
                raw = zlib.decompress(compressed_data)
            except Exception as e:
                log = self._record_log(f"解压失败：{e}", "error")
                logs.append((log, "error"))
                return None, logs
            
            # 遍历所有文本文件，搜索内容
            offset = 0
            search_bytes = search_text.encode('utf-8', errors='ignore')
            
            for fi in file_info_list:
                rel_path = fi.get("relative_path")
                size = fi.get("file_size", 0)
                
                # 只处理文本文件
                if rel_path and os.path.splitext(rel_path)[1].lower() in text_extensions:
                    # 提取文件内容
                    content = raw[offset: offset + size]
                    
                    # 搜索文本
                    match_positions = []
                    start_pos = 0
                    while True:
                        pos = content.find(search_bytes, start_pos)
                        if pos == -1:
                            break
                        match_positions.append(pos)
                        start_pos = pos + len(search_bytes)
                    
                    # 如果有匹配，添加到结果
                    if match_positions:
                        results.append((rel_path, match_positions))
                
                offset += size
            
            log = self._record_log(f"搜索完成，共找到 {len(results)} 个匹配的文件", "info")
            logs.append((log, "info"))
            return results, logs
            
        except Exception as e:
            log = self._record_log(f"搜索失败：{e}", "error")
            logs.append((log, "error"))
            return None, logs
        except Exception as e:
             log = self._record_log(f"读取压缩包信息失败：{e}", "error")
             logs.append((log, "error"))
             return None, logs
                
    def _smart_compression_analysis(self, targets):
        """
        根据文件类型智能分析并推荐最佳压缩算法和级别
        """
        # 文件类型映射表：{文件扩展名: (推荐算法, 推荐级别)}
        # 基于各种文件类型的压缩特性优化
        FILE_TYPE_MAP = {
            # 文档类
            '.txt': ('lzma', 7),
            '.csv': ('lzma', 7),
            '.xml': ('lzma', 7),
            '.json': ('lzma', 7),
            '.html': ('lzma', 6),
            '.css': ('lzma', 6),
            '.js': ('lzma', 6),
            
            # 图片类
            '.jpg': ('zlib', 3),
            '.jpeg': ('zlib', 3),
            '.png': ('zlib', 3),
            '.gif': ('zlib', 3),
            '.bmp': ('lzma', 8),
            '.webp': ('zlib', 2),
            
            # 音频类
            '.mp3': ('zlib', 2),
            '.wav': ('lzma', 8),
            '.flac': ('zlib', 1),
            '.ogg': ('zlib', 1),
            
            # 视频类
            '.mp4': ('zlib', 1),
            '.avi': ('zlib', 2),
            '.mkv': ('zlib', 1),
            '.flv': ('zlib', 1),
            
            # 压缩包类
            '.zip': ('zlib', 2),
            '.rar': ('zlib', 1),
            '.7z': ('zlib', 1),
            '.tar': ('lzma', 9),
            '.gz': ('zlib', 2),
            
            # 程序文件类
            '.exe': ('zlib', 2),
            '.dll': ('zlib', 2),
            '.bin': ('zlib', 2),
            '.pyc': ('zlib', 3),
            
            # 其他
            '.pdf': ('lzma', 6),
            '.doc': ('lzma', 7),
            '.docx': ('lzma', 6),
            '.xls': ('lzma', 7),
            '.xlsx': ('lzma', 6),
            '.ppt': ('lzma', 7),
            '.pptx': ('lzma', 6),
        }
        
        # 统计不同文件类型的大小
        type_stats = {}
        for target in targets:
            if os.path.isfile(target):
                ext = os.path.splitext(target)[1].lower()
                size = os.path.getsize(target)
                type_stats[ext] = type_stats.get(ext, 0) + size
            else:
                for root, _, files in os.walk(target):
                    for file in files:
                        file_path = os.path.join(root, file)
                        ext = os.path.splitext(file)[1].lower()
                        size = os.path.getsize(file_path)
                        type_stats[ext] = type_stats.get(ext, 0) + size
        
        # 找出占比最大的文件类型
        if not type_stats:
            return None, None
            
        max_ext = max(type_stats, key=type_stats.get)
        
        # 返回推荐的算法和级别
        if max_ext in FILE_TYPE_MAP:
            return FILE_TYPE_MAP[max_ext]
        else:
            # 默认使用lzma算法，级别6
            return 'lzma', 6

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
        temp_files = []  # 跟踪临时文件
        files_created = []  # 跟踪创建的文件
        original_files = []  # 跟踪原始文件（用于回滚）
        try:
            # 1. 检查压缩包文件的权限
            if not check_file_permissions(archive_path):
                log = self._record_log(f"权限不足：无法读取压缩包 {archive_path}", "error")
                logs.append((log, "error"))
                return False, logs
            
            # 2. 检查压缩包文件是否被占用
            if check_file_in_use(archive_path):
                log = self._record_log(f"文件被占用：压缩包 {archive_path} 正在被其他程序使用", "error")
                logs.append((log, "error"))
                return False, logs
            
            if not os.path.exists(archive_path):
                log = self._record_log(f"错误：压缩包不存在 → {archive_path}", "error")
                logs.append((log, "error"))
                return False, logs
            
            # 备份原始压缩包
            backup_path = f"{archive_path}.bak"
            shutil.copy2(archive_path, backup_path)
            original_files.append(backup_path)
            temp_files.append(backup_path)

            # 解出当前包到临时目录
            temp_files.append(temp_dir)
            ok, dl_logs = self.decompress(archive_path, temp_dir, password)
            logs.extend(dl_logs)
            if not ok:
                # 回滚操作
                self._rollback(temp_files, files_created, logs)
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
                # 删除备份文件
                if os.path.exists(backup_path):
                    try:
                        os.remove(backup_path)
                        original_files.remove(backup_path)
                    except Exception as e:
                        self._record_log(f"删除备份文件失败: {e}", "warning")
                return True, logs
            else:
                log = self._record_log("重新打包失败，修改未保存", "error")
                logs.append((log, "error"))
                # 回滚操作：恢复原始压缩包
                if os.path.exists(backup_path):
                    try:
                        shutil.copy2(backup_path, archive_path)
                        log = self._record_log(f"已回滚压缩包 → {archive_path}", "info")
                        logs.append((log, "info"))
                    except Exception as e:
                        log = self._record_log(f"回滚压缩包失败: {e}", "error")
                        logs.append((log, "error"))
                return False, logs

        except Exception as e:
            log = self._record_log(f"修改压缩包失败：{e}", "error")
            logs.append((log, "error"))
            
            # 回滚操作
            self._rollback(temp_files, files_created, logs)
            
            # 恢复原始压缩包
            if os.path.exists(backup_path):
                try:
                    shutil.copy2(backup_path, archive_path)
                    log = self._record_log(f"已回滚压缩包 → {archive_path}", "info")
                    logs.append((log, "info"))
                except Exception as backup_e:
                    log = self._record_log(f"回滚压缩包失败: {backup_e}", "error")
                    logs.append((log, "error"))
            return False, logs
        finally:
            # 清理临时文件
            for temp_file in temp_files:
                if os.path.exists(temp_file):
                    try:
                        if os.path.isdir(temp_file):
                            shutil.rmtree(temp_file)
                        else:
                            os.remove(temp_file)
                    except Exception as e:
                        self._record_log(f"清理临时文件失败: {temp_file} -> {e}", "warning")

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
    """
    加载配置文件，首先从注册表（仅Windows）读取，然后从配置文件读取
    
    返回:
        dict: 完整的配置字典
    """
    config = DEFAULT_CONFIG.copy()
    
    try:
        # 1. 优先从注册表读取配置（仅Windows平台）
        if platform.system() == "Windows":
            # 从注册表读取基本配置项
            registry_config = {}
            compression_level = read_registry("DefaultCompressionLevel", str(config["compression_level"]))
            registry_config["compression_level"] = int(compression_level) if compression_level else config["compression_level"]
            registry_config["theme"] = read_registry("Theme", config["theme"])
            registry_config["language"] = read_registry("Language", config["language"])
            first_launch_str = read_registry("FirstLaunch", str(config["first_launch"]))
            registry_config["first_launch"] = first_launch_str.lower() == "true" if first_launch_str else config["first_launch"]
            
            # 更新配置
            for k, v in registry_config.items():
                if v is not None:
                    config[k] = v
        
        # 2. 从配置文件读取配置（补充注册表未包含的项）
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                file_config = json.load(f)
                # 合并配置文件项
                for k, v in file_config.items():
                    config[k] = v
        
        # 合并默认项（确保所有配置项都存在）
        for k, v in DEFAULT_CONFIG.items():
            if k not in config:
                config[k] = v
        
        # 检查配置完整性
        if not check_config_integrity(config):
            print("配置文件不完整或损坏，尝试修复...")
            repair_config_file()
            return DEFAULT_CONFIG.copy()
        
        return config
    except Exception as e:
        print(f"加载配置失败：{e}")
        print("尝试修复配置文件...")
        repair_config_file()
        return DEFAULT_CONFIG.copy()


def save_config(config):
    """
    保存配置到注册表（仅Windows）和配置文件
    
    参数:
        config: 要保存的配置字典
    """
    try:
        # 确保配置字典完整
        full_config = DEFAULT_CONFIG.copy()
        full_config.update(config)
        
        # 1. 保存配置到注册表（仅Windows平台，保存基本配置项）
        if platform.system() == "Windows":
            write_registry("DefaultCompressionLevel", str(full_config.get("compression_level", 6)))
            write_registry("Theme", full_config.get("theme", "system"))
            write_registry("Language", full_config.get("language", "zh"))
            write_registry("FirstLaunch", str(full_config.get("first_launch", True)))
        
        # 2. 保存完整配置到配置文件
        # 确保配置文件目录存在
        config_dir = os.path.dirname(CONFIG_FILE)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)  # 使用exist_ok参数避免重复创建目录
        
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(full_config, f, ensure_ascii=False, indent=2)
            
        return True
    except Exception as e:
        print(f"保存配置失败：{e}")
        return False