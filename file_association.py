#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
file_association.py - STZ文件类型关联工具模块
用于自动关联STZ文件类型到STZ压缩工具
"""
import os
import sys
import winreg
import ctypes
from typing import Tuple, Optional

# 检查是否以管理员权限运行
def is_admin() -> bool:
    """
    检查当前进程是否以管理员权限运行
    返回:
        布尔值，表示是否以管理员权限运行
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# 获取应用程序路径和图标路径
def get_app_paths() -> Tuple[str, str, str]:
    """
    获取应用程序路径、可执行文件路径和图标路径
    返回:
        (app_dir, exe_path, icon_path) 应用程序目录、可执行文件路径、图标路径
    """
    # 获取当前脚本所在目录
    app_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 查找可执行文件
    exe_candidates = [
        os.path.join(app_dir, "stz压缩.exe"),
        os.path.join(app_dir, "STZ压缩工具.exe"),
        os.path.join(app_dir, "main.exe")
    ]
    
    exe_path = None
    for candidate in exe_candidates:
        if os.path.exists(candidate):
            exe_path = candidate
            break
    
    # 如果没有找到可执行文件，使用Python脚本路径
    if not exe_path:
        exe_path = os.path.join(app_dir, "main.py")
    
    # 查找图标文件
    icon_candidates = [
        os.path.join(app_dir, "STZ.ico"),
        os.path.join(app_dir, "STC.ico")
    ]
    
    icon_path = None
    for candidate in icon_candidates:
        if os.path.exists(candidate):
            icon_path = candidate
            break
    
    return app_dir, exe_path, icon_path

# 关联STZ文件类型
def associate_stz_file_type() -> Tuple[bool, str]:
    """
    关联STZ文件类型到STZ压缩工具
    返回:
        (success, message) 成功标志和消息
    """
    try:
        if not is_admin():
            return False, "需要管理员权限才能修改文件关联"
        
        # 获取应用程序路径
        app_dir, exe_path, icon_path = get_app_paths()
        
        # 确定要使用的命令行
        if exe_path.endswith(".exe"):
            # 如果是可执行文件，直接使用
            command = f'"{exe_path}" "%1"'
        else:
            # 如果是Python脚本，使用Python解释器运行
            python_exe = sys.executable
            command = f'"{python_exe}" "{exe_path}" "%1"'
        
        # 定义注册表项
        stz_file_type = ".stz"
        stz_prog_id = "STZCompressor.stzfile"
        
        # 1. 创建文件类型关联
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, stz_file_type) as key:
            winreg.SetValue(key, "", winreg.REG_SZ, stz_prog_id)
        
        # 2. 创建程序标识符
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, stz_prog_id) as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "STZ压缩文件")
        
        # 3. 设置图标
        if icon_path:
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, f"{stz_prog_id}\\DefaultIcon") as key:
                winreg.SetValue(key, "", winreg.REG_SZ, icon_path)
        
        # 4. 设置打开命令
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, f"{stz_prog_id}\\shell\\open\\command") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, command)
        
        # 5. 添加到"打开方式"列表
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\{stz_file_type}\\OpenWithProgids") as key:
            winreg.SetValueEx(key, stz_prog_id, 0, winreg.REG_NONE, b"")
        
        return True, "STZ文件类型关联成功！"
        
    except Exception as e:
        return False, f"STZ文件类型关联失败: {str(e)}"

# 检查STZ文件类型是否已关联
def check_stz_association() -> Tuple[bool, str]:
    """
    检查STZ文件类型是否已关联到STZ压缩工具
    返回:
        (is_associated, message) 是否已关联和消息
    """
    try:
        stz_file_type = ".stz"
        stz_prog_id = "STZCompressor.stzfile"
        
        # 检查文件类型关联
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, stz_file_type) as key:
            prog_id = winreg.QueryValue(key, "")
            if prog_id != stz_prog_id:
                return False, f"STZ文件类型关联到了其他程序: {prog_id}"
        
        # 检查程序标识符
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, stz_prog_id) as key:
            file_type_name = winreg.QueryValue(key, "")
        
        # 检查打开命令
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f"{stz_prog_id}\\shell\\open\\command") as key:
            command = winreg.QueryValue(key, "")
        
        return True, f"STZ文件类型已关联: {file_type_name}\n打开命令: {command}"
        
    except FileNotFoundError:
        return False, "STZ文件类型未关联"
    except Exception as e:
        return False, f"检查STZ文件类型关联失败: {str(e)}"

# 移除STZ文件类型关联
def remove_stz_association() -> Tuple[bool, str]:
    """
    移除STZ文件类型关联
    返回:
        (success, message) 成功标志和消息
    """
    try:
        if not is_admin():
            return False, "需要管理员权限才能修改文件关联"
        
        stz_file_type = ".stz"
        stz_prog_id = "STZCompressor.stzfile"
        
        # 1. 删除程序标识符
        try:
            winreg.DeleteKeyTree(winreg.HKEY_CLASSES_ROOT, stz_prog_id)
        except FileNotFoundError:
            pass
        
        # 2. 删除文件类型关联
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, stz_file_type)
        except FileNotFoundError:
            pass
        
        # 3. 从"打开方式"列表中移除
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\{stz_file_type}\\OpenWithProgids", 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, stz_prog_id)
        except FileNotFoundError:
            pass
        except OSError:
            # 如果值不存在，忽略错误
            pass
        
        return True, "STZ文件类型关联已成功移除！"
        
    except Exception as e:
        return False, f"移除STZ文件类型关联失败: {str(e)}"

# 以管理员权限重新运行当前脚本
def run_as_admin() -> None:
    """
    以管理员权限重新运行当前脚本
    """
    script = os.path.abspath(__file__)
    params = ' '.join(sys.argv[1:])
    
    # 使用ShellExecute重新运行脚本
    ctypes.windll.shell32.ShellExecuteW(
        None,          # 父窗口句柄
        "runas",       # 操作类型
        sys.executable,# 要执行的程序
        f'"{script}" {params}',  # 命令行参数
        None,          # 工作目录
        1              # 显示窗口方式
    )

# 命令行界面
def main() -> None:
    """
    命令行界面入口
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="STZ文件类型关联工具")
    parser.add_argument("--associate", action="store_true", help="关联STZ文件类型")
    parser.add_argument("--check", action="store_true", help="检查STZ文件类型关联")
    parser.add_argument("--remove", action="store_true", help="移除STZ文件类型关联")
    
    args = parser.parse_args()
    
    if args.associate:
        if not is_admin():
            print("需要管理员权限，正在以管理员身份重新运行...")
            run_as_admin()
        else:
            success, message = associate_stz_file_type()
            print(message)
    
    elif args.check:
        success, message = check_stz_association()
        print(message)
    
    elif args.remove:
        if not is_admin():
            print("需要管理员权限，正在以管理员身份重新运行...")
            run_as_admin()
        else:
            success, message = remove_stz_association()
            print(message)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
