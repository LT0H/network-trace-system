#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络溯源工具诊断脚本
用于检查环境配置和排查常见问题
"""

import os
import sys
import subprocess
import json
import platform
from datetime import datetime

def print_header(title):
    """打印标题"""
    print("\n" + "=" * 60)
    print(f" {title} ".center(58))
    print("=" * 60)

def print_success(message):
    """打印成功消息"""
    print(f"[✓] {message}")

def print_error(message):
    """打印错误消息"""
    print(f"[✗] {message}")

def print_warning(message):
    """打印警告消息"""
    print(f"[!] {message}")

def print_info(message):
    """打印信息消息"""
    print(f"[i] {message}")

def check_python_version():
    """检查Python版本"""
    print_header("Python环境检查")
    
    version = sys.version
    major, minor = sys.version_info[:2]
    
    print_info(f"当前Python版本: {version.strip()}")
    
    if major >= 3 and minor >= 8:
        print_success("Python版本满足要求 (>= 3.8)")
        return True
    else:
        print_error(f"Python版本不满足要求，需要Python 3.8或更高版本")
        return False

def check_windows_admin():
    """检查是否以管理员权限运行（仅Windows）"""
    if platform.system() != 'Windows':
        return True
    
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin:
            print_success("当前以管理员权限运行")
        else:
            print_error("未以管理员权限运行，这可能导致某些功能无法正常工作")
        return is_admin
    except Exception as e:
        print_warning(f"无法检查管理员权限: {e}")
        return False

def check_wireshark_installation():
    """检查Wireshark安装"""
    print_header("Wireshark安装检查")
    
    # 检查常见的Wireshark安装路径
    common_paths = [
        "C:\\Program Files\\Wireshark\\dumpcap.exe",
        "C:\\Program Files (x86)\\Wireshark\\dumpcap.exe",
        "D:\\Program Files\\Wireshark\\dumpcap.exe",
        "D:\\Program Files (x86)\\Wireshark\\dumpcap.exe"
    ]
    
    found_paths = []
    for path in common_paths:
        if os.path.exists(path):
            found_paths.append(path)
    
    if found_paths:
        print_success(f"找到Wireshark安装:")
        for i, path in enumerate(found_paths, 1):
            print_info(f"  {i}. {path}")
        return found_paths[0]  # 返回第一个找到的路径
    else:
        print_error("未找到Wireshark安装")
        print_info("请确保已安装Wireshark，或在config.json中正确配置dumpcap路径")
        return None

def test_dumpcap_execution(dumpcap_path):
    """测试dumpcap执行"""
    if not dumpcap_path or not os.path.exists(dumpcap_path):
        print_error("dumpcap路径无效，无法测试执行")
        return False
    
    print_header("Dumpcap执行测试")
    print_info(f"测试路径: {dumpcap_path}")
    
    try:
        # 测试版本信息
        try:
            result = subprocess.run(
                [dumpcap_path, "-v"],
                capture_output=True,
                text=False,  # 使用二进制模式
                timeout=10
            )
            
            if result.returncode == 0:
                # 尝试多种编码解码
                stdout = None
                for encoding in ['utf-8', 'gbk', 'latin-1']:
                    try:
                        stdout = result.stdout.decode(encoding)
                        break
                    except UnicodeDecodeError:
                        continue
                
                if stdout:
                    print_success("dumpcap版本信息获取成功")
                    print_info(f"版本输出: {stdout.strip()}")
                else:
                    print_success("dumpcap版本信息获取成功，但无法解码输出")
                    print_info(f"原始输出(十六进制): {result.stdout.hex()[:100]}...")
            else:
                print_error(f"获取版本信息失败，返回码: {result.returncode}")
                # 尝试解码错误输出
                stderr = None
                for encoding in ['utf-8', 'gbk', 'latin-1']:
                    try:
                        stderr = result.stderr.decode(encoding)
                        break
                    except UnicodeDecodeError:
                        continue
                
                if stderr:
                    print_error(f"错误输出: {stderr.strip()}")
                else:
                    print_error(f"错误输出(十六进制): {result.stderr.hex()[:100]}...")
                return False
        except Exception as e:
            print_error(f"测试版本信息时发生错误: {e}")
            return False
        
        # 测试列出接口
        print_info("测试列出网络接口...")
        try:
            result = subprocess.run(
                [dumpcap_path, "-D"],
                capture_output=True,
                text=False,  # 使用二进制模式
                timeout=10
            )
            
            if result.returncode == 0:
                # 尝试多种编码解码
                stdout = None
                for encoding in ['utf-8', 'gbk', 'latin-1']:
                    try:
                        stdout = result.stdout.decode(encoding)
                        break
                    except UnicodeDecodeError:
                        continue
                
                if stdout:
                    interfaces = stdout.strip().split('\n')
                    print_success(f"成功列出{len(interfaces)}个网络接口")
                    for i, interface in enumerate(interfaces, 1):
                        print_info(f"  {i}. {interface.strip()}")
                    return True
                else:
                    print_error("无法解码接口列表输出")
                    print_info(f"原始输出(十六进制): {result.stdout.hex()[:100]}...")
                    return False
            else:
                print_error(f"列出接口失败，返回码: {result.returncode}")
                # 尝试解码错误输出
                stderr = None
                for encoding in ['utf-8', 'gbk', 'latin-1']:
                    try:
                        stderr = result.stderr.decode(encoding)
                        break
                    except UnicodeDecodeError:
                        continue
                
                if stderr:
                    print_error(f"错误输出: {stderr.strip()}")
                else:
                    print_error(f"错误输出(十六进制): {result.stderr.hex()[:100]}...")
                print_warning("这可能是由于权限不足导致的，请尝试以管理员权限运行")
                return False
        except Exception as e:
            print_error(f"执行dumpcap时发生错误: {e}")
            return False
            
    except subprocess.TimeoutExpired:
        print_error("执行dumpcap超时")
        return False
    except PermissionError as e:
        print_error(f"权限错误: {e}")
        print_warning("请尝试以管理员权限运行程序")
        return False
    except Exception as e:
        print_error(f"执行dumpcap时发生错误: {e}")
        return False

def check_config_file():
    """检查配置文件"""
    print_header("配置文件检查")
    
    config_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'config',
        'config.json'
    )
    
    if not os.path.exists(config_path):
        print_error(f"配置文件不存在: {config_path}")
        return None
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        print_success("配置文件读取成功")
        
        # 检查关键路径配置
        paths = config.get('paths', {})
        
        # 检查dumpcap路径
        dumpcap_path = paths.get('dumpcap')
        if dumpcap_path:
            if os.path.exists(dumpcap_path):
                print_success(f"dumpcap路径有效: {dumpcap_path}")
            else:
                print_error(f"dumpcap路径无效: {dumpcap_path}")
        else:
            print_error("配置文件中未设置dumpcap路径")
        
        # 检查输出目录
        output_dir = paths.get('output_dir')
        if output_dir:
            if os.path.exists(output_dir):
                print_success(f"输出目录存在: {output_dir}")
            else:
                print_warning(f"输出目录不存在: {output_dir}，程序将尝试创建")
        else:
            print_error("配置文件中未设置输出目录")
        
        # 检查分析器路径
        analyzer_path = paths.get('analyzer')
        if analyzer_path:
            if os.path.exists(analyzer_path):
                print_success(f"分析器路径有效: {analyzer_path}")
            else:
                print_warning(f"分析器路径可能无效: {analyzer_path}")
        else:
            print_warning("配置文件中未设置分析器路径")
        
        # 检查qqwry数据库路径
        qqwry_path = paths.get('qqwry')
        if qqwry_path:
            if os.path.exists(qqwry_path):
                print_success(f"qqwry数据库路径有效: {qqwry_path}")
            else:
                print_warning(f"qqwry数据库路径可能无效: {qqwry_path}")
        else:
            print_warning("配置文件中未设置qqwry数据库路径")
        
        return config
        
    except json.JSONDecodeError as e:
        print_error(f"配置文件格式错误: {e}")
        return None
    except Exception as e:
        print_error(f"读取配置文件时发生错误: {e}")
        return None

def check_directory_structure():
    """检查目录结构"""
    print_header("目录结构检查")
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 检查必要的目录
    required_dirs = [
        'config',
        'data',
        'data/catched_data',
        'data/tasks',
        'logs',
        'modules',
        'utils'
    ]
    
    all_exists = True
    for dir_name in required_dirs:
        dir_path = os.path.join(base_dir, dir_name)
        if os.path.exists(dir_path):
            print_success(f"目录存在: {dir_name}")
        else:
            print_error(f"目录不存在: {dir_name}")
            all_exists = False
    
    return all_exists

def check_required_packages():
    """检查必要的Python包"""
    print_header("Python包检查")
    
    required_packages = [
        'matplotlib',
        'networkx',
        'pyshark'
    ]
    
    installed_packages = []
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            installed_packages.append(package)
        except ImportError:
            missing_packages.append(package)
    
    if installed_packages:
        print_success(f"已安装的包: {', '.join(installed_packages)}")
    
    if missing_packages:
        print_error(f"缺少的包: {', '.join(missing_packages)}")
        print_info(f"请运行以下命令安装缺少的包:")
        print_info(f"pip install {' '.join(missing_packages)}")
    
    return len(missing_packages) == 0

def generate_fixed_config(dumpcap_path, output_dir=None):
    """生成修复后的配置文件"""
    if not dumpcap_path:
        print_error("无法生成配置文件，dumpcap路径无效")
        return False
    
    print_header("生成修复后的配置文件")
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, 'config', 'config.json')
    
    # 如果未指定输出目录，使用默认目录
    if not output_dir:
        output_dir = os.path.join(base_dir, 'data', 'catched_data')
    
    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)
    
    # 读取当前配置（如果存在）
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        else:
            config = {}
    except:
        config = {}
    
    # 更新路径配置
    if 'paths' not in config:
        config['paths'] = {}
    
    config['paths']['dumpcap'] = dumpcap_path
    config['paths']['output_dir'] = output_dir
    
    # 保存修复后的配置
    try:
        # 备份原配置（如果存在）
        if os.path.exists(config_path):
            backup_path = f"{config_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            with open(config_path, 'r', encoding='utf-8') as f:
                with open(backup_path, 'w', encoding='utf-8') as backup_f:
                    backup_f.write(f.read())
            print_info(f"已备份原配置文件: {backup_path}")
        
        # 保存新配置
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        print_success(f"已生成修复后的配置文件: {config_path}")
        print_info(f"dumpcap路径: {dumpcap_path}")
        print_info(f"输出目录: {output_dir}")
        return True
        
    except Exception as e:
        print_error(f"保存配置文件失败: {e}")
        return False

def main():
    """主函数"""
    print_header("网络溯源工具诊断")
    print_info(f"当前目录: {os.path.dirname(os.path.abspath(__file__))}")
    print_info(f"操作系统: {platform.system()} {platform.version()}")
    
    # 运行各项检查
    python_ok = check_python_version()
    is_admin = check_windows_admin() if platform.system() == 'Windows' else True
    wireshark_path = check_wireshark_installation()
    config = check_config_file()
    dirs_ok = check_directory_structure()
    packages_ok = check_required_packages()
    
    # 测试dumpcap执行
    dumpcap_path = None
    if config and 'paths' in config and 'dumpcap' in config['paths']:
        dumpcap_path = config['paths']['dumpcap']
    elif wireshark_path:
        dumpcap_path = wireshark_path
    
    dumpcap_ok = False
    if dumpcap_path:
        dumpcap_ok = test_dumpcap_execution(dumpcap_path)
    
    # 总结
    print_header("诊断总结")
    
    issues_found = []
    
    if not python_ok:
        issues_found.append("Python版本不满足要求")
    
    if not is_admin and platform.system() == 'Windows':
        issues_found.append("未以管理员权限运行")
    
    if not wireshark_path:
        issues_found.append("未找到Wireshark安装")
    
    if not dumpcap_ok and dumpcap_path:
        issues_found.append("dumpcap执行测试失败")
    
    if not dirs_ok:
        issues_found.append("目录结构不完整")
    
    if not packages_ok:
        issues_found.append("缺少必要的Python包")
    
    if issues_found:
        print_error(f"发现{len(issues_found)}个问题:")
        for i, issue in enumerate(issues_found, 1):
            print_error(f"  {i}. {issue}")
        
        # 提供修复建议
        print_header("修复建议")
        
        if not wireshark_path or not dumpcap_ok:
            print_info("1. 确保已安装Wireshark:")
            print_info("   - 从官网下载并安装最新版本: https://www.wireshark.org/download.html")
            print_info("   - 安装时确保选中'dumpcap'组件")
            print_info("   - 安装后重启计算机")
            
            if wireshark_path and not dumpcap_ok:
                print_info("\n2. 以管理员权限运行程序:")
                print_info("   - 在Windows上，右键点击程序并选择'以管理员身份运行'")
                print_info("   - 或使用管理员权限打开命令提示符/PowerShell")
        
        if not packages_ok:
            print_info("\n3. 安装缺少的Python包:")
            print_info("   - 运行: pip install matplotlib networkx pyshark")
        
        # 提供自动修复选项
        if (not config or not dumpcap_path or not os.path.exists(dumpcap_path)) and wireshark_path:
            print("\n是否生成修复后的配置文件？(y/n)")
            if input().lower() == 'y':
                generate_fixed_config(wireshark_path)
    
    else:
        print_success("未发现明显问题，程序应该可以正常运行")
        print_info("提示: 运行捕获功能时请确保以管理员权限运行")
    
    print("\n按Enter键退出...")
    input()

if __name__ == '__main__':
    main()