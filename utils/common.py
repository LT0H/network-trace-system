#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
通用工具模块
"""

import os
import sys
import json
import time
import random
import string
from datetime import datetime

def ensure_dir_exists(directory):
    """
    确保目录存在，如果不存在则创建
    
    Args:
        directory (str): 目录路径
    """
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
        except Exception as e:
            print(f"创建目录失败: {e}", file=sys.stderr)
            raise

def generate_unique_id(prefix='', length=8):
    """
    生成唯一ID
    
    Args:
        prefix (str): ID前缀
        length (int): 随机部分长度
        
    Returns:
        str: 唯一ID
    """
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{prefix}{timestamp}_{random_part}"

def format_bytes(bytes_value):
    """
    格式化字节数为人类可读的格式
    
    Args:
        bytes_value (int): 字节数
        
    Returns:
        str: 格式化后的字符串
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def format_duration(seconds):
    """
    格式化时间间隔为人类可读的格式
    
    Args:
        seconds (float): 秒数
        
    Returns:
        str: 格式化后的字符串
    """
    if seconds < 60:
        return f"{seconds:.2f} 秒"
    elif seconds < 3600:
        minutes, seconds = divmod(seconds, 60)
        return f"{int(minutes)} 分 {int(seconds)} 秒"
    elif seconds < 86400:
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours)} 时 {int(minutes)} 分 {int(seconds)} 秒"
    else:
        days, remainder = divmod(seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(days)} 天 {int(hours)} 时 {int(minutes)} 分 {int(seconds)} 秒"

def load_json_file(file_path):
    """
    加载JSON文件
    
    Args:
        file_path (str): JSON文件路径
        
    Returns:
        dict: 解析后的JSON数据
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"加载JSON文件失败: {e}", file=sys.stderr)
        raise

def save_json_file(data, file_path, indent=2):
    """
    保存数据为JSON文件
    
    Args:
        data: 要保存的数据
        file_path (str): JSON文件路径
        indent (int): 缩进空格数
    """
    try:
        # 确保目录存在
        ensure_dir_exists(os.path.dirname(file_path))
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
    except Exception as e:
        print(f"保存JSON文件失败: {e}", file=sys.stderr)
        raise

def validate_ip_address(ip):
    """
    验证IP地址格式
    
    Args:
        ip (str): IP地址字符串
        
    Returns:
        bool: 是否为有效的IP地址
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except ValueError:
        return False

def timestamp_to_datetime(timestamp):
    """
    将时间戳转换为datetime对象
    
    Args:
        timestamp (float): 时间戳
        
    Returns:
        datetime: datetime对象
    """
    return datetime.fromtimestamp(timestamp)

def datetime_to_timestamp(dt):
    """
    将datetime对象转换为时间戳
    
    Args:
        dt (datetime): datetime对象
        
    Returns:
        float: 时间戳
    """
    return dt.timestamp()

def run_with_timeout(func, timeout, *args, **kwargs):
    """
    在超时时间内运行函数
    
    Args:
        func: 要运行的函数
        timeout (float): 超时时间（秒）
        *args: 函数参数
        **kwargs: 函数关键字参数
        
    Returns:
        函数的返回值
        
    Raises:
        TimeoutError: 如果函数运行超时
    """
    import threading
    
    result = [None]
    exception = [None]
    
    def target():
        try:
            result[0] = func(*args, **kwargs)
        except Exception as e:
            exception[0] = e
    
    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout)
    
    if thread.is_alive():
        raise TimeoutError(f"函数执行超时: {timeout}秒")
    
    if exception[0]:
        raise exception[0]
    
    return result[0]