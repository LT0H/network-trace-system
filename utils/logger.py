#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
日志工具模块
"""

import logging
from logging.handlers import RotatingFileHandler
import sys
import os

def setup_logger(log_file, log_level='INFO'):
    """
    设置日志系统
    
    Args:
        log_file (str): 日志文件路径
        log_level (str): 日志级别，默认为INFO
        
    Returns:
        logging.Logger: 根日志记录器
    """
    # 创建根日志记录器
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # 清除现有的处理器
    logger.handlers.clear()
    
    # 创建格式化器
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 创建文件处理器
    try:
        # 确保日志目录存在
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # 创建RotatingFileHandler，支持日志轮转
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"无法创建日志文件: {e}", file=sys.stderr)
    
    # 创建控制台处理器
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

def get_logger(name):
    """
    获取指定名称的日志记录器
    
    Args:
        name (str): 日志记录器名称
        
    Returns:
        logging.Logger: 指定名称的日志记录器
    """
    return logging.getLogger(name)