#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
流量分析模块
"""

import os
import sys
import subprocess
import logging
import json
import time
from datetime import datetime
from threading import Thread, Event

from utils.common import ensure_dir_exists

class TrafficAnalyzer:
    """
    流量分析类，用于调用ws-traffic-analyze-kit分析网络流量
    """
    
    def __init__(self, analyzer_path):
        """
        初始化TrafficAnalyzer实例
        
        Args:
            analyzer_path (str): ws-traffic-analyze-kit可执行文件的路径
        """
        self.logger = logging.getLogger(__name__)
        self.analyzer_path = analyzer_path
        self.process = None
        self.analyze_thread = None
        self.stop_event = Event()
        
        # 检查分析器是否存在
        if not os.path.exists(self.analyzer_path):
            self.logger.error(f"流量分析器不存在: {self.analyzer_path}")
            raise FileNotFoundError(f"流量分析器不存在: {self.analyzer_path}")
    
    def analyze(self, pcap_file, output_format="json", timeout=None):
        """
        分析数据包文件
        
        Args:
            pcap_file (str): pcap文件路径
            output_format (str): 输出格式，支持json、text等
            timeout (int): 超时时间（秒），None表示不超时
            
        Returns:
            dict or str: 分析结果，根据output_format返回不同格式
        """
        try:
            # 检查pcap文件是否存在
            if not os.path.exists(pcap_file):
                raise FileNotFoundError(f"PCAP文件不存在: {pcap_file}")
            
            self.logger.info(f"开始分析数据包文件: {pcap_file}")
            
            # 构建命令行参数
            cmd = [
                self.analyzer_path,
                "-i", pcap_file
            ]
            
            # 根据输出格式添加参数
            if output_format == "json":
                cmd.append("--json")
            
            self.logger.debug(f"执行命令: {' '.join(cmd)}")
            
            # 重置停止事件
            self.stop_event.clear()
            
            # 启动分析线程
            result = [None]
            exception = [None]
            
            self.analyze_thread = Thread(
                target=self._analyze_process,
                args=(cmd, result, exception)
            )
            self.analyze_thread.daemon = True
            self.analyze_thread.start()
            
            # 等待分析完成或超时
            self.analyze_thread.join(timeout)
            
            # 检查是否超时
            if self.analyze_thread.is_alive():
                self.logger.warning("分析超时，正在停止...")
                self.stop_analysis()
                raise TimeoutError(f"分析超时: {timeout}秒")
            
            # 检查是否发生异常
            if exception[0]:
                raise exception[0]
            
            # 返回结果
            if output_format == "json":
                # 解析JSON结果
                try:
                    return json.loads(result[0])
                except json.JSONDecodeError as e:
                    self.logger.error(f"解析JSON结果失败: {e}")
                    self.logger.debug(f"原始输出: {result[0]}")
                    raise
            else:
                # 返回原始文本结果
                return result[0]
                
        except Exception as e:
            self.logger.error(f"分析数据包失败: {e}")
            self.stop_analysis()
            raise
    
    def _analyze_process(self, cmd, result_container, exception_container):
        """
        分析进程的内部方法
        
        Args:
            cmd (list): 命令行参数列表
            result_container (list): 用于存储结果的列表
            exception_container (list): 用于存储异常的列表
        """
        try:
            # 启动分析进程
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # 读取输出
            stdout, stderr = self.process.communicate()
            
            # 检查进程是否成功执行
            if self.process.returncode != 0:
                error_msg = f"分析进程返回错误代码: {self.process.returncode}"
                self.logger.error(error_msg)
                self.logger.debug(f"标准错误: {stderr}")
                raise RuntimeError(f"{error_msg}\n{stderr}")
            
            # 存储结果
            result_container[0] = stdout
            
            # 记录标准错误（如果有）
            if stderr:
                self.logger.debug(f"分析器标准错误: {stderr}")
            
            self.logger.info("数据包分析已完成")
            
        except Exception as e:
            self.logger.error(f"分析进程发生错误: {e}")
            exception_container[0] = e
        finally:
            # 清理进程
            self.process = None
    
    def stop_analysis(self):
        """
        停止分析
        """
        if self.process is not None and self.process.poll() is None:
            self.logger.info("停止数据包分析")
            
            # 设置停止事件
            self.stop_event.set()
            
            # 尝试终止进程
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.logger.warning("分析进程未在超时时间内终止，强制终止")
                self.process.kill()
            
            # 清理进程
            self.process = None
        
        # 等待线程结束
        if self.analyze_thread and self.analyze_thread.is_alive():
            self.analyze_thread.join(timeout=2)
    
    def get_supported_formats(self):
        """
        获取支持的输出格式
        
        Returns:
            list: 支持的输出格式列表
        """
        # 这是一个示例实现，实际应根据ws-traffic-analyze-kit的支持情况调整
        return ["json", "text", "csv"]
    
    def get_version(self):
        """
        获取分析器版本信息
        
        Returns:
            str: 版本信息
        """
        try:
            # 尝试获取版本信息
            cmd = [self.analyzer_path, "--version"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            return result.stdout.strip()
            
        except Exception as e:
            self.logger.error(f"获取版本信息失败: {e}")
            return "未知版本"
    
    def __del__(self):
        """
        析构函数，确保分析进程被终止
        """
        self.stop_analysis()