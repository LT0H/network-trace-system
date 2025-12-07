#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
数据包捕获模块
"""

import os
import sys
import subprocess
import logging
import time
from datetime import datetime
from threading import Thread, Event

from utils.common import ensure_dir_exists, generate_unique_id

class PacketCapture:
    """
    数据包捕获类，用于调用dumpcap.exe捕获网络数据包
    """
    
    def __init__(self, dumpcap_path, output_dir):
        """
        初始化PacketCapture实例
        
        Args:
            dumpcap_path (str): dumpcap.exe的路径
            output_dir (str): 捕获文件的输出目录
        """
        self.logger = logging.getLogger(__name__)
        self.dumpcap_path = dumpcap_path
        self.output_dir = output_dir
        self.process = None
        self.capture_thread = None
        self.stop_event = Event()
        self.capture_file = None
        
        # 确保输出目录存在
        ensure_dir_exists(self.output_dir)
        
        # 检查dumpcap是否存在
        if not os.path.exists(self.dumpcap_path):
            self.logger.error(f"dumpcap.exe不存在: {self.dumpcap_path}")
            raise FileNotFoundError(f"dumpcap.exe不存在: {self.dumpcap_path}")
    
    def list_interfaces(self):
        """
        列出所有可用的网络接口
        
        Returns:
            list: 网络接口列表
        """
        try:
            # 检查dumpcap路径是否存在
            if not os.path.exists(self.dumpcap_path):
                error_msg = f"dumpcap.exe不存在: {self.dumpcap_path}"
                self.logger.error(error_msg)
                raise FileNotFoundError(error_msg)
            
            # 调用dumpcap -D列出所有接口
            cmd = [self.dumpcap_path, "-D"]
            self.logger.debug(f"执行命令: {' '.join(cmd)}")
            
            try:
                # 使用二进制模式运行，避免编码问题
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=False,  # 二进制模式
                    check=True,
                    timeout=10  # 增加超时时间
                )
            except subprocess.TimeoutExpired:
                self.logger.error("列出接口超时，请检查dumpcap是否正常工作")
                raise RuntimeError("列出接口超时，请检查dumpcap是否正常工作")
            
            # 尝试多种编码解码输出
            stdout = None
            for encoding in ['utf-8', 'gbk', 'latin-1']:
                try:
                    stdout = result.stdout.decode(encoding)
                    self.logger.debug(f"使用编码 {encoding} 成功解码输出")
                    break
                except UnicodeDecodeError:
                    self.logger.debug(f"使用编码 {encoding} 解码失败")
                    continue
            
            if not stdout:
                self.logger.error("无法解码接口列表输出")
                self.logger.debug(f"原始输出(十六进制): {result.stdout.hex()[:200]}...")
                raise RuntimeError("无法解码dumpcap输出，请检查系统编码设置")
            
            # 解析输出
            interfaces = []
            for line in stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split('. ', 1)
                    if len(parts) == 2:
                        interface_id = parts[0].strip()
                        interface_name = parts[1].strip()
                        interfaces.append({
                            'id': interface_id,
                            'name': interface_name
                        })
            
            self.logger.info(f"发现{len(interfaces)}个网络接口: {[i['name'] for i in interfaces]}")
            return interfaces
            
        except subprocess.CalledProcessError as e:
            # 尝试获取错误信息
            stderr = None
            for encoding in ['utf-8', 'gbk', 'latin-1']:
                try:
                    stderr = e.stderr.decode(encoding)
                    break
                except (UnicodeDecodeError, AttributeError):
                    continue
            
            if not stderr and e.stderr:
                stderr = f"无法解码(十六进制): {e.stderr.hex()[:200]}..."
            
            self.logger.error(f"列出网络接口失败: {e}，错误信息: {stderr}")
            raise RuntimeError(f"列出网络接口失败，请检查dumpcap是否正确安装并具有足够权限: {stderr}")
        except PermissionError as e:
            self.logger.error(f"权限错误: {e}，请以管理员权限运行程序")
            raise RuntimeError(f"权限不足，请以管理员权限运行程序: {e}")
        except Exception as e:
            self.logger.error(f"列出网络接口时发生错误: {e}")
            raise
    
    def start_capture(self, interface, duration=None, filter_expr=None, output_file=None):
        """
        开始捕获数据包
        
        Args:
            interface (str): 网络接口名称或ID
            duration (int): 捕获时长（秒），None表示无限期捕获
            filter_expr (str): 捕获过滤器表达式
            output_file (str): 输出文件名，None表示自动生成
            
        Returns:
            str: 捕获文件的路径
        """
        try:
            # 检查dumpcap路径是否存在
            if not os.path.exists(self.dumpcap_path):
                error_msg = f"dumpcap.exe不存在: {self.dumpcap_path}"
                self.logger.error(error_msg)
                raise FileNotFoundError(error_msg)
            
            # 检查输出目录是否存在
            if not os.path.exists(self.output_dir):
                error_msg = f"输出目录不存在: {self.output_dir}"
                self.logger.error(error_msg)
                raise FileNotFoundError(error_msg)
            
            # 检查接口是否有效
            try:
                interfaces = self.list_interfaces()
                interface_exists = any(
                    i['name'] == interface or i['id'] == interface 
                    for i in interfaces
                )
                if not interface_exists:
                    self.logger.warning(f"接口 '{interface}' 可能不存在，尝试继续...")
                    self.logger.info(f"可用接口列表: {[i['name'] for i in interfaces]}")
            except Exception as e:
                self.logger.warning(f"无法列出接口: {e}，尝试继续...")
            
            # 生成输出文件名
            if not output_file:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                unique_id = generate_unique_id(length=4)
                output_file = os.path.join(
                    self.output_dir, 
                    f'capture_{timestamp}_{unique_id}.pcap'
                )
            
            self.capture_file = output_file
            
            # 构建命令行参数
            cmd = [
                self.dumpcap_path,
                "-i", interface,
                "-w", output_file,
                "-q"  # 安静模式，减少输出
            ]
            
            # 添加过滤器（如果有）
            if filter_expr:
                cmd.extend(["-f", filter_expr])
            
            self.logger.info(f"开始捕获数据包: 接口={interface}, 输出={output_file}")
            self.logger.debug(f"执行命令: {' '.join(cmd)}")
            
            # 重置停止事件
            self.stop_event.clear()
            
            # 启动捕获线程
            self.capture_thread = Thread(
                target=self._capture_process,
                args=(cmd, duration)
            )
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            # 等待一段时间确保进程已启动
            time.sleep(2)  # 增加等待时间
            
            # 检查进程是否成功启动
            if self.process is None:
                error_msg = "无法启动dumpcap进程（进程对象为None）"
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            if self.process.poll() is not None:
                # 尝试获取错误信息
                stderr = ""
                if self.process.stderr:
                    stderr = self.process.stderr.read()
                
                error_msg = f"无法启动dumpcap进程，退出码: {self.process.returncode}，错误信息: {stderr}"
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            self.logger.info("数据包捕获已开始")
            
            # 如果指定了时长，则等待捕获完成
            if duration:
                self.capture_thread.join()
                self.logger.info(f"捕获完成，时长: {duration}秒")
            
            return output_file
            
        except FileNotFoundError as e:
            self.logger.error(f"文件不存在错误: {e}")
            raise
        except PermissionError as e:
            self.logger.error(f"权限错误: {e}，请以管理员权限运行程序")
            raise RuntimeError(f"权限不足，请以管理员权限运行程序: {e}")
        except Exception as e:
            self.logger.error(f"启动捕获失败: {e}")
            self.stop_capture()
            raise
    
    def _capture_process(self, cmd, duration):
        """
        捕获进程的内部方法
        
        Args:
            cmd (list): 命令行参数列表
            duration (int): 捕获时长（秒）
        """
        try:
            self.logger.debug(f"在捕获线程中执行命令: {' '.join(cmd)}")
            
            # 启动dumpcap进程（使用二进制模式避免编码问题）
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,  # 二进制模式
                creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == 'win32' else 0
            )
            
            self.logger.debug(f"dumpcap进程已启动，PID: {self.process.pid}")
            
            # 实时读取错误输出（用于调试）
            def read_stderr():
                if self.process.stderr:
                    buffer = b''
                    while True:
                        try:
                            chunk = self.process.stderr.read(1024)
                            if not chunk:
                                break
                            
                            buffer += chunk
                            
                            # 尝试解码缓冲区内容
                            for encoding in ['utf-8', 'gbk', 'latin-1']:
                                try:
                                    lines = buffer.split(b'\n')
                                    for i, line in enumerate(lines[:-1]):  # 不处理最后一行（可能不完整）
                                        if line.strip():
                                            decoded_line = line.decode(encoding).strip()
                                            self.logger.debug(f"dumpcap stderr: {decoded_line}")
                                    
                                    # 更新缓冲区（只保留最后一行）
                                    buffer = lines[-1]
                                    break
                                except UnicodeDecodeError:
                                    continue
                            
                        except Exception as e:
                            self.logger.error(f"读取错误输出时发生错误: {e}")
                            break
            
            # 启动错误读取线程
            stderr_thread = Thread(target=read_stderr)
            stderr_thread.daemon = True
            stderr_thread.start()
            
            # 如果指定了时长，则在指定时间后停止
            if duration:
                self.stop_event.wait(duration)
                self.stop_capture()
            else:
                # 否则等待停止信号
                self.stop_event.wait()
            
        except FileNotFoundError as e:
            self.logger.error(f"找不到dumpcap.exe: {e}")
        except PermissionError as e:
            self.logger.error(f"权限错误: {e}，请以管理员权限运行程序")
        except Exception as e:
            self.logger.error(f"捕获进程发生错误: {e}")
            # 尝试获取更多错误信息
            if self.process and self.process.stderr:
                try:
                    stderr_data = self.process.stderr.read()
                    # 尝试多种编码解码
                    for encoding in ['utf-8', 'gbk', 'latin-1']:
                        try:
                            stderr = stderr_data.decode(encoding)
                            self.logger.error(f"dumpcap错误输出: {stderr}")
                            break
                        except UnicodeDecodeError:
                            continue
                except:
                    pass
        finally:
            self.stop_capture()
    
    def stop_capture(self):
        """
        停止捕获数据包
        """
        if self.process is not None and self.process.poll() is None:
            self.logger.info("停止数据包捕获")
            
            # 设置停止事件
            self.stop_event.set()
            
            # 尝试优雅地终止进程
            try:
                # 发送Ctrl+C信号
                self.process.send_signal(subprocess.signal.SIGINT)
                
                # 等待进程终止
                self.process.wait(timeout=5)
                
            except subprocess.TimeoutExpired:
                self.logger.warning("dumpcap进程未在超时时间内终止，强制终止")
                self.process.kill()
            
            finally:
                # 读取剩余的输出（如果有）
                if self.process.stdout:
                    stdout = self.process.stdout.read()
                    if stdout:
                        self.logger.debug(f"dumpcap stdout: {stdout}")
                
                if self.process.stderr:
                    stderr = self.process.stderr.read()
                    if stderr:
                        self.logger.debug(f"dumpcap stderr: {stderr}")
                
                # 清理进程
                self.process = None
        
        # 等待线程结束
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
    
    def get_capture_file(self):
        """
        获取当前捕获文件的路径
        
        Returns:
            str: 捕获文件的路径，None表示没有正在进行的捕获
        """
        return self.capture_file
    
    def is_capturing(self):
        """
        检查是否正在捕获数据包
        
        Returns:
            bool: 是否正在捕获
        """
        return (self.process is not None and 
                self.process.poll() is None and 
                self.capture_thread is not None and 
                self.capture_thread.is_alive())
    
    def get_capture_statistics(self):
        """
        获取捕获统计信息
        
        Returns:
            dict: 捕获统计信息
        """
        # 这个功能需要dumpcap支持，可能需要通过其他方式实现
        # 这里只是一个示例实现
        return {
            'is_capturing': self.is_capturing(),
            'capture_file': self.capture_file,
            'interface': None,  # 需要在start_capture时保存
            'start_time': None,  # 需要在start_capture时保存
            'packets': None,     # 需要通过其他方式获取
            'bytes': None        # 需要通过其他方式获取
        }
    
    def __del__(self):
        """
        析构函数，确保捕获进程被终止
        """
        self.stop_capture()