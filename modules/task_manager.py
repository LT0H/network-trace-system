#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
任务管理模块
"""

import os
import sys
import json
import logging
import threading
import time
from datetime import datetime
from queue import Queue, Empty

from utils.common import ensure_dir_exists, generate_unique_id, save_json_file, load_json_file

class TaskManager:
    """
    任务管理类，用于管理网络扫描任务
    """
    
    # 任务状态常量
    STATUS_PENDING = "pending"      # 等待中
    STATUS_RUNNING = "running"      # 运行中
    STATUS_COMPLETED = "completed"  # 已完成
    STATUS_FAILED = "failed"        # 失败
    STATUS_STOPPED = "stopped"      # 已停止
    
    def __init__(self, tasks_dir=None):
        """
        初始化TaskManager实例
        
        Args:
            tasks_dir (str): 任务数据保存目录
        """
        self.logger = logging.getLogger(__name__)
        self.tasks = {}
        self.task_id_counter = 0
        self.lock = threading.Lock()
        
        # 设置任务目录
        if tasks_dir:
            self.tasks_dir = tasks_dir
        else:
            self.tasks_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'data',
                'tasks'
            )
        
        # 确保任务目录存在
        ensure_dir_exists(self.tasks_dir)
        
        # 加载已保存的任务
        self._load_tasks()
        
        # 启动任务处理线程
        self.task_queue = Queue()
        self.stop_event = threading.Event()
        self.worker_thread = threading.Thread(target=self._worker_loop)
        self.worker_thread.daemon = True
        self.worker_thread.start()
        
        self.logger.info("任务管理器已初始化")
    
    def create_task(self, target, options=None):
        """
        创建新任务
        
        Args:
            target (str): 扫描目标（IP地址或域名）
            options (dict): 任务选项
            
        Returns:
            str: 任务ID
        """
        if not target:
            raise ValueError("目标不能为空")
        
        # 生成任务ID
        task_id = generate_unique_id('task_', 6)
        
        # 创建任务数据
        task_data = {
            'id': task_id,
            'target': target,
            'options': options or {},
            'status': self.STATUS_PENDING,
            'progress': 0,
            'created_at': datetime.now().isoformat(),
            'started_at': None,
            'completed_at': None,
            'results': None,
            'error': None
        }
        
        # 保存任务
        with self.lock:
            self.tasks[task_id] = task_data
            self._save_task(task_id)
        
        self.logger.info(f"创建任务: ID={task_id}, 目标={target}")
        
        return task_id
    
    def start_task(self, task_id):
        """
        启动任务
        
        Args:
            task_id (str): 任务ID
            
        Returns:
            str: 任务状态
        """
        with self.lock:
            if task_id not in self.tasks:
                raise ValueError(f"任务不存在: {task_id}")
            
            task = self.tasks[task_id]
            
            if task['status'] != self.STATUS_PENDING:
                raise ValueError(f"任务状态不允许启动: {task['status']}")
            
            # 更新任务状态
            task['status'] = self.STATUS_RUNNING
            task['started_at'] = datetime.now().isoformat()
            task['progress'] = 0
            
            # 保存任务
            self._save_task(task_id)
        
        # 将任务加入队列
        self.task_queue.put(task_id)
        
        self.logger.info(f"启动任务: ID={task_id}")
        
        return task['status']
    
    def stop_task(self, task_id):
        """
        停止任务
        
        Args:
            task_id (str): 任务ID
            
        Returns:
            str: 任务状态
        """
        with self.lock:
            if task_id not in self.tasks:
                raise ValueError(f"任务不存在: {task_id}")
            
            task = self.tasks[task_id]
            
            if task['status'] != self.STATUS_RUNNING:
                raise ValueError(f"任务未在运行: {task['status']}")
            
            # 更新任务状态
            task['status'] = self.STATUS_STOPPED
            task['completed_at'] = datetime.now().isoformat()
            
            # 保存任务
            self._save_task(task_id)
        
        self.logger.info(f"停止任务: ID={task_id}")
        
        return task['status']
    
    def track_task(self, task_id):
        """
        跟踪任务进度
        
        Args:
            task_id (str): 任务ID
            
        Returns:
            dict: 任务状态信息
        """
        with self.lock:
            if task_id not in self.tasks:
                raise ValueError(f"任务不存在: {task_id}")
            
            task = self.tasks[task_id]
            
            # 返回任务状态信息
            return {
                'id': task['id'],
                'status': task['status'],
                'progress': task['progress'],
                'target': task['target'],
                'created_at': task['created_at'],
                'started_at': task['started_at'],
                'completed_at': task['completed_at']
            }
    
    def get_results(self, task_id):
        """
        获取任务结果
        
        Args:
            task_id (str): 任务ID
            
        Returns:
            dict: 任务结果
        """
        with self.lock:
            if task_id not in self.tasks:
                raise ValueError(f"任务不存在: {task_id}")
            
            task = self.tasks[task_id]
            
            if task['status'] not in [self.STATUS_COMPLETED, self.STATUS_FAILED, self.STATUS_STOPPED]:
                raise ValueError(f"任务尚未完成: {task['status']}")
            
            # 返回任务结果
            return {
                'id': task['id'],
                'target': task['target'],
                'status': task['status'],
                'results': task['results'],
                'error': task['error'],
                'created_at': task['created_at'],
                'started_at': task['started_at'],
                'completed_at': task['completed_at']
            }
    
    def list_tasks(self, status=None):
        """
        列出所有任务
        
        Args:
            status (str): 按状态筛选任务
            
        Returns:
            list: 任务列表
        """
        with self.lock:
            tasks = list(self.tasks.values())
            
            # 按状态筛选
            if status:
                tasks = [t for t in tasks if t['status'] == status]
            
            # 按创建时间排序
            tasks.sort(key=lambda x: x['created_at'], reverse=True)
            
            return tasks
    
    def delete_task(self, task_id):
        """
        删除任务
        
        Args:
            task_id (str): 任务ID
            
        Returns:
            bool: 是否删除成功
        """
        with self.lock:
            if task_id not in self.tasks:
                raise ValueError(f"任务不存在: {task_id}")
            
            # 删除任务文件
            task_file = os.path.join(self.tasks_dir, f"{task_id}.json")
            if os.path.exists(task_file):
                os.remove(task_file)
            
            # 从内存中删除任务
            del self.tasks[task_id]
        
        self.logger.info(f"删除任务: ID={task_id}")
        
        return True
    
    def _worker_loop(self):
        """
        工作线程循环，处理任务队列
        """
        self.logger.info("任务工作线程已启动")
        
        while not self.stop_event.is_set():
            try:
                # 从队列获取任务
                task_id = self.task_queue.get(timeout=1)
                
                # 处理任务
                self._process_task(task_id)
                
                # 标记任务完成
                self.task_queue.task_done()
                
            except Empty:
                # 队列为空，继续等待
                continue
                
            except Exception as e:
                self.logger.error(f"处理任务队列时发生错误: {e}")
        
        self.logger.info("任务工作线程已停止")
    
    def _process_task(self, task_id):
        """
        处理单个任务
        
        Args:
            task_id (str): 任务ID
        """
        try:
            with self.lock:
                if task_id not in self.tasks:
                    self.logger.warning(f"任务不存在: {task_id}")
                    return
                
                task = self.tasks[task_id]
                
                if task['status'] != self.STATUS_RUNNING:
                    self.logger.warning(f"任务状态不是运行中: {task['status']}")
                    return
            
            # 模拟任务执行
            self._simulate_task_execution(task_id)
            
        except Exception as e:
            self.logger.error(f"处理任务时发生错误: ID={task_id}, 错误={e}")
            
            # 更新任务状态为失败
            with self.lock:
                if task_id in self.tasks:
                    task = self.tasks[task_id]
                    task['status'] = self.STATUS_FAILED
                    task['error'] = str(e)
                    task['completed_at'] = datetime.now().isoformat()
                    self._save_task(task_id)
    
    def _simulate_task_execution(self, task_id):
        """
        模拟任务执行过程
        
        Args:
            task_id (str): 任务ID
        """
        # 注意：这是一个模拟实现，实际应用中应该替换为真实的扫描逻辑
        # 这里我们模拟一个网络扫描任务，包括端口扫描、服务识别等步骤
        
        with self.lock:
            task = self.tasks[task_id]
            target = task['target']
            options = task['options']
        
        self.logger.info(f"开始执行任务: ID={task_id}, 目标={target}")
        
        # 模拟任务步骤
        steps = [
            {"name": "端口扫描", "duration": 2},
            {"name": "服务识别", "duration": 1},
            {"name": "操作系统检测", "duration": 1},
            {"name": "漏洞扫描", "duration": 3},
            {"name": "结果汇总", "duration": 1}
        ]
        
        total_steps = len(steps)
        results = {
            "target": target,
            "steps": []
        }
        
        # 执行每个步骤
        for i, step in enumerate(steps):
            # 检查任务是否被停止
            with self.lock:
                if self.tasks[task_id]['status'] != self.STATUS_RUNNING:
                    self.logger.info(f"任务已停止: ID={task_id}")
                    return
            
            step_name = step["name"]
            duration = step["duration"]
            
            self.logger.info(f"执行步骤: ID={task_id}, 步骤={step_name}")
            
            # 模拟步骤执行时间
            start_time = time.time()
            while time.time() - start_time < duration:
                time.sleep(0.5)
                
                # 更新进度
                progress = int((i + (time.time() - start_time) / duration) / total_steps * 100)
                with self.lock:
                    self.tasks[task_id]['progress'] = progress
                    self._save_task(task_id)
            
            # 模拟步骤结果
            step_result = self._simulate_step_result(step_name, target, options)
            results["steps"].append({
                "name": step_name,
                "result": step_result
            })
        
        # 任务完成，更新状态和结果
        with self.lock:
            task = self.tasks[task_id]
            task['status'] = self.STATUS_COMPLETED
            task['progress'] = 100
            task['results'] = results
            task['completed_at'] = datetime.now().isoformat()
            self._save_task(task_id)
        
        self.logger.info(f"任务执行完成: ID={task_id}")
    
    def _simulate_step_result(self, step_name, target, options):
        """
        模拟步骤结果
        
        Args:
            step_name (str): 步骤名称
            target (str): 目标
            options (dict): 任务选项
            
        Returns:
            dict: 步骤结果
        """
        # 模拟不同步骤的结果
        if step_name == "端口扫描":
            # 模拟开放端口
            ports = [22, 80, 443, 8080]
            return {
                "open_ports": ports,
                "total_scanned": 1000,
                "total_open": len(ports)
            }
        
        elif step_name == "服务识别":
            # 模拟服务识别结果
            return {
                "services": [
                    {"port": 22, "service": "ssh", "version": "OpenSSH 7.6p1"},
                    {"port": 80, "service": "http", "version": "Apache 2.4.29"},
                    {"port": 443, "service": "https", "version": "Apache 2.4.29"},
                    {"port": 8080, "service": "http-proxy", "version": "Unknown"}
                ]
            }
        
        elif step_name == "操作系统检测":
            # 模拟操作系统检测结果
            return {
                "os": "Linux",
                "distribution": "Ubuntu",
                "version": "18.04",
                "confidence": 0.85
            }
        
        elif step_name == "漏洞扫描":
            # 模拟漏洞扫描结果
            return {
                "vulnerabilities": [
                    {
                        "id": "CVE-2019-0708",
                        "severity": "critical",
                        "description": "Remote Desktop Services Remote Code Execution Vulnerability"
                    },
                    {
                        "id": "CVE-2020-1472",
                        "severity": "high",
                        "description": "Netlogon Elevation of Privilege Vulnerability"
                    }
                ],
                "total_found": 2
            }
        
        elif step_name == "结果汇总":
            # 模拟结果汇总
            return {
                "summary": {
                    "target": target,
                    "risk_score": 85,
                    "recommendations": [
                        "更新OpenSSH至最新版本",
                        "配置防火墙限制SSH访问",
                        "修复发现的关键漏洞"
                    ]
                }
            }
        
        return {}
    
    def _save_task(self, task_id):
        """
        保存任务到文件
        
        Args:
            task_id (str): 任务ID
        """
        task_file = os.path.join(self.tasks_dir, f"{task_id}.json")
        save_json_file(self.tasks[task_id], task_file)
    
    def _load_tasks(self):
        """
        从文件加载任务
        """
        try:
            # 遍历任务目录
            for filename in os.listdir(self.tasks_dir):
                if filename.endswith('.json'):
                    task_file = os.path.join(self.tasks_dir, filename)
                    
                    try:
                        # 加载任务文件
                        task_data = load_json_file(task_file)
                        
                        # 检查任务数据是否有效
                        if 'id' in task_data:
                            self.tasks[task_data['id']] = task_data
                            
                    except Exception as e:
                        self.logger.error(f"加载任务文件失败: {task_file}, 错误={e}")
            
            self.logger.info(f"已加载{len(self.tasks)}个任务")
            
        except Exception as e:
            self.logger.error(f"加载任务时发生错误: {e}")
    
    def shutdown(self):
        """
        关闭任务管理器
        """
        # 设置停止事件
        self.stop_event.set()
        
        # 等待工作线程结束
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=5)
        
        self.logger.info("任务管理器已关闭")
    
    def __del__(self):
        """
        析构函数，确保任务管理器正确关闭
        """
        self.shutdown()