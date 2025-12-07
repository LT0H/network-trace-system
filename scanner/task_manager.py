import time
import json
import logging
from pathlib import Path
from datetime import datetime
from .traffic_monitor import TrafficMonitor
from .ip_locator import IPLocator
from django.conf import settings

logger = logging.getLogger(__name__)

class ScanTask:
    """扫描任务类"""
    def __init__(self, task_id, target, duration=3600, interval=60):
        self.task_id = task_id
        self.target = target
        self.duration = duration  # 总任务时长
        self.interval = interval  # 扫描间隔
        self.status = "created"  # created, running, paused, completed, failed
        self.start_time = None
        self.end_time = None
        self.results = []
        self.monitor = TrafficMonitor()
        
    def start(self):
        """开始任务"""
        if self.status == "running":
            return {"status": "warning", "message": "任务已在运行"}
            
        self.status = "running"
        self.start_time = datetime.now()
        logger.info(f"任务 {self.task_id} 开始，目标: {self.target}")
        
        # 启动监控
        result = self.monitor.start_monitoring(
            duration=self.duration,
            target=self.target
        )
        
        if result["status"] == "success":
            return {"status": "success", "message": f"任务 {self.task_id} 启动成功"}
        else:
            self.status = "failed"
            return result
    
    def stop(self):
        """停止任务"""
        if self.status != "running":
            return {"status": "warning", "message": "任务未在运行"}
            
        result = self.monitor.stop_monitoring()
        self.status = "completed"
        self.end_time = datetime.now()
        logger.info(f"任务 {self.task_id} 已停止")
        return result
    
    def get_status(self):
        """获取任务状态"""
        return {
            "task_id": self.task_id,
            "target": self.target,
            "status": self.status,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "result_count": len(self.results)
        }
    
    def add_result(self, result_file):
        """添加分析结果"""
        self.results.append({
            "timestamp": datetime.now().isoformat(),
            "file_path": str(result_file)
        })


class TaskManager:
    """任务管理器"""
    def __init__(self):
        self.tasks = {}  # task_id -> ScanTask
        self.ip_locator = IPLocator(settings.QQWRY_PATH)
        
    def create_task(self, target, duration=3600, interval=60):
        """创建新任务"""
        task_id = f"task_{int(time.time())}"
        task = ScanTask(task_id, target, duration, interval)
        self.tasks[task_id] = task
        logger.info(f"创建新任务: {task_id}, 目标: {target}")
        return task_id
    
    def start_task(self, task_id):
        """启动任务"""
        if task_id not in self.tasks:
            return {"status": "error", "message": "任务不存在"}
            
        return self.tasks[task_id].start()
    
    def stop_task(self, task_id):
        """停止任务"""
        if task_id not in self.tasks:
            return {"status": "error", "message": "任务不存在"}
            
        return self.tasks[task_id].stop()
    
    def get_task_status(self, task_id):
        """获取任务状态"""
        if task_id not in self.tasks:
            return {"status": "error", "message": "任务不存在"}
            
        return self.tasks[task_id].get_status()
    
    def list_tasks(self):
        """列出所有任务"""
        return [task.get_status() for task in self.tasks.values()]
    
    def get_task_results(self, task_id):
        """获取任务结果，包含IP定位信息"""
        if task_id not in self.tasks:
            return {"status": "error", "message": "任务不存在"}
            
        task = self.tasks[task_id]
        detailed_results = []
        
        for result in task.results:
            try:
                with open(result["file_path"], 'r') as f:
                    analysis_data = json.load(f)
                
                # 添加上IP定位信息
                for flow in analysis_data.get("flows", []):
                    if "src_ip" in flow:
                        flow["src_location"] = self.ip_locator.query(flow["src_ip"])
                    if "dst_ip" in flow:
                        flow["dst_location"] = self.ip_locator.query(flow["dst_ip"])
                
                detailed_results.append({
                    "timestamp": result["timestamp"],
                    "data": analysis_data
                })
            except Exception as e:
                logger.error(f"解析结果文件失败: {e}")
                detailed_results.append({
                    "timestamp": result["timestamp"],
                    "error": str(e)
                })
        
        return {
            "task_id": task_id,
            "results": detailed_results
        }