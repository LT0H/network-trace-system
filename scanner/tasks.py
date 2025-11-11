from celery import shared_task
import logging
import time  # 新增必要导入
from .models import ScanTask, TrafficAnalysisResult
from .traffic_monitor import TrafficMonitor
from django.utils import timezone

logger = logging.getLogger(__name__)
traffic_monitor = TrafficMonitor()  # 确保此处初始化不会引发导入问题

@shared_task
def run_scan_task(task_id):
    """运行扫描任务（修复语法错误和逻辑错误）"""
    task = None  # 提前初始化task变量，避免未定义问题
    try:
        # 获取任务实例
        task = ScanTask.objects.get(id=task_id)
        logger.info(f"开始执行扫描任务: {task.id} - {task.target}")
        
        # 检查任务状态
        if task.status == 'RUNNING':
            logger.warning(f"任务 {task.id} 已在运行中")
            return {
                'status': 'warning',
                'message': '任务已在运行'
            }
            
        # 更新任务状态为运行中
        task.status = 'RUNNING'
        task.save()
        
        # 模拟扫描逻辑（请根据实际扫描需求替换）
        # 此处添加真实的扫描代码，例如调用扫描工具
        logger.info(f"正在扫描目标: {task.target}")
        time.sleep(5)  # 模拟扫描耗时
        
        # 扫描完成后更新状态
        task.status = 'COMPLETED'
        task.completed_at = timezone.now()  # 假设已导入timezone
        task.save()
        logger.info(f"扫描任务 {task.id} 完成")
        
        return {
            'status': 'success',
            'task_id': task.id,
            'message': '扫描完成'
        }
        
    except ScanTask.DoesNotExist:
        logger.error(f"扫描任务不存在: {task_id}")
        return {
            'status': 'error',
            'message': f"任务ID {task_id} 不存在"
        }
    except Exception as e:
        # 异常情况下更新任务状态
        if task:
            task.status = 'FAILED'
            task.save()
        logger.error(f"扫描任务执行失败: {str(e)}", exc_info=True)
        return {
            'status': 'error',
            'message': str(e)
        }

@shared_task
def start_traffic_monitoring(duration=None):
    """启动流量监听任务"""
    try:
        traffic_monitor.start_monitoring(duration)
        return {
            'status': 'success',
            'message': '流量监听已启动'
        }
    except Exception as e:
        logger.error(f"启动流量监听失败: {e}")
        return {
            'status': 'failed',
            'error': str(e)
        }

@shared_task
def stop_traffic_monitoring():
    """停止流量监听任务"""
    try:
        traffic_monitor.stop_monitoring()
        return {
            'status': 'success',
            'message': '流量监听已停止'
        }
    except Exception as e:
        logger.error(f"停止流量监听失败: {e}")
        return {
            'status': 'failed',
            'error': str(e)
        }