from celery import shared_task
from celery.exceptions import MaxRetriesExceededError
from django.utils import timezone
import logging
from .models import ScanTask, ScanResult
from .scanners import NMAPScanner, ScapyScanner

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def run_scan_task(self, task_id):
    """
    执行扫描任务的Celery任务
    
    Args:
        task_id: ScanTask实例的ID
        self: Celery任务实例，用于重试和状态更新
    """
    #添加任务验证
    if task.status == 'RUNNING':
        logger.warning(f"任务 {task_id} 已经在运行中")
        return {
            'task_id': task_id,
            'status': 'skipped', 
            'message': '任务已在运行中'
        }
    
    if task.status == 'COMPLETED' and not task.result_summary:
        logger.info(f"任务 {task_id} 已完成但无结果，重新执行")
        task.reset_task()
    
    try:
        # 获取扫描任务实例
        task = ScanTask.objects.get(id=task_id)
        logger.info(f"开始执行扫描任务: {task.name} (ID: {task_id})")
        
        # 更新任务状态为运行中
        task.status = 'RUNNING'
        task.started_at = timezone.now()
        task.save()
        
        # 根据扫描类型选择合适的扫描器
        scanner = None
        if task.scan_type in ['SYN_SCAN', 'UDP_SCAN']:
            scanner = ScapyScanner(target=task.target, ports=task.ports)
        else:
            scanner = NMAPScanner(target=task.target, ports=task.ports, options=task.options)
        
        # 执行扫描并获取结果
        results = scanner.execute_scan(scan_type=task.scan_type)
        
        # 保存扫描结果到数据库
        saved_count = 0
        for result_data in results:
            try:
                # 创建扫描结果记录
                ScanResult.objects.create(task=task, **result_data)
                saved_count += 1
                
                # 更新任务进度（每保存10条记录更新一次进度）
                if saved_count % 10 == 0:
                    progress = min(90, int((saved_count / len(results)) * 90))
                    task.progress = progress
                    task.save()
                    
            except Exception as e:
                logger.error(f"保存扫描结果失败: {e}")
                continue
        
        # 更新任务状态为完成
        task.status = 'COMPLETED'
        task.progress = 100
        task.completed_at = timezone.now()
        
        # 生成结果摘要
        open_ports = ScanResult.objects.filter(task=task, state='open').count()
        unique_hosts = ScanResult.objects.filter(task=task).values('ip_address').distinct().count()
        
        task.result_summary = {
            'total_results': saved_count,
            'open_ports': open_ports,
            'unique_hosts': unique_hosts,
            'scan_duration': str(task.get_duration()) if task.get_duration() else None
        }
        task.save()
        
        logger.info(f"扫描任务完成: {task.name}，共保存 {saved_count} 条结果")
        return {
            'task_id': task_id,
            'status': 'completed',
            'results_count': saved_count,
            'message': '扫描任务执行成功'
        }
        
    except ScanTask.DoesNotExist:
        error_msg = f"扫描任务不存在: {task_id}"
        logger.error(error_msg)
        return {
            'task_id': task_id,
            'status': 'failed',
            'error': error_msg
        }
        
    except Exception as exc:
        logger.error(f"扫描任务执行失败: {exc}")
        
        # 更新任务状态为失败
        try:
            task.status = 'FAILED'
            task.save()
        except:
            pass
        
        # 尝试重试任务
        try:
            raise self.retry(exc=exc, countdown=60)
        except MaxRetriesExceededError:
            logger.error(f"扫描任务重试次数已达上限: {task_id}")
            return {
                'task_id': task_id,
                'status': 'failed',
                'error': f'任务执行失败且重试次数已达上限: {str(exc)}'
            }


@shared_task
def cleanup_old_tasks(days=30):
    """
    清理旧扫描任务的后台任务
    
    Args:
        days: 保留天数，早于此天数的任务将被删除
    """
    from django.utils import timezone
    from datetime import timedelta
    
    cutoff_date = timezone.now() - timedelta(days=days)
    
    # 删除旧任务及相关结果
    old_tasks = ScanTask.objects.filter(created_at__lt=cutoff_date)
    task_count = old_tasks.count()
    
    for task in old_tasks:
        # 删除关联的扫描结果
        task.results.all().delete()
        # 删除任务本身
        task.delete()
    
    logger.info(f"清理完成，共删除 {task_count} 个旧扫描任务")
    return f"已清理 {task_count} 个超过 {days} 天的扫描任务"