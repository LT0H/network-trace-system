from celery import shared_task
from celery.schedules import crontab
from trace_system.celery_config import app
from .scanners import ScapyScanner, NMAPScanner
from .ip_tracker import QQWryIPLocator
import os
import logging
import json
import time
from django.conf import settings
from .models import ScanTask, TrafficAnalysisResult, ScanResult
from .traffic_monitor import TrafficMonitor
from django.utils import timezone
from datetime import datetime
from celery.exceptions import SoftTimeLimitExceeded

logger = logging.getLogger(__name__)
traffic_monitor = TrafficMonitor()

@app.task(bind=True, soft_time_limit=3600)  # 添加软时间限制（1小时）
def run_scan_task(self, task_id):
    """运行扫描任务，支持任务取消和超时处理"""
    ip_locator = QQWryIPLocator()
    task = None
    try:
        task = ScanTask.objects.get(id=task_id)
        logger.info(f"开始执行扫描任务: {task.id} - {task.target}")
        
        if task.status == 'RUNNING':
            logger.warning(f"任务 {task.id} 已在运行中")
            return {'status': 'warning', 'message': '任务已在运行'}
            
        if task.status == 'CANCELLED':
            logger.warning(f"任务 {task.id} 已被取消")
            return {'status': 'cancelled', 'message': '任务已被取消'}
            
        # 更新任务状态和Celery任务ID
        task.status = 'RUNNING'
        task.started_at = timezone.now()
        task.celery_task_id = self.request.id  # 记录Celery任务ID
        task.save()
        
        # 根据扫描类型选择合适的扫描器
        if task.scan_type in ['SYN_SCAN', 'UDP_SCAN']:
            scanner = ScapyScanner(task)
        else:
            scanner = NMAPScanner(task)
            
        results = []
        targets = [t.strip() for t in task.target.split(',')]
        total_targets = len(targets)
        if total_targets == 0:
            raise ValueError("扫描目标不能为空")
    
        for target_idx, target in enumerate(targets):
            # 检查任务是否已被取消
            task.refresh_from_db()
            if task.status == 'CANCELLED':
                logger.info(f"任务 {task.id} 被用户取消")
                return {'status': 'cancelled', 'message': '任务已被取消'}
                
            # 获取IP地理位置信息
            ip_location = ip_locator.query(target)
                    
            if task.scan_type == 'SYN_SCAN':
                scan_results = scanner.syn_scan(target, task.ports)
            elif task.scan_type == 'UDP_SCAN':
                scan_results = scanner.udp_scan(target, task.ports)
            elif task.scan_type == 'OS_DETECTION':
                scan_results = scanner.os_detection(target)
            elif task.scan_type == 'SERVICE_DETECTION':
                scan_results = scanner.service_detection(target, task.ports)
            elif task.scan_type == 'FULL_SCAN':
                scan_results = scanner.full_scan(target, task.ports)
            else:
                scan_results = []
            
            # 为每个结果添加地理位置信息
            for res in scan_results:
                res.update({
                    'country': ip_location.get('country', ''),
                    'city': ip_location.get('city', '')
                })
            
            results.extend(scan_results)
            
            # 更新整体进度
            target_progress = int((target_idx + 1) / total_targets * 100)
            task.progress = target_progress
            task.save()
        
        # 保存扫描结果
        bulk_results = []
        for res in results:
            bulk_results.append(ScanResult(
                task=task,
                ip_address=res['ip_address'],
                port=res.get('port'),
                protocol=res.get('protocol', 'tcp'),
                state=res['state'],
                service=res.get('service', ''),
                service_version=res.get('service_version', ''),
                os_family=res.get('os_family', ''),
                os_version=res.get('os_version', ''),
                country=res.get('country', ''),
                city=res.get('city', ''),
                discovered_at=timezone.now()
            ))
        
        # 使用bulk_create优化数据库操作
        if bulk_results:
            ScanResult.objects.bulk_create(bulk_results)
        
        # 完成任务
        task.status = 'COMPLETED'
        task.completed_at = timezone.now()
        task.progress = 100
        task.result_summary = {
            'total_scanned': len(results),
            'targets': targets,
            'completed_at': task.completed_at.isoformat()
        }
        task.save()
        
        logger.info(f"扫描任务 {task.id} 完成")
        return {'status': 'success', 'task_id': task.id, 'message': '扫描完成'}
        
    except ScanTask.DoesNotExist:
        logger.error(f"扫描任务不存在: {task_id}")
        return {'status': 'error', 'message': f"任务ID {task_id} 不存在"}
    except SoftTimeLimitExceeded:
        if task:
            task.status = 'FAILED'
            task.result_summary = {'error': '任务超时'}
            task.save()
        logger.error(f"扫描任务 {task_id} 超时")
        return {'status': 'error', 'message': '任务执行超时'}
    except Exception as e:
        if task:
            task.status = 'FAILED'
            task.result_summary = {'error': str(e)}
            task.save()
        logger.error(f"扫描任务执行失败: {str(e)}", exc_info=True)
        return {'status': 'error', 'message': str(e)}

@app.task
def start_traffic_monitoring(duration=None):
    """启动流量监听任务"""
    try:
        if traffic_monitor.is_running:
            logger.warning("流量监听已在运行中")
            return {
                'status': 'warning',
                'message': '流量监听已在运行中'
            }
            
        # 明确传递duration参数
        traffic_monitor.start_monitoring(duration=duration or 3600)  # 默认1小时
        return {
            'status': 'success',
            'message': '流量监听已启动',
            'duration': duration or 3600
        }
    except Exception as e:
        logger.error(f"启动流量监听失败: {e}")
        return {
            'status': 'failed',
            'error': str(e)
        }

@app.task
def check_traffic_monitor_status():
    """检查流量监控状态的任务"""
    status = 'running' if traffic_monitor.is_running else 'stopped'
    details = traffic_monitor.get_status_details() if traffic_monitor.is_running else {}
    
    return {
        'status': status,
        'timestamp': timezone.now().isoformat(),
        'details': details
    }

@app.task
def stop_traffic_monitoring():
    """停止流量监听任务"""
    try:
        if not traffic_monitor.is_running:
            logger.warning("流量监听未在运行中")
            return {
                'status': 'warning',
                'message': '流量监听未在运行中'
            }
            
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

@app.task(name="analyze_traffic_periodically")
def analyze_traffic_periodically():
    """每2小时执行一次流量分析，优化资源处理"""
    logger.info("开始执行定时流量分析任务")
    
    try:
        # 获取未分析的pcap文件或需要重新分析的文件
        records = TrafficAnalysisResult.objects.filter(
            is_analyzed=False
        ).order_by('created_at')
        
        if not records:
            logger.info("没有需要分析的流量记录")
            return
        
        # 创建数据集目录，添加时间戳确保唯一性
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dataset_dir = os.path.join(settings.BASE_DIR, 'datasets', f"dataset_{timestamp}")
        os.makedirs(dataset_dir, exist_ok=True)
        logger.info(f"创建数据集目录: {dataset_dir}")
        
        # 分析记录并构建数据集
        analysis_summary = {
            'timestamp': datetime.now().isoformat(),
            'record_count': len(records),
            'success_count': 0,
            'fail_count': 0,
            'records': []
        }
        
        for record in records:
            try:
                # 更新分析状态
                record.is_analyzed = False
                record.analysis_started_at = timezone.now()
                record.save()
                
                # 复制分析结果到数据集目录
                if record.analyzer_type == 'ws' and 'analysis_result' in record.analysis_result:
                    result_file = os.path.join(dataset_dir, f"ws_analysis_{record.id}.json")
                    with open(result_file, 'w') as f:
                        json.dump(record.analysis_result, f, indent=2)
                
                elif record.analyzer_type == 'cic' and 'csv_path' in record.analysis_result:
                    import shutil
                    csv_path = record.analysis_result['csv_path']
                    if os.path.exists(csv_path):
                        shutil.copy2(csv_path, dataset_dir)
                        # 复制后删除原文件释放空间
                        os.remove(csv_path)
                
                # 标记为已分析
                record.is_analyzed = True
                record.analysis_completed_at = timezone.now()
                record.save()
                
                # 更新摘要
                analysis_summary['success_count'] += 1
                analysis_summary['records'].append({
                    'id': record.id,
                    'status': 'success'
                })
                
                # 删除pcap文件释放空间
                if os.path.exists(record.pcap_file_path):
                    os.remove(record.pcap_file_path)
                    logger.info(f"已删除pcap文件: {record.pcap_file_path}")
                
            except Exception as e:
                logger.error(f"分析记录 {record.id} 失败: {e}")
                analysis_summary['fail_count'] += 1
                analysis_summary['records'].append({
                    'id': record.id,
                    'status': 'failed',
                    'error': str(e)
                })
        
        # 保存数据集摘要
        summary_file = os.path.join(dataset_dir, 'summary.json')
        with open(summary_file, 'w') as f:
            json.dump(analysis_summary, f, indent=2)
        
        # 记录分析日志
        logger.info(f"定时流量分析完成: 共{len(records)}条记录，成功{analysis_summary['success_count']}条，失败{analysis_summary['fail_count']}条")
        
        # 重新启动监控（如果当前未运行）
        if not traffic_monitor.is_running:
            traffic_monitor.start_monitoring(duration=3600)
            logger.info("流量监控已重新启动")
        
        return analysis_summary
        
    except Exception as e:
        logger.error(f"定时流量分析任务出错: {e}", exc_info=True)
        raise e

@app.task
def cancel_scan_task(task_id):
    """取消扫描任务"""
    try:
        task = ScanTask.objects.get(id=task_id)
        if task.cancel_task():
            # 如果任务正在运行，尝试终止Celery任务
            if task.celery_task_id:
                app.control.revoke(task.celery_task_id, terminate=True)
                logger.info(f"已发送终止命令到Celery任务: {task.celery_task_id}")
            return {'status': 'success', 'message': f"任务 {task_id} 已取消"}
        else:
            return {'status': 'error', 'message': f"任务 {task_id} 无法取消，当前状态: {task.status}"}
    except ScanTask.DoesNotExist:
        return {'status': 'error', 'message': f"任务 {task_id} 不存在"}
    except Exception as e:
        logger.error(f"取消任务 {task_id} 失败: {e}")
        return {'status': 'error', 'message': str(e)}