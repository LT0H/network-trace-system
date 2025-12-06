from celery import shared_task
from celery.schedules import crontab
from trace_system.celery_config import app
from .scanners import ScapyScanner, NMAPScanner  # 导入NMAPScanner
from .ip_tracker import QQWryIPLocator
import os
import logging
import json
import time
from django.conf import settings
from .models import ScanTask, TrafficAnalysisResult
from .traffic_monitor import TrafficMonitor
from django.utils import timezone
from datetime import datetime

logger = logging.getLogger(__name__)
traffic_monitor = TrafficMonitor()  # 确保此处初始化不会引发导入问题

@app.task
def run_scan_task(task_id):
    """运行扫描任务"""
    ip_locator = QQWryIPLocator()
    task = None
    try:
        task = ScanTask.objects.get(id=task_id)
        logger.info(f"开始执行扫描任务: {task.id} - {task.target}")
        
        if task.status == 'RUNNING':
            logger.warning(f"任务 {task.id} 已在运行中")
            return {'status': 'warning', 'message': '任务已在运行'}
            
        # 更新任务状态
        task.status = 'RUNNING'
        task.started_at = timezone.now()
        task.save()
        
        # 根据扫描类型选择合适的扫描器
        if task.scan_type in ['SYN_SCAN', 'UDP_SCAN']:
            scanner = ScapyScanner(task)
        else:  # OS_DETECTION, SERVICE_DETECTION, FULL_SCAN 使用NMAP扫描器
            scanner = NMAPScanner(task)
            
        results = []
        
        # 根据扫描类型执行相应扫描
        targets = [t.strip() for t in task.target.split(',')]
        total_targets = len(targets)
    
        for target_idx, target in enumerate(targets):
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
                    'country': ip_location['country'],
                    'city': ip_location['city']
                })
            
            results.extend(scan_results)
            
            # 更新整体进度
            target_progress = int((target_idx + 1) / total_targets * 100)
            task.progress = target_progress
            task.save()
        
        # 保存扫描结果
        from scanner.models import ScanResult
        for res in results:
            ScanResult.objects.create(
                task=task,
                ip_address=res['ip_address'],
                port=res.get('port'),
                protocol=res.get('protocol', 'tcp'),
                state=res['state'],
                service=res.get('service', ''),
                service_version=res.get('service_version', ''),
                os_family=res.get('os_family', ''),
                os_version=res.get('os_version', ''),
                discovered_at=timezone.now()
            )
        
        # 完成任务
        task.status = 'COMPLETED'
        task.completed_at = timezone.now()
        task.progress = 100
        task.result_summary = {
            'total_scanned': len(results),
            'targets': targets
        }
        task.save()
        
        logger.info(f"扫描任务 {task.id} 完成")
        return {'status': 'success', 'task_id': task.id, 'message': '扫描完成'}
        
    except ScanTask.DoesNotExist:
        logger.error(f"扫描任务不存在: {task_id}")
        return {'status': 'error', 'message': f"任务ID {task_id} 不存在"}
    except Exception as e:
        if task:
            task.status = 'FAILED'
            task.save()
        logger.error(f"扫描任务执行失败: {str(e)}", exc_info=True)
        return {'status': 'error', 'message': str(e)}

@app.task
def start_traffic_monitoring(duration=None):
    """启动流量监听任务"""
    try:
        # 明确传递 duration 参数
        traffic_monitor.start_monitoring(duration=duration or 3600)  # 默认1小时
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

@app.task
def check_traffic_monitor_status():
    """检查流量监控状态的任务"""
    return {
        'status': 'running' if traffic_monitor.is_running else 'stopped',
        'timestamp': timezone.now().isoformat()
    }

@app.task
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

@app.task(name="analyze_traffic_periodically")
def analyze_traffic_periodically():
    """每2小时执行一次流量分析"""
    logger.info("开始执行定时流量分析任务")
    
    try:
        # 1. 获取未分析的pcap文件或需要重新分析的文件
        records = TrafficAnalysisResult.objects.filter(
            is_analyzed=False
        ).order_by('created_at')
        
        if not records:
            logger.info("没有需要分析的流量记录")
            return
        
        # 3. 创建数据集目录
        dataset_dir = os.path.join(settings.BASE_DIR, 'datasets', f"dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(dataset_dir, exist_ok=True)
        logger.info(f"创建数据集目录: {dataset_dir}")
        
        # 4. 分析记录并构建数据集
        analysis_summary = {
            'timestamp': datetime.now().isoformat(),
            'record_count': len(records),
            'success_count': 0,
            'fail_count': 0,
            'records': []
        }
        
        for record in records:
            try:
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
                
                # 标记为已分析
                record.is_analyzed = True
                record.save()
                
                # 更新摘要
                analysis_summary['success_count'] += 1
                analysis_summary['records'].append({
                    'id': record.id,
                    'status': 'success'
                })
                
                # 删除pcap文件
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
        
        # 5. 保存数据集摘要
        summary_file = os.path.join(dataset_dir, 'summary.json')
        with open(summary_file, 'w') as f:
            json.dump(analysis_summary, f, indent=2)
        
        # 6. 记录分析日志
        logger.info(f"定时流量分析完成: 共{len(records)}条记录，成功{analysis_summary['success_count']}条，失败{analysis_summary['fail_count']}条")
        
        # 7. 重新启动监控
        traffic_monitor.start_monitoring(duration=3600)
        
        return analysis_summary
        
    except Exception as e:
        logger.error(f"定时流量分析任务出错: {e}")
        raise e