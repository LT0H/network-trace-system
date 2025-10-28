from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_GET
from django.db import connection
from django.core.cache import cache
from django.utils import timezone
from scanner.models import ScanTask, ScanResult
from django.db.models import Count, Q
import psutil
import os
import json
from datetime import timedelta

@login_required
def dashboard(request):
    """系统仪表盘"""
    # 统计信息
    total_tasks = ScanTask.objects.count()
    completed_tasks = ScanTask.objects.filter(status='COMPLETED').count()
    running_tasks = ScanTask.objects.filter(status='RUNNING').count()
    
    # 最近7天的任务统计
    seven_days_ago = timezone.now() - timedelta(days=7)
    recent_tasks = ScanTask.objects.filter(created_at__gte=seven_days_ago)
    
    # 任务状态分布
    status_distribution = (
        ScanTask.objects.values('status')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    
    # 端口统计
    open_ports = ScanResult.objects.filter(state='open').count()
    unique_hosts = ScanResult.objects.values('ip_address').distinct().count()
    
    # 最近扫描结果
    recent_results = ScanResult.objects.select_related('task').order_by('-discovered_at')[:10]
    
    # 准备图表数据
    chart_data = {
        'task_trend': get_task_trend_data(),
        'port_distribution': get_port_distribution_data(),
        'topology_data': get_topology_data()
    }
    
    context = {
        'total_tasks': total_tasks,
        'completed_tasks': completed_tasks,
        'running_tasks': running_tasks,
        'open_ports': open_ports,
        'unique_hosts': unique_hosts,
        'recent_tasks': recent_tasks[:5],
        'recent_results': recent_results,
        'status_distribution': status_distribution,
        'chart_data': json.dumps(chart_data)
    }
    
    return render(request, 'dashboard/dashboard.html', context)

@login_required
def topology_view(request):
    """网络拓扑视图"""
    context = {
        'page_title': '网络拓扑',
    }
    return render(request, 'dashboard/topology.html', context)

@login_required
def reports_view(request):
    """报告视图"""
    context = {
        'page_title': '扫描报告',
    }
    return render(request, 'dashboard/reports.html', context)

# ==================== 健康检查功能 ====================

@require_GET
def health_check(request):
    """
    系统健康检查端点
    用于负载均衡器和监控系统检查服务状态
    """
    checks = {}
    
    # 1. 数据库连接检查
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        checks['database'] = {
            'status': 'healthy', 
            'response_time': 'ok',
            'details': '数据库连接正常'
        }
    except Exception as e:
        checks['database'] = {
            'status': 'unhealthy', 
            'error': str(e),
            'details': '数据库连接失败'
        }
    
    # 2. 缓存检查
    try:
        cache.set('health_check', 'ok', 10)
        if cache.get('health_check') == 'ok':
            checks['cache'] = {
                'status': 'healthy',
                'details': '缓存服务正常'
            }
        else:
            checks['cache'] = {
                'status': 'unhealthy', 
                'error': 'Cache set/get failed',
                'details': '缓存读写失败'
            }
    except Exception as e:
        checks['cache'] = {
            'status': 'unhealthy', 
            'error': str(e),
            'details': '缓存服务异常'
        }
    
    # 3. Celery检查（如果配置了Celery）
    try:
        from celery import current_app
        insp = current_app.control.inspect()
        active_workers = insp.active()
        if active_workers:
            worker_count = len(active_workers)
            checks['celery'] = {
                'status': 'healthy', 
                'workers': worker_count,
                'details': f'Celery服务正常，活跃Worker数量: {worker_count}'
            }
        else:
            checks['celery'] = {
                'status': 'warning', 
                'error': 'No active workers',
                'details': '没有活跃的Celery Worker'
            }
    except Exception as e:
        checks['celery'] = {
            'status': 'unhealthy', 
            'error': str(e),
            'details': 'Celery服务异常'
        }
    
    # 4. 系统资源检查
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        checks['system'] = {
            'status': 'healthy',
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'disk_percent': disk.percent,
            'details': f'系统资源正常 - CPU: {cpu_percent}%, 内存: {memory.percent}%, 磁盘: {disk.percent}%'
        }
        
        # 检查资源使用是否过高
        warnings = []
        if cpu_percent > 90:
            warnings.append('CPU使用率过高')
        if memory.percent > 90:
            warnings.append('内存使用率过高') 
        if disk.percent > 90:
            warnings.append('磁盘空间不足')
            
        if warnings:
            checks['system']['status'] = 'warning'
            checks['system']['warnings'] = warnings
            checks['system']['details'] += f' | 警告: {", ".join(warnings)}'
            
    except Exception as e:
        checks['system'] = {
            'status': 'unhealthy', 
            'error': str(e),
            'details': '系统资源检查失败'
        }
    
    # 5. 扫描功能检查
    try:
        # 检查最近任务状态
        recent_tasks = ScanTask.objects.order_by('-created_at')[:5]
        failed_recently = recent_tasks.filter(status='FAILED').exists()
        
        checks['scanner'] = {
            'status': 'healthy',
            'recent_tasks': len(recent_tasks),
            'details': '扫描功能正常'
        }
        
        if failed_recently:
            checks['scanner']['status'] = 'warning'
            checks['scanner']['details'] = '扫描功能正常，但最近有失败任务'
            
    except Exception as e:
        checks['scanner'] = {
            'status': 'unhealthy', 
            'error': str(e),
            'details': '扫描功能检查失败'
        }
    
    # 6. 应用状态检查
    try:
        total_hosts = ScanResult.objects.values('ip_address').distinct().count()
        total_results = ScanResult.objects.count()
        
        checks['application'] = {
            'status': 'healthy',
            'total_hosts': total_hosts,
            'total_results': total_results,
            'details': f'应用运行正常 - 已发现 {total_hosts} 台主机，{total_results} 条记录'
        }
    except Exception as e:
        checks['application'] = {
            'status': 'unhealthy',
            'error': str(e),
            'details': '应用状态检查失败'
        }
    
    # 总体状态计算
    status_priority = {
        'unhealthy': 3,
        'warning': 2, 
        'healthy': 1
    }
    
    overall_status = max(
        (check['status'] for check in checks.values()),
        key=lambda x: status_priority[x]
    )
    
    status_code = 200 if overall_status in ['healthy', 'warning'] else 503
    
    response_data = {
        'status': overall_status,
        'timestamp': timezone.now().isoformat(),
        'service': '网络扫描溯源系统',
        'version': '1.0.0',
        'checks': checks
    }
    
    return JsonResponse(response_data, status=status_code)

@require_GET
def metrics(request):
    """
    Prometheus格式的监控指标端点
    """
    from django.db.models import Count
    from scanner.models import ScanTask, ScanResult
    import time
    
    metrics_data = []
    
    # 任务统计
    task_stats = ScanTask.objects.aggregate(
        total=Count('id'),
        completed=Count('id', filter=Q(status='COMPLETED')),
        running=Count('id', filter=Q(status='RUNNING')),
        failed=Count('id', filter=Q(status='FAILED')),
        pending=Count('id', filter=Q(status='PENDING'))
    )
    
    metrics_data.append(f'scantask_total {task_stats["total"]}')
    metrics_data.append(f'scantask_completed {task_stats["completed"]}')
    metrics_data.append(f'scantask_running {task_stats["running"]}')
    metrics_data.append(f'scantask_failed {task_stats["failed"]}')
    metrics_data.append(f'scantask_pending {task_stats["pending"]}')
    
    # 结果统计
    result_stats = ScanResult.objects.aggregate(
        total=Count('id'),
        open_ports=Count('id', filter=Q(state='open')),
        closed_ports=Count('id', filter=Q(state='closed')),
        filtered_ports=Count('id', filter=Q(state='filtered')),
        unique_hosts=Count('ip_address', distinct=True)
    )
    
    metrics_data.append(f'scanresult_total {result_stats["total"]}')
    metrics_data.append(f'scanresult_open_ports {result_stats["open_ports"]}')
    metrics_data.append(f'scanresult_closed_ports {result_stats["closed_ports"]}')
    metrics_data.append(f'scanresult_filtered_ports {result_stats["filtered_ports"]}')
    metrics_data.append(f'scanresult_unique_hosts {result_stats["unique_hosts"]}')
    
    # 服务统计
    service_stats = ScanResult.objects.filter(service__isnull=False).values('service').annotate(count=Count('id'))
    for service in service_stats[:10]:  # 限制前10个服务
        service_name = service['service'].replace('-', '_').replace('.', '_')
        metrics_data.append(f'scanresult_service_{service_name} {service["count"]}')
    
    # 系统指标
    try:
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        metrics_data.append(f'system_memory_used_bytes {memory.used}')
        metrics_data.append(f'system_memory_total_bytes {memory.total}')
        metrics_data.append(f'system_memory_percent {memory.percent}')
        metrics_data.append(f'system_disk_used_bytes {disk.used}')
        metrics_data.append(f'system_disk_total_bytes {disk.total}')
        metrics_data.append(f'system_disk_percent {disk.percent}')
        metrics_data.append(f'system_cpu_percent {psutil.cpu_percent(interval=0.1)}')
    except Exception as e:
        metrics_data.append(f'system_metrics_error 1')
    
    # 响应时间
    response_time = time.time() - float(request.META.get('REQUEST_TIME_FLOAT', time.time()))
    metrics_data.append(f'http_response_time_seconds {response_time}')
    
    # Django请求指标
    metrics_data.append(f'django_requests_total 1')
    
    return HttpResponse('\n'.join(metrics_data), content_type='text/plain')

@require_GET
def health_simple(request):
    """
    简化版健康检查，用于基础监控
    """
    try:
        # 基础数据库检查
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        
        return JsonResponse({
            'status': 'ok',
            'timestamp': timezone.now().isoformat()
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=503)

# ==================== 辅助函数 ====================

def get_task_trend_data():
    """获取任务趋势数据"""
    from django.db.models.functions import TruncDay
    from django.db.models import Count
    
    trend_data = (
        ScanTask.objects
        .filter(created_at__gte=timezone.now()-timedelta(days=30))
        .annotate(day=TruncDay('created_at'))
        .values('day')
        .annotate(count=Count('id'))
        .order_by('day')
    )
    
    days = [item['day'].strftime('%Y-%m-%d') for item in trend_data]
    counts = [item['count'] for item in trend_data]
    
    return {
        'days': days,
        'counts': counts
    }

def get_port_distribution_data():
    """获取端口分布数据"""
    port_data = (
        ScanResult.objects
        .filter(state='open')
        .values('port')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )
    
    ports = [f"端口 {item['port']}" for item in port_data]
    counts = [item['count'] for item in port_data]
    
    return {
        'ports': ports,
        'counts': counts
    }

def get_topology_data():
    """获取网络拓扑数据（简化版）"""
    # 这里可以实现更复杂的拓扑发现逻辑
    hosts = (
        ScanResult.objects
        .values('ip_address')
        .distinct()
        .annotate(port_count=Count('id', filter=Q(state='open')))
    )
    
    nodes = []
    links = []
    
    for i, host in enumerate(hosts):
        nodes.append({
            'id': host['ip_address'],
            'name': host['ip_address'],
            'value': host['port_count'],
            'category': 0 if host['port_count'] > 5 else 1  # 根据端口数量分类
        })
    
    # 简单的链接关系（实际应用中需要更复杂的发现逻辑）
    if len(nodes) > 1:
        links.append({
            'source': nodes[0]['id'],
            'target': nodes[1]['id']
        })
    
    return {
        'nodes': nodes,
        'links': links
    }

# ==================== 上下文处理器 ====================

def app_version(request):
    """应用版本上下文处理器"""
    return {
        'app_version': '1.0.0',
        'app_name': '网络扫描溯源系统'
    }