import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from scanner.traffic_monitor import TrafficMonitor
from scanner.scanners.scapy_scanner import ScapyScanner

logger = logging.getLogger(__name__)

# 单例监控实例
traffic_monitor = TrafficMonitor()

@csrf_exempt
def start_monitoring(request):
    """启动流量监控"""
    duration = request.POST.get('duration', 3600)  # 默认1小时
    try:
        result = traffic_monitor.start_monitoring(int(duration))
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@csrf_exempt
def stop_monitoring(request):
    """停止流量监控"""
    result = traffic_monitor.stop_monitoring()
    return JsonResponse(result)

@csrf_exempt
def run_scan(request):
    """执行主动扫描任务"""
    if request.method != 'POST':
        return JsonResponse({'error': '仅支持POST请求'}, status=405)
    
    data = request.POST
    target = data.get('target')
    scan_type = data.get('scan_type')
    ports = data.get('ports', '1-100')
    interface = data.get('interface')
    
    if not target or not scan_type:
        return JsonResponse({'error': '缺少目标或扫描类型'}, status=400)
    
    try:
        # 初始化扫描器
        scanner = ScapyScanner(
            target=target,
            options={
                'ports': ports,
                'interface': interface,
                'timeout': 2,
                'retries': 1
            }
        )
        # 执行扫描
        results = scanner.execute_scan(scan_type)
        return JsonResponse({
            'success': True,
            'target': target,
            'scan_type': scan_type,
            'results': results
        })
    except Exception as e:
        logger.error(f"扫描失败: {e}")
        return JsonResponse({'error': str(e)}, status=500)

def get_analysis_results(request):
    """获取分析结果列表"""
    from scanner.models import TrafficAnalysis
    results = TrafficAnalysis.objects.order_by('-analysis_time').values(
        'id', 'analysis_time', 'analysis_type', 'result_summary'
    )
    return JsonResponse({'results': list(results)})