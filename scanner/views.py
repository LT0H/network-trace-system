import json
import os
from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.admin.views.decorators import staff_member_required
from .traffic_monitor import TrafficMonitor
from .models import TrafficAnalysisResult
import logging

logger = logging.getLogger(__name__)

# 实例化流量监控器
traffic_monitor = TrafficMonitor()

@staff_member_required
def traffic_monitor_admin(request):
    """流量监控管理员页面"""
    return render(request, 'scanner/traffic_monitor_admin.html')

def start_traffic_monitor(request):
    """启动流量监控API"""
    if request.method == 'POST':
        try:
            traffic_monitor.start_monitoring()
            return JsonResponse({
                'status': 'success',
                'message': '流量监控已启动'
            })
        except Exception as e:
            logger.error(f"启动流量监控失败: {e}")
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    return JsonResponse({'status': 'error', 'message': '无效请求'}, status=400)

def stop_traffic_monitor(request):
    """停止流量监控API"""
    if request.method == 'POST':
        try:
            traffic_monitor.stop_monitoring()
            return JsonResponse({
                'status': 'success',
                'message': '流量监控已停止'
            })
        except Exception as e:
            logger.error(f"停止流量监控失败: {e}")
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    return JsonResponse({'status': 'error', 'message': '无效请求'}, status=400)

def get_traffic_records(request):
    """获取流量记录列表"""
    records = TrafficAnalysisResult.objects.all().order_by('-id')
    data = [{
        'id': record.id,
        'pcap_file': record.pcap_file_path,
        'analyzer_type': record.analyzer_type,
        'packet_count': record.packet_count,
        'created_at': record.created_at,
        'protocol_distribution': record.protocol_distribution
    } for record in records]
    return JsonResponse({'status': 'success', 'data': data})

def analyze_traffic_record(request, record_id):
    """分析特定流量记录"""
    try:
        record = TrafficAnalysisResult.objects.get(id=record_id)
        # 这里可以添加更详细的分析逻辑
        return JsonResponse({
            'status': 'success',
            'data': {
                'id': record.id,
                'analysis_result': record.analysis_result,
                'protocol_distribution': record.protocol_distribution,
                'packet_count': record.packet_count
            }
        })
    except TrafficAnalysisResult.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': '记录不存在'}, status=404)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)