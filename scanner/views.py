import json
import os
from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
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

@staff_member_required
def start_traffic_monitor(request):
    """启动流量监控API"""
    if request.method == 'POST':
        try:
            if not traffic_monitor.is_running:
                # 启动监控并获取启动结果（包含错误信息）
                start_result = traffic_monitor.start_monitoring()  # 需要修改TrafficMonitor.start_monitoring返回结果
                if start_result.get("status") == "success":
                    return JsonResponse({
                        'status': 'success',
                        'message': '流量监控已启动',
                        'is_running': True,
                        'errors': []
                    })
                else:
                    return JsonResponse({
                        'status': 'warning',
                        'message': f'监控已启动，但部分功能异常: {start_result.get("message", "")}',
                        'is_running': True,
                        'errors': [start_result.get("message", "")]
                    })
            else:
                return JsonResponse({
                    'status': 'warning',
                    'message': '流量监控已在运行中',
                    'is_running': True,
                    'errors': []
                })
        except Exception as e:
            logger.error(f"启动流量监控失败: {str(e)}", exc_info=True)
            return JsonResponse({
                'status': 'error',
                'message': f'启动失败: {str(e)}',
                'is_running': traffic_monitor.is_running,
                'errors': [str(e)]
            }, status=500)
    return JsonResponse({'status': 'error', 'message': '无效请求'}, status=400)

@staff_member_required
def stop_traffic_monitor(request):
    """停止流量监控API"""
    if request.method == 'POST':
        try:
            if traffic_monitor.is_running:  # 检查是否在运行
                traffic_monitor.stop_monitoring()
                return JsonResponse({
                    'status': 'success',
                    'message': '流量监控已停止',
                    'is_running': False
                })
            else:
                return JsonResponse({
                    'status': 'warning',
                    'message': '流量监控未在运行',
                    'is_running': False
                })
        except Exception as e:
            logger.error(f"停止流量监控失败: {e}")
            return JsonResponse({
                'status': 'error',
                'message': str(e),
                'is_running': traffic_monitor.is_running
            }, status=500)
    return JsonResponse({'status': 'error', 'message': '无效请求'}, status=400)

@staff_member_required
def get_monitor_status(request):
    """获取当前监控状态"""
    try:
        return JsonResponse({
            'status': 'success',
            'is_running': traffic_monitor.is_running,
            'interface': traffic_monitor.interface,
            'message': '运行中' if traffic_monitor.is_running else '已停止'
        })
    except Exception as e:
        logger.error(f"获取监控状态失败: {e}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@staff_member_required
def get_traffic_records(request):
    """获取流量记录列表"""
    records = TrafficAnalysisResult.objects.all().order_by('-id')
    data = [{
        'id': record.id,
        'pcap_file': record.pcap_file_path,
        'analyzer_type': record.analyzer_type,
        'packet_count': record.packet_count,
        'created_at': record.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'protocol_distribution': record.protocol_distribution
    } for record in records]
    return JsonResponse({'status': 'success', 'data': data})

@staff_member_required
def analyze_traffic_record(request, record_id):
    """分析特定流量记录"""
    try:
        record = TrafficAnalysisResult.objects.get(id=record_id)
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