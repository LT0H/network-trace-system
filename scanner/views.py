import json
import os
import subprocess
from django.conf import settings
from .models import TrafficFlow, TrafficAnalysis
from rest_framework.decorators import api_view
from django.shortcuts import get_object_or_404, render
from .models import ScanTask
from django.http import JsonResponse
from django.contrib import messages
from django.utils import timezone
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from .traffic_monitor import TrafficMonitor
from .models import TrafficAnalysisResult
from .models import ScanTask, ScanResult
import logging

logger = logging.getLogger(__name__)

# 实例化流量监控器
traffic_monitor = TrafficMonitor()

@login_required
def task_list_view(request):
    """任务列表网页视图"""
    tasks = ScanTask.objects.all().order_by('-created_at')
    context = {
        'page_title': '扫描任务列表',
        'tasks': tasks
    }
    return render(request, 'scanner/task_list.html', context)

@login_required
def scan_results_view(request):
    """扫描结果网页视图"""
    results = ScanResult.objects.select_related('task').order_by('-discovered_at')
    context = {
        'page_title': '扫描结果',
        'results': results
    }
    return render(request, 'scanner/scan_results.html', context)

@staff_member_required
def traffic_monitor_admin(request):
    """流量监控管理员页面"""
    return render(request, 'scanner/traffic_monitor_admin.html')

@staff_member_required
def start_traffic_monitor(request):
    """启动流量监控API"""
    if request.method == 'POST':
        try:
            # 增加更严格的状态检查
            if traffic_monitor.is_running:
                return JsonResponse({
                    'status': 'warning',
                    'message': '流量监控已在运行中',
                    'is_running': True,
                    'errors': []
                })
            
            # 启动监控并获取启动结果
            start_result = traffic_monitor.start_monitoring()
            if start_result.get("status") == "success":
                return JsonResponse({
                    'status': 'success',
                    'message': '流量监控已启动',
                    'is_running': True,
                    'errors': []
                })
            else:
                return JsonResponse({
                    'status': 'error',
                    'message': f'启动失败: {start_result.get("message", "")}',
                    'is_running': traffic_monitor.is_running,
                    'errors': [start_result.get("message", "")]
                }, status=500)
            
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
def task_create_view(request):
    """创建任务的视图函数"""
    if request.method == 'POST':
        try:
            # 1. 获取前端提交的任务数据
            name = request.POST.get('name')
            target = request.POST.get('target')
            scan_type = request.POST.get('scan_type', 'basic')
            ports = request.POST.get('ports', '')
            description = request.POST.get('description', '')
            
            # 2. 基本数据验证
            if not all([name, target]):
                return JsonResponse({
                    'status': 'error', 
                    'message': '任务名称和目标不能为空'
                }, status=400)
            
            # 3. 创建并保存任务到数据库
            task = ScanTask(
                name=name,
                target=target,
                scan_type=scan_type,
                ports=ports,
                description=description,
                status='PENDING',  # 初始状态为"待执行"
                progress=0,
                created_by=request.user,  # 关联创建者
                created_at=timezone.now()
            )
            task.save()  # 保存到数据库
            
            # 4. 返回包含任务ID的成功响应（便于前端跳转）
            return JsonResponse({
                'status': 'success', 
                'message': '任务创建成功',
                'task_id': task.id  # 新增任务ID，方便前端处理
            })
            
        except Exception as e:
            # 捕获异常并返回错误信息
            return JsonResponse({
                'status': 'error', 
                'message': f'任务创建失败：{str(e)}'
            }, status=500)
    
    # GET 请求返回创建任务的页面
    return render(request, 'scanner/task_create.html')

def task_detail_view(request, task_id):
    """查看任务详情的视图函数"""
    task = get_object_or_404(ScanTask, id=task_id)
    return render(request, 'scanner/task_detail.html', {'task': task})

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

@login_required
def traffic_monitor_view(request):
    """流量监控面板"""
    # 获取最近的流量数据
    recent_flows = TrafficFlow.objects.order_by('-timestamp')[:100]
    recent_analyses = TrafficAnalysis.objects.order_by('-analysis_time')[:10]
    
    context = {
        'page_title': '流量监控',
        'recent_flows': recent_flows,
        'recent_analyses': recent_analyses
    }
    return render(request, 'scanner/traffic_monitor.html', context)

@api_view(['POST'])
@login_required
def start_traffic_capture(request):
    """启动流量捕获和分析"""
    try:
        interface = request.data.get('interface', 'eth0')
        duration = request.data.get('duration', 300)  # 默认捕获5分钟
        
        # 启动CICFlowMeter捕获流量
        cicflow_path = os.path.join(settings.BASE_DIR, 'third_party', 'CICFlowMeter')
        output_dir = os.path.join(settings.BASE_DIR, 'traffic_data')
        os.makedirs(output_dir, exist_ok=True)
        
        # 启动后台进程运行CICFlowMeter
        cmd = f'java -jar {cicflow_path}/target/CICFlowMeter-4.0.jar -i {interface} -o {output_dir}'
        subprocess.Popen(cmd, shell=True)
        
        return JsonResponse({
            'success': True,
            'message': f'已开始在接口 {interface} 上捕获流量，将持续 {duration} 秒'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)

@api_view(['POST'])
@login_required
def analyze_traffic(request):
    """使用ws-traffic-analyze-kit分析流量"""
    try:
        traffic_file = request.data.get('traffic_file')
        if not traffic_file:
            return JsonResponse({
                'success': False,
                'error': '请指定流量文件'
            }, status=400)
        
        # 运行ws-traffic-analyze-kit分析
        analyze_script = os.path.join(settings.BASE_DIR, 'third_party', 'ws-traffic-analyze-kit', 'analyze.py')
        result = subprocess.check_output(['python', analyze_script, traffic_file], stderr=subprocess.STDOUT)
        
        # 解析结果
        analysis_result = json.loads(result)
        
        # 保存分析结果到数据库
        analysis = TrafficAnalysis.objects.create(
            analysis_type='full_analysis',
            result_summary=analysis_result.get('summary', {}),
            detailed_report=json.dumps(analysis_result.get('details', {}), indent=2)
        )
        
        return JsonResponse({
            'success': True,
            'analysis_id': analysis.id,
            'result': analysis_result
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)