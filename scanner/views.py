import json
import os
import subprocess
from django.conf import settings
from .models import TrafficFlow, TrafficAnalysis, TrafficAnalysisResult, ScanTask, ScanResult
from rest_framework.decorators import api_view
from django.shortcuts import get_object_or_404, render
from django.http import JsonResponse
from django.contrib import messages
from django.utils import timezone
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from .traffic_monitor import TrafficMonitor
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

@api_view(['POST'])
@login_required
def start_traffic_capture(request):
    """启动流量捕获和分析"""
    try:
        # 从请求数据获取参数，支持form-data和JSON
        if request.content_type == 'application/json':
            data = request.data
        else:
            data = request.POST
        
        interface = data.get('interface', '')
        duration = int(data.get('duration', 300))  # 默认捕获5分钟
        
        # 验证接口参数
        if not interface:
            return JsonResponse({
                'success': False,
                'error': '请指定网络接口'
            }, status=400)
        
        # 检查CICFlowMeter是否存在
        cicflow_jar = os.path.join(settings.CIC_FLOW_METER_PATH, 'target', 'CICFlowMeter-4.0.jar')
        if not os.path.exists(cicflow_jar):
            return JsonResponse({
                'success': False,
                'error': f'CICFlowMeter JAR文件不存在: {cicflow_jar}\n请确保已正确编译CICFlowMeter项目'
            }, status=400)
        
        # 确保输出目录存在
        output_dir = os.path.join(settings.BASE_DIR, 'traffic_data', 'cic_output')
        os.makedirs(output_dir, exist_ok=True)
        
        # 启动后台进程运行CICFlowMeter
        cmd = f'java -jar "{cicflow_jar}" -i {interface} -o "{output_dir}"'
        subprocess.Popen(cmd, shell=True)
        
        # 设置定时器，在指定时间后停止捕获
        from threading import Timer
        def stop_capture():
            # 这里添加停止捕获的逻辑
            pass
        
        Timer(duration, stop_capture).start()
        
        return JsonResponse({
            'success': True,
            'message': f'已开始在接口 {interface} 上捕获流量，将持续 {duration} 秒',
            'output_dir': output_dir
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

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
                'message': '任务创建成功，请手动启动任务',
                'task_id': task.id
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
def start_task_api(request, task_id):
    """启动指定任务"""
    try:
        task = get_object_or_404(ScanTask, id=task_id)
        
        if task.status == 'RUNNING':
            return JsonResponse({
                'success': False,
                'error': '任务正在运行中'
            }, status=400)
            
        # 更新任务状态
        task.status = 'PENDING'
        task.progress = 0
        task.save()
        
        # 调用Celery任务
        from .tasks import run_scan_task
        run_scan_task.delay(task.id)
        
        return JsonResponse({
            'success': True,
            'message': '任务已开始'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['POST'])
@login_required
def stop_task_api(request, task_id):
    """停止指定任务"""
    try:
        task = get_object_or_404(ScanTask, id=task_id)
        
        if task.status != 'RUNNING':
            return JsonResponse({
                'success': False,
                'error': '任务不在运行中'
            }, status=400)
            
        # 这里需要根据实际情况实现停止任务的逻辑
        # 例如，通过Celery的revoke方法撤销任务
        from celery.task.control import revoke
        revoke(task.celery_task_id, terminate=True)
        
        # 更新任务状态
        task.status = 'STOPPED'
        task.save()
        
        return JsonResponse({
            'success': True,
            'message': '任务已停止'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['POST'])
@login_required
def analyze_traffic(request):
    """分析流量数据"""
    try:
        # 获取分析所需的参数
        if request.content_type == 'application/json':
            data = request.data
        else:
            data = request.POST
            
        file_path = data.get('file_path')
        if not file_path or not os.path.exists(file_path):
            return JsonResponse({
                'success': False,
                'error': '无效的文件路径'
            }, status=400)
        
        # 检查分析脚本是否存在
        analyze_script = os.path.join(settings.WS_ANALYZER_PATH, 'analyze.py')
        if not os.path.exists(analyze_script):
            return JsonResponse({
                'success': False,
                'error': f'分析脚本不存在: {analyze_script}'
            }, status=400)
        
        # 确保输出目录存在
        output_dir = os.path.join(settings.BASE_DIR, 'traffic_data', 'ws_output')
        os.makedirs(output_dir, exist_ok=True)
        
        # 构建输出文件名
        filename = os.path.basename(file_path)
        output_file = os.path.join(output_dir, f"analysis_{filename}.json")
        
        # 运行ws-traffic-analyze-kit分析
        cmd = [
            'python', analyze_script,
            '-f', file_path,
            '-o', output_file
        ]
        
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding='utf-8'
        )
        
        if result.returncode != 0:
            return JsonResponse({
                'success': False,
                'error': f'分析失败: {result.stderr}',
                'return_code': result.returncode
            }, status=500)
        
        # 验证输出文件
        if not os.path.exists(output_file):
            return JsonResponse({
                'success': False,
                'error': '分析完成但未生成输出文件'
            }, status=500)
            
        # 保存分析结果到数据库
        with open(output_file, 'r') as f:
            analysis_data = json.load(f)
            
        TrafficAnalysisResult.objects.create(
            pcap_file_path=file_path,
            analyzer_type="ws",
            analysis_result=analysis_data,
            packet_count=len(analysis_data.get('packets', [])),
            protocol_distribution=analysis_data.get('protocol_distribution', {})
        )
        
        return JsonResponse({
            'success': True,
            'message': '流量分析完成',
            'result': {}  # 这里添加分析结果
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)