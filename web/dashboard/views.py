from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.utils import timezone
import os
import subprocess
import json
from .models import Task
from src.active_probe import ActiveProbe
from src.analyze_traffic import analyze_traffic_patterns
from src.analyze_traffic import generate_html_report, get_latest_file
from src.elasticsearch_client import ESClient

# 项目根目录
BASE_DIR = r"C:\Users\z1395\network_trace_system"
RESULTS_DIR = os.path.join(BASE_DIR, "task_results")
REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "reports")

# 确保结果目录存在
os.makedirs(RESULTS_DIR, exist_ok=True)

@login_required
def task_list(request):
    """任务列表页"""
    tasks = Task.objects.filter(created_by=request.user)
    return render(request, 'dashboard/task_list.html', {'tasks': tasks})

@login_required
def task_create(request):
    """创建任务"""
    if request.method == 'POST':
        try:
            task = Task(
                name=request.POST.get('name'),
                task_type=request.POST.get('task_type'),
                target=request.POST.get('target'),
                created_by=request.user
            )
            task.save()
            messages.success(request, "任务创建成功！")
            return redirect('task_list')
        except Exception as e:
            messages.error(request, f"创建失败：{str(e)}")
    
    return render(request, 'dashboard/task_create.html')

@login_required
def run_task(request, task_id):
    """执行任务"""
    task = get_object_or_404(Task, id=task_id, created_by=request.user)
    task.status = 'running'
    task.save()

    try:
        result_file = os.path.join(RESULTS_DIR, f"task_{task.id}_{timezone.now().strftime('%Y%m%d%H%M%S')}.json")
        
        if task.task_type == 'scan':
            # 端口扫描任务
            probe = ActiveProbe()
            result = probe.tcp_syn_scan(task.target)
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
        
        elif task.task_type == 'traffic':
            # 流量分析任务
            result = analyze_traffic_patterns()
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            
            # 同步到ES
            es_client = ESClient()
            es_result = es_client.bulk_insert_from_file(result_file)
            result['es_sync'] = es_result
        
        task.status = 'completed'
        task.result_path = result_file
        task.save()
        messages.success(request, "任务执行完成！")
    
    except Exception as e:
        task.status = 'failed'
        task.save()
        messages.error(request, f"任务执行失败：{str(e)}")
    
    return redirect('task_list')

@login_required
def task_results(request, task_id):
    """查看任务结果"""
    task = get_object_or_404(Task, id=task_id, created_by=request.user)
    results = None
    
    if task.result_path and os.path.exists(task.result_path):
        with open(task.result_path, 'r', encoding='utf-8') as f:
            results = json.load(f)
    
    return render(request, 'dashboard/task_results.html', {
        'task': task,
        'results': results
    })

def dashboard(request):
    """仪表盘视图，展示系统状态和摘要信息"""
    try:
        # 检查ES连接状态
        es_connected = False
        es_client = None
        try:
            es_client = ESClient()
            es_connected = True
        except:
            pass
        
        # 获取最新报告摘要
        latest_report_path = os.path.join(REPORT_DIR, "latest_report.json")
        report_summary = None
        
        if os.path.exists(latest_report_path):
            with open(latest_report_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
                report_summary = {
                    "analysis_time": report_data.get("analysis_time", ""),
                    "total_flows": report_data.get("total_flows", 0),
                    "malicious_count": report_data.get("malicious", {}).get("count", 0),
                    "malicious_ratio": report_data.get("malicious", {}).get("ratio", 0)
                }
        
        context = {
            "es_connected": es_connected,
            "latest_report": report_summary,
            "has_report": os.path.exists(latest_report_path)
        }
        
        return render(request, "dashboard.html", context)
    except Exception as e:
        return render(request, "error.html", {"message": str(e)})

def traffic_analysis(request):
    """流量分析报告视图"""
    try:
        # 生成或获取最新HTML报告
        html_path, msg = generate_html_report()
        
        if not html_path:
            return render(request, "error.html", {"message": f"无法生成分析报告：{msg}"})
        
        # 读取HTML内容并返回
        with open(html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        return HttpResponse(html_content)
    except Exception as e:
        return render(request, "error.html", {"message": str(e)})

def run_port_scan(request):
    """运行端口扫描的API"""
    if request.method == "POST":
        target_ip = request.POST.get("target_ip", "127.0.0.1")
        probe = ActiveProbe()
        result = probe.tcp_syn_scan(target_ip)
        return JsonResponse(result)
    return JsonResponse({"error": "请使用POST方法"})

def run_anomaly_detection(request):
    """运行异常检测的API"""
    if request.method == "POST":
        target_ip = request.POST.get("target_ip", "127.0.0.1")
        probe = ActiveProbe()
        result = probe.detect_anomaly_traffic(target_ip)
        return JsonResponse(result)
    return JsonResponse({"error": "请使用POST方法"})

def get_anomaly_results(request):
    """获取异常检测结果的API"""
    target_ip = request.GET.get("target_ip", "127.0.0.1")
    probe = ActiveProbe()
    result, msg = probe.get_latest_anomaly_results(target_ip)
    
    if result:
        return JsonResponse(result)
    return JsonResponse({"error": msg})