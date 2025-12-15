from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
import os
import subprocess
import json
from .models import Task
from src.active_probe import ActiveProbe
from src.analyze_traffic import analyze_traffic_patterns
from src.elasticsearch_client import ESClient

# 项目根目录
BASE_DIR = r"C:\Users\z1395\network_trace_system"
RESULTS_DIR = os.path.join(BASE_DIR, "task_results")

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