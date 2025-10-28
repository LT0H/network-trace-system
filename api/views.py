from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from scanner.models import ScanTask, ScanResult
from scanner.serializers import ScanTaskSerializer, ScanResultSerializer
import json

@api_view(['GET'])
def task_list_api(request):
    """获取任务列表API"""
    tasks = ScanTask.objects.all().order_by('-created_at')
    serializer = ScanTaskSerializer(tasks, many=True)
    return Response({
        'success': True,
        'data': serializer.data,
        'total': tasks.count()
    })

@api_view(['GET'])
def task_status_api(request, task_id):
    """获取任务状态API"""
    task = get_object_or_404(ScanTask, id=task_id)
    return Response({
        'success': True,
        'task_id': task_id,
        'status': task.status,
        'status_text': task.get_status_display(),
        'progress': task.progress
    })

@api_view(['POST'])
def create_task_api(request):
    """创建扫描任务API"""
    from scanner.tasks import run_scan_task
    
    try:
        # 创建扫描任务记录
        task = ScanTask.objects.create(
            name=request.data.get('name'),
            target=request.data.get('target'),
            scan_type=request.data.get('scan_type'),
            ports=request.data.get('ports', '1-1000'),
            created_by=request.user if request.user.is_authenticated else None
        )
        
        # 异步执行扫描任务
        run_scan_task.delay(task.id)
        
        return Response({
            'success': True,
            'task_id': task.id,
            'message': '任务创建成功，正在后台执行'
        })
        
    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=400)

@api_view(['GET'])
def scan_results_api(request):
    """获取扫描结果API"""
    task_id = request.GET.get('task_id')
    ip_address = request.GET.get('ip_address')
    state = request.GET.get('state')
    
    results = ScanResult.objects.all()
    
    if task_id:
        results = results.filter(task_id=task_id)
    if ip_address:
        results = results.filter(ip_address=ip_address)
    if state:
        results = results.filter(state=state)
    
    serializer = ScanResultSerializer(results, many=True)
    return Response({
        'success': True,
        'data': serializer.data,
        'total': results.count()
    })

@api_view(['GET'])
def topology_data_api(request):
    """获取网络拓扑数据API"""
    from dashboard.views import get_topology_data
    
    try:
        data = get_topology_data()
        return Response({
            'success': True,
            'data': data
        })
    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=500)