import logging
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from scanner.task_manager import TaskManager
from scanner.topology import NetworkTopology
import json

logger = logging.getLogger(__name__)

# 初始化任务管理器和拓扑生成器
task_manager = TaskManager()
topology_generator = NetworkTopology()

@csrf_exempt
@require_http_methods(["POST"])
def create_task(request):
    """创建扫描任务"""
    try:
        data = json.loads(request.body)
        target = data.get("target")
        duration = int(data.get("duration", 3600))
        interval = int(data.get("interval", 60))
        
        if not target:
            return JsonResponse({"status": "error", "message": "目标不能为空"})
            
        task_id = task_manager.create_task(target, duration, interval)
        return JsonResponse({
            "status": "success", 
            "task_id": task_id,
            "message": "任务创建成功"
        })
    except Exception as e:
        logger.error(f"创建任务失败: {e}")
        return JsonResponse({"status": "error", "message": str(e)})

@csrf_exempt
@require_http_methods(["POST"])
def start_task(request):
    """启动扫描任务"""
    try:
        data = json.loads(request.body)
        task_id = data.get("task_id")
        
        if not task_id:
            return JsonResponse({"status": "error", "message": "任务ID不能为空"})
            
        result = task_manager.start_task(task_id)
        return JsonResponse(result)
    except Exception as e:
        logger.error(f"启动任务失败: {e}")
        return JsonResponse({"status": "error", "message": str(e)})

@csrf_exempt
@require_http_methods(["POST"])
def stop_task(request):
    """停止扫描任务"""
    try:
        data = json.loads(request.body)
        task_id = data.get("task_id")
        
        if not task_id:
            return JsonResponse({"status": "error", "message": "任务ID不能为空"})
            
        result = task_manager.stop_task(task_id)
        return JsonResponse(result)
    except Exception as e:
        logger.error(f"停止任务失败: {e}")
        return JsonResponse({"status": "error", "message": str(e)})

@require_http_methods(["GET"])
def get_task_status(request):
    """获取任务状态"""
    try:
        task_id = request.GET.get("task_id")
        
        if not task_id:
            return JsonResponse({"status": "error", "message": "任务ID不能为空"})
            
        status = task_manager.get_task_status(task_id)
        return JsonResponse({"status": "success", "data": status})
    except Exception as e:
        logger.error(f"获取任务状态失败: {e}")
        return JsonResponse({"status": "error", "message": str(e)})

@require_http_methods(["GET"])
def list_tasks(request):
    """列出所有任务"""
    try:
        tasks = task_manager.list_tasks()
        return JsonResponse({"status": "success", "data": tasks})
    except Exception as e:
        logger.error(f"列出任务失败: {e}")
        return JsonResponse({"status": "error", "message": str(e)})

@require_http_methods(["GET"])
def get_task_results(request):
    """获取任务结果"""
    try:
        task_id = request.GET.get("task_id")
        
        if not task_id:
            return JsonResponse({"status": "error", "message": "任务ID不能为空"})
            
        results = task_manager.get_task_results(task_id)
        
        # 生成拓扑图
        topology_generator.clear()
        for result in results.get("results", []):
            if "data" in result:
                topology_generator.add_flow_data(result["data"])
        
        topology_image = topology_generator.generate_topology_image(task_id)
        results["topology_image"] = topology_image
        
        return JsonResponse({"status": "success", "data": results})
    except Exception as e:
        logger.error(f"获取任务结果失败: {e}")
        return JsonResponse({"status": "error", "message": str(e)})