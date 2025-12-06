from django.urls import path
from . import views

urlpatterns = [
    # 流量监控页面
    path('traffic-monitor/', views.traffic_monitor_admin, name='traffic_monitor_admin'),
    # 启动监控API
    path('start-monitor/', views.start_traffic_capture, name='start_traffic_capture'),
    # 停止监控API
    path('stop-monitor/', views.stop_traffic_monitor, name='stop_traffic_monitor'),
    # 获取监控状态API
    path('monitor-status/', views.get_monitor_status, name='get_monitor_status'),
    # 获取记录列表API
    path('get-records/', views.get_traffic_records, name='get_traffic_records'),
    # 分析记录API
    path('analyze/<int:record_id>/', views.analyze_traffic_record, name='analyze_traffic_record'),
    path('tasks/', views.task_list_view, name='task_list'),
    path('tasks/create/', views.task_create_view, name='task_create'),
    path('tasks/<int:task_id>/', views.task_detail_view, name='task_detail'),
    path('results/', views.scan_results_view, name='scan_results'),
    path('traffic/', views.traffic_monitor_view, name='traffic_monitor'),
    path('api/traffic/capture/', views.start_traffic_capture, name='start_traffic_capture'),
    path('api/traffic/analyze/', views.analyze_traffic, name='analyze_traffic'),
    path('api/traffic/recent/', views.get_traffic_records, name='get_traffic_records'),
    path('api/tasks/<int:task_id>/start/', views.start_task_api, name='start_task_api'),
    path('api/tasks/<int:task_id>/stop/', views.stop_task_api, name='stop_task_api'),
]