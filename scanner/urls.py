from django.urls import path
from . import views

urlpatterns = [
    # 流量监控页面
    path('traffic-monitor/', views.traffic_monitor_admin, name='traffic_monitor_admin'),
    # 启动监控API
    path('start-monitor/', views.start_traffic_monitor, name='start_traffic_monitor'),
    # 停止监控API
    path('stop-monitor/', views.stop_traffic_monitor, name='stop_traffic_monitor'),
    # 获取记录列表API
    path('get-records/', views.get_traffic_records, name='get_traffic_records'),
    # 分析记录API
    path('analyze/<int:record_id>/', views.analyze_traffic_record, name='analyze_traffic_record'),
]