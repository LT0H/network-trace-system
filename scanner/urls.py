from django.urls import path
from . import views

urlpatterns = [
    path('admin/traffic-monitor/', views.traffic_monitor_admin, name='traffic_monitor_admin'),
    path('api/traffic/start/', views.start_traffic_monitor, name='start_traffic_monitor'),
    path('api/traffic/stop/', views.stop_traffic_monitor, name='stop_traffic_monitor'),
    path('api/traffic/records/', views.get_traffic_records, name='get_traffic_records'),
    path('api/traffic/analyze/<int:record_id>/', views.analyze_traffic_record, name='analyze_traffic_record'),
]