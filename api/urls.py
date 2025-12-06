from django.urls import path
from . import views

urlpatterns = [
    path('tasks/', views.task_list_api, name='task_list'),
    path('results/', views.scan_results_api, name='scan_results'),
    path('task-status/<int:task_id>/', views.task_status_api, name='task_status_api'),
    path('topology/', views.topology_data_api, name='api_topology_data'),
]