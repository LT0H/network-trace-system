from django.urls import path
from . import views

urlpatterns = [
    path('tasks/', views.task_list_api, name='task_list'),
    path('results/', views.scan_results_api, name='scan_results'),
    path('topology/', views.topology_data_api, name='api_topology_data'),
]