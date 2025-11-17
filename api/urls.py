from django.urls import path
from . import views

urlpatterns = [
    path('tasks/', views.task_list_api, name='task_list'),
    path('results/', views.scan_results_api, name='scan_results'),
]