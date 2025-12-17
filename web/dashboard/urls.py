from django.urls import path
from . import views

urlpatterns = [
    path('', views.task_list, name='task_list'),  # 任务列表
    path('create/', views.task_create, name='task_create'),  # 创建任务
    path('run/<int:task_id>/', views.run_task, name='run_task'),  # 执行任务
    path('results/<int:task_id>/', views.task_results, name='task_results'),  # 任务结果
    path('delete/<int:task_id>/', views.delete_task, name='delete_task'), #删除过往任务
]