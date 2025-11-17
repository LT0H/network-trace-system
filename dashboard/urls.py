from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard_home'),  # 首页对应dashboard视图
    path('topology/', views.topology_view, name='topology'),  # 网络拓扑页面
    path('reports/', views.reports_view, name='reports'),      # 报告页面
]