import os
from celery import Celery
from django.conf import settings

# 设置Django的默认配置模块
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trace_system.settings')

# 创建Celery应用实例
app = Celery('trace_system')

# 从Django配置中加载Celery配置
app.config_from_object('django.conf:settings', namespace='CELERY')

# 自动发现任务（从所有已注册的Django应用中）
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)

@app.task(bind=True)
def debug_task(self):
    """调试任务，用于测试Celery是否正常工作"""
    print(f'Request: {self.request!r}')