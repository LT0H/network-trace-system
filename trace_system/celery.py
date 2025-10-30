from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# 设置默认Django设置模块
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trace_system.settings')

app = Celery('trace_system')

# 使用Django的设置文件配置Celery
app.config_from_object('django.conf:settings', namespace='CELERY')

# 从所有已注册的Django app中加载任务模块
app.autodiscover_tasks()

# 确保使用正确的Redis配置
app.conf.update(
    broker_url='redis://localhost:6379/0',
    result_backend='redis://localhost:6379/0',
    broker_connection_retry_on_startup=True,
)