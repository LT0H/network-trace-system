from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab

# 设置默认Django设置模块
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trace_system.settings')

app = Celery('trace_system')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

app.conf.beat_schedule = {
    # 任务名称（自定义）
    'analyze_traffic_periodically': {
        'task': 'scanner.tasks.your_periodic_task',  # 任务路径（对应上面定义的函数）
        'schedule': crontab(minute=0, hour='*/2'),   # 执行周期（秒），可使用 celery.schedules.crontab 定义复杂周期
    },
}

# 确保使用正确的Redis配置
app.conf.update(
    broker_url='redis://localhost:6379/0',
    result_backend='redis://localhost:6379/0',
    broker_connection_retry_on_startup=True,
)