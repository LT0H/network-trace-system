from celery import Celery
from celery.schedules import crontab

app = Celery('network_trace_system')

# 配置定时任务
app.conf.beat_schedule = {
    'analyze-traffic-every-2-hours': {
        'task': 'scanner.tasks.analyze_traffic_periodically',
        'schedule': crontab(minute=0, hour='*/2'),  # 每2小时执行一次
    },
}