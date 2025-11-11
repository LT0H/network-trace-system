from django.core.management.base import BaseCommand
from scanner.tasks import stop_traffic_monitoring

class Command(BaseCommand):
    help = '停止流量监听服务'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('停止流量监听服务...'))
        result = stop_traffic_monitoring.delay()
        self.stdout.write(self.style.SUCCESS(f'停止流量监听任务已提交，任务ID: {result.id}'))