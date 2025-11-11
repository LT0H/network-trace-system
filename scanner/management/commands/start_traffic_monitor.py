from django.core.management.base import BaseCommand
from scanner.tasks import start_traffic_monitoring

class Command(BaseCommand):
    help = '启动流量监听服务'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('启动流量监听服务...'))
        result = start_traffic_monitoring.delay()
        self.stdout.write(self.style.SUCCESS(f'流量监听任务已启动，任务ID: {result.id}'))