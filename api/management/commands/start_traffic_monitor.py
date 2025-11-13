from django.core.management.base import BaseCommand
from api.traffic_monitor import TrafficMonitor

class Command(BaseCommand):
    help = '启动流量监控服务'

    def handle(self, *args, **options):
        monitor = TrafficMonitor()
        self.stdout.write(self.style.SUCCESS('成功启动流量监控服务'))
        monitor.start_monitoring()
        
        # 保持命令运行
        try:
            while True:
                import time
                time.sleep(3600)
        except KeyboardInterrupt:
            monitor.stop_monitoring()
            self.stdout.write(self.style.SUCCESS('已停止流量监控服务'))