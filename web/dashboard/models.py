from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Task(models.Model):
    TASK_TYPES = (
        ('scan', '端口扫描'),
        ('traffic', '流量分析'),
        ('anomaly', '异常检测'),
    )
    
    name = models.CharField(max_length=100, verbose_name="任务名称")
    task_type = models.CharField(max_length=20, choices=TASK_TYPES, verbose_name="任务类型")
    target = models.CharField(max_length=200, verbose_name="目标（IP/网段）")
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="创建者")
    created_at = models.DateTimeField(default=timezone.now, verbose_name="创建时间")
    status = models.CharField(max_length=20, default='pending', verbose_name="状态")
    result_path = models.CharField(max_length=500, blank=True, null=True, verbose_name="结果路径")

    class Meta:
        verbose_name = "监控任务"
        verbose_name_plural = "监控任务"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.get_task_type_display()})"