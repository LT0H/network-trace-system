from django.db import models
import json

class ScanTask(models.Model):
    """
    扫描任务模型
    存储扫描任务的基本信息和状态
    """
    SCAN_TYPE_CHOICES = (
        ('SYN_SCAN', 'SYN端口扫描'),
        ('UDP_SCAN', 'UDP端口扫描'),
        ('OS_DETECTION', '操作系统检测'),
        ('SERVICE_DETECTION', '服务版本检测'),
        ('FULL_SCAN', '全面扫描'),
    )
    
    STATUS_CHOICES = (
        ('PENDING', '等待中'),
        ('RUNNING', '进行中'),
        ('COMPLETED', '已完成'),
        ('FAILED', '失败'),
        ('CANCELLED', '已取消'),
    )
    
    # 任务基本信息
    name = models.CharField(max_length=200, verbose_name="任务名称")
    description = models.TextField(blank=True, verbose_name="任务描述")
    target = models.TextField(verbose_name="扫描目标", help_text="IP地址、网段或域名，多个用逗号分隔")
    scan_type = models.CharField(max_length=50, choices=SCAN_TYPE_CHOICES, verbose_name="扫描类型")
    
    # 扫描参数
    ports = models.CharField(max_length=500, default="1-1000", verbose_name="端口范围", 
                           help_text="例如: 80,443,1-1000")
    options = models.JSONField(default=dict, blank=True, verbose_name="扫描选项")
    
    # 任务状态
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING', verbose_name="状态")
    progress = models.IntegerField(default=0, verbose_name="进度百分比")
    result_summary = models.JSONField(default=dict, blank=True, verbose_name="结果摘要")
    
    # 时间戳
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="创建时间")
    started_at = models.DateTimeField(null=True, blank=True, verbose_name="开始时间")
    completed_at = models.DateTimeField(null=True, blank=True, verbose_name="完成时间")
    
    # 创建者（如果有多用户需求）
    created_by = models.ForeignKey('auth.User', on_delete=models.CASCADE, null=True, verbose_name="创建者")
    
    class Meta:
        verbose_name = "扫描任务"
        verbose_name_plural = "扫描任务"
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.get_status_display()})"
    
    def get_duration(self):
        """计算任务执行时长"""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

    def reset_task(self):
        """重置任务状态"""
        self.status = 'PENDING'
        self.progress = 0
        self.started_at = None
        self.completed_at = None
        self.result_summary = {}
        self.save()
        
        # 删除关联的扫描结果
        self.results.all().delete()

class ScanResult(models.Model):
    """
    扫描结果模型
    存储具体的扫描结果数据
    """
    # 关联任务
    task = models.ForeignKey(ScanTask, on_delete=models.CASCADE, related_name='results', verbose_name="所属任务")
    
    # 主机信息
    ip_address = models.GenericIPAddressField(verbose_name="IP地址")
    hostname = models.CharField(max_length=255, blank=True, verbose_name="主机名")
    mac_address = models.CharField(max_length=17, blank=True, verbose_name="MAC地址")
    vendor = models.CharField(max_length=255, blank=True, verbose_name="设备厂商")
    
    # 端口信息
    port = models.IntegerField(null=True, blank=True, verbose_name="端口号")
    protocol = models.CharField(max_length=10, default='tcp', verbose_name="协议")
    state = models.CharField(max_length=20, verbose_name="状态")  # open, closed, filtered, unfiltered
    service = models.CharField(max_length=100, blank=True, verbose_name="服务名称")
    service_version = models.CharField(max_length=255, blank=True, verbose_name="服务版本")
    
    # 网络特征
    ttl = models.IntegerField(null=True, blank=True, verbose_name="TTL值")
    rtt = models.FloatField(null=True, blank=True, verbose_name="往返时间(ms)")
    
    # 指纹信息
    os_family = models.CharField(max_length=100, blank=True, verbose_name="操作系统家族")
    os_version = models.CharField(max_length=100, blank=True, verbose_name="操作系统版本")
    fingerprint = models.JSONField(default=dict, verbose_name="设备指纹")
    
    # 时间戳
    discovered_at = models.DateTimeField(auto_now_add=True, verbose_name="发现时间")
    
    class Meta:
        verbose_name = "扫描结果"
        verbose_name_plural = "扫描结果"
        ordering = ['task', 'ip_address', 'port']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['task', 'state']),
        ]
    
    def __str__(self):
        if self.port:
            return f"{self.ip_address}:{self.port} ({self.state})"
        return f"{self.ip_address} ({self.state})"


class NetworkTopology(models.Model):
    """
    网络拓扑模型
    存储网络设备之间的关系
    """
    task = models.ForeignKey(ScanTask, on_delete=models.CASCADE, verbose_name="关联任务")
    source_ip = models.GenericIPAddressField(verbose_name="源IP")
    destination_ip = models.GenericIPAddressField(verbose_name="目标IP")
    connection_type = models.CharField(max_length=50, verbose_name="连接类型")
    metadata = models.JSONField(default=dict, verbose_name="元数据")
    
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="创建时间")
    
    class Meta:
        verbose_name = "网络拓扑"
        verbose_name_plural = "网络拓扑"