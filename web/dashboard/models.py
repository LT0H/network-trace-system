from django.db import models
from django.contrib.auth.models import User, Group
from django.utils import timezone

class Task(models.Model):
    """扫描/分析任务模型"""
    TASK_TYPE_CHOICES = (
        ("tcp_syn_scan", "TCP SYN扫描"),
        ("anomaly_detect", "异常流量探测"),
        ("traffic_analyze", "流量数据分析"),
        ("ip_track", "IP轨迹追踪"),
    )
    
    TASK_STATUS_CHOICES = (
        ("pending", "待执行"),
        ("running", "执行中"),
        ("completed", "已完成"),
        ("failed", "失败"),
        ("cancelled", "已取消"),
    )
    
    name = models.CharField(max_length=100, verbose_name="任务名称")
    task_type = models.CharField(max_length=20, choices=TASK_TYPE_CHOICES, verbose_name="任务类型")
    target = models.CharField(max_length=500, verbose_name="目标（IP/文件路径）")
    params = models.JSONField(default=dict, verbose_name="任务参数", help_text="JSON格式，如{\"ports\":\"1-1000\",\"timeout\":10}")
    status = models.CharField(max_length=20, choices=TASK_STATUS_CHOICES, default="pending", verbose_name="任务状态")
    create_time = models.DateTimeField(auto_now_add=True, verbose_name="创建时间")
    start_time = models.DateTimeField(null=True, blank=True, verbose_name="开始时间")
    complete_time = models.DateTimeField(null=True, blank=True, verbose_name="完成时间")
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="tasks", verbose_name="创建人")
    result_path = models.FileField(upload_to="task_results/%Y/%m/%d", null=True, blank=True, verbose_name="结果文件路径")
    result_summary = models.JSONField(default=dict, verbose_name="结果摘要", help_text="任务结果的简要信息")
    
    class Meta:
        verbose_name = "任务管理"
        verbose_name_plural = "任务管理"
        ordering = ["-create_time"]
    
    def __str__(self):
        return f"{self.name} - {self.get_task_type_display()} - {self.get_status_display()}"
    
    def complete_task(self, result_summary=None, result_path=None):
        """完成任务"""
        self.status = "completed"
        self.complete_time = timezone.now()
        if result_summary:
            self.result_summary = result_summary
        if result_path:
            self.result_path = result_path
        self.save()
    
    def fail_task(self, error_msg):
        """标记任务失败"""
        self.status = "failed"
        self.complete_time = timezone.now()
        self.result_summary = {"error": error_msg}
        self.save()

class Role(models.Model):
    """RBAC角色模型（扩展Django Group）"""
    ROLE_LEVEL_CHOICES = (
        ("admin", "系统管理员"),
        ("security_admin", "安全管理员"),
        ("operator", "普通操作员"),
        ("viewer", "只读查看者"),
    )
    
    group = models.OneToOneField(Group, on_delete=models.CASCADE, verbose_name="关联用户组")
    role_level = models.CharField(max_length=20, choices=ROLE_LEVEL_CHOICES, unique=True, verbose_name="角色等级")
    description = models.CharField(max_length=200, blank=True, verbose_name="角色描述")
    create_time = models.DateTimeField(auto_now_add=True, verbose_name="创建时间")
    
    class Meta:
        verbose_name = "RBAC角色"
        verbose_name_plural = "RBAC角色"
    
    def __str__(self):
        return self.get_role_level_display()

class Permission(models.Model):
    """RBAC权限模型"""
    PERMISSION_TYPE_CHOICES = (
        ("task_create", "创建任务"),
        ("task_execute", "执行任务"),
        ("task_delete", "删除任务"),
        ("signature_update", "更新特征库"),
        ("user_manage", "用户管理"),
        ("system_config", "系统配置"),
    )
    
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="permissions", verbose_name="关联角色")
    permission_type = models.CharField(max_length=30, choices=PERMISSION_TYPE_CHOICES, verbose_name="权限类型")
    is_allowed = models.BooleanField(default=True, verbose_name="是否允许")
    description = models.CharField(max_length=200, blank=True, verbose_name="权限描述")
    
    class Meta:
        verbose_name = "RBAC权限"
        verbose_name_plural = "RBAC权限"
        unique_together = ("role", "permission_type")
    
    def __str__(self):
        return super().__str__()