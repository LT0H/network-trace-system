from django.contrib import admin
from django.utils.html import format_html
from django.contrib import messages
from django.http import HttpResponseRedirect
from .models import ScanTask, ScanResult, NetworkTopology

@admin.register(ScanTask)
class ScanTaskAdmin(admin.ModelAdmin):
    """扫描任务管理界面"""
    list_display = ['name', 'target', 'scan_type', 'status', 'progress_bar', 
                   'created_at', 'created_by']
    list_filter = ['scan_type', 'status', 'created_at']
    search_fields = ['name', 'target', 'description']
    readonly_fields = ['created_at', 'started_at', 'completed_at', 'progress']
    fieldsets = (
        ('基本信息', {
            'fields': ('name', 'description', 'created_by')
        }),
        ('扫描配置', {
            'fields': ('target', 'scan_type', 'ports', 'options')
        }),
        ('任务状态', {
            'fields': ('status', 'progress', 'result_summary')
        }),
        ('时间信息', {
            'fields': ('created_at', 'started_at', 'completed_at')
        }),
    )
    
    def run_selected_tasks(self, request, queryset):
        """
        运行选中的扫描任务
        """
        from .tasks import run_scan_task  # 延迟导入，避免循环依赖
        
        for task in queryset:
            if task.status in ['PENDING', 'FAILED']:
                # 重置任务状态为等待中
                task.status = 'PENDING'
                task.progress = 0
                task.started_at = None
                task.completed_at = None
                task.save()
                
                # 异步执行扫描任务
                run_scan_task.delay(task.id)
                self.message_user(
                    request, 
                    f"任务 '{task.name}' 已开始执行", 
                    messages.SUCCESS
                )
            elif task.status == 'RUNNING':
                self.message_user(
                    request, 
                    f"任务 '{task.name}' 正在运行中", 
                    messages.WARNING
                )
            elif task.status == 'COMPLETED':
                self.message_user(
                    request, 
                    f"任务 '{task.name}' 已完成，如需重新执行请先重置状态", 
                    messages.INFO
                )
        
        # 返回当前页面
        return HttpResponseRedirect(request.get_full_path())
    
    run_selected_tasks.short_description = "运行选中的扫描任务"
    
    def reset_selected_tasks(self, request, queryset):
        """
        重置选中的扫描任务
        """
        for task in queryset:
            task.status = 'PENDING'
            task.progress = 0
            task.started_at = None
            task.completed_at = None
            task.result_summary = {}
            task.save()
            
            # 删除关联的扫描结果
            task.results.all().delete()
            
            self.message_user(
                request, 
                f"任务 '{task.name}' 已重置", 
                messages.SUCCESS
            )
    
    reset_selected_tasks.short_description = "重置选中的扫描任务"
    
    def view_scan_results(self, request, queryset):
        """
        查看扫描结果
        """
        if queryset.count() == 1:
            task = queryset.first()
            # 重定向到任务详情页
            from django.urls import reverse
            url = reverse('admin:scanner_scantask_change', args=[task.id])
            return HttpResponseRedirect(url + '#scanresults')
        else:
            self.message_user(
                request, 
                "请选择单个任务查看结果", 
                messages.WARNING
            )
    
    view_scan_results.short_description = "查看扫描结果"
    
    # actions 配置必须在所有方法定义之后
    actions = ['run_selected_tasks', 'reset_selected_tasks', 'view_scan_results']
    
    def progress_bar(self, obj):
        """在列表页显示进度条"""
        color = 'green' if obj.status == 'COMPLETED' else 'blue' if obj.status == 'RUNNING' else 'gray'
        return format_html(
            '<div style="width:100px;background-color:lightgray;border-radius:5px;">'
            '<div style="width:{}%;background-color:{};height:20px;border-radius:5px;text-align:center;color:white;">{}%</div>'
            '</div>',
            obj.progress, color, obj.progress
        )
    progress_bar.short_description = '进度'
    
    def save_model(self, request, obj, form, change):
        """保存模型时自动设置创建者"""
        if not obj.pk:  # 新建对象
            obj.created_by = request.user
        super().save_model(request, obj, form, change)

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    """扫描结果管理界面"""
    list_display = ['ip_address', 'port', 'protocol', 'state', 'service', 'task']
    list_filter = ['state', 'protocol', 'discovered_at', 'task']
    search_fields = ['ip_address', 'hostname', 'service']
    readonly_fields = ['discovered_at']
    
    def has_add_permission(self, request):
        """禁止手动添加扫描结果"""
        return False

@admin.register(NetworkTopology)
class NetworkTopologyAdmin(admin.ModelAdmin):
    """网络拓扑管理界面"""
    list_display = ['source_ip', 'destination_ip', 'connection_type', 'task']
    list_filter = ['connection_type', 'created_at']
    search_fields = ['source_ip', 'destination_ip']

# 设置Admin站点标题
admin.site.site_header = "网络扫描溯源系统管理后台"
admin.site.site_title = "扫描溯源系统"
admin.site.index_title = "系统管理"