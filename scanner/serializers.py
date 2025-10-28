from rest_framework import serializers
from .models import ScanTask, ScanResult

class ScanTaskSerializer(serializers.ModelSerializer):
    """扫描任务序列化器"""
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    duration = serializers.SerializerMethodField(read_only=True)
    created_by_name = serializers.CharField(source='created_by.username', read_only=True, allow_null=True)
    
    class Meta:
        model = ScanTask
        fields = [
            'id', 'name', 'target', 'scan_type', 'status', 'status_display',
            'progress', 'result_summary', 'created_at', 'started_at', 
            'completed_at', 'duration', 'created_by_name'
        ]
    
    def get_duration(self, obj):
        duration = obj.get_duration()
        return str(duration) if duration else None

class ScanResultSerializer(serializers.ModelSerializer):
    """扫描结果序列化器"""
    task_name = serializers.CharField(source='task.name', read_only=True)
    
    class Meta:
        model = ScanResult
        fields = [
            'id', 'task', 'task_name', 'ip_address', 'hostname', 'port',
            'protocol', 'state', 'service', 'service_version', 'ttl', 'rtt',
            'os_family', 'os_version', 'discovered_at'
        ]