from django.contrib import admin
from django.urls import reverse
from django.utils.html import format_html
from .models import TrafficAnalysisResult

class TrafficAnalysisResultAdmin(admin.ModelAdmin):
    list_display = ('id', 'pcap_file_path', 'analyzer_type', 'packet_count', 'created_at', 'is_analyzed', 'monitor_link')
    list_filter = ('analyzer_type', 'created_at', 'is_analyzed')
    search_fields = ('pcap_file_path',)
    
    def monitor_link(self, obj):
        url = reverse('traffic_monitor_admin')
        return format_html(f'<a href="{url}">流量监控面板</a>')
    monitor_link.short_description = '监控面板'

admin.site.register(TrafficAnalysisResult, TrafficAnalysisResultAdmin)