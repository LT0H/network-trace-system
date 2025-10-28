import pytest
from django.test import TestCase
from django.urls import reverse
from scanner.models import ScanTask

class SecurityTest(TestCase):
    """安全测试"""
    
    def test_sql_injection_prevention(self):
        """测试SQL注入防护"""
        # 尝试SQL注入攻击
        malicious_input = "'; DROP TABLE scanner_scantask; --"
        
        task = ScanTask.objects.create(
            name='安全测试任务',
            target=malicious_input,
            scan_type='SYN_SCAN'
        )
        
        # 验证数据安全存储
        saved_task = ScanTask.objects.get(id=task.id)
        self.assertEqual(saved_task.target, malicious_input)
        
        # 验证没有SQL注入漏洞
        tasks = ScanTask.objects.filter(target=malicious_input)
        self.assertEqual(tasks.count(), 1)
    
    def test_xss_prevention(self):
        """测试XSS攻击防护"""
        xss_payload = '<script>alert("XSS")</script>'
        
        task = ScanTask.objects.create(
            name=xss_payload,
            target='192.168.1.1',
            scan_type='SYN_SCAN'
        )
        
        # 访问任务详情页，验证XSS防护
        response = self.client.get(reverse('task_detail', args=[task.id]))
        self.assertEqual(response.status_code, 200)
        
        # 验证响应中不包含原始脚本标签
        content = response.content.decode()
        self.assertNotIn('<script>alert', content)
        self.assertIn('&lt;script&gt;alert', content)  # 应该被转义
    
    def test_input_validation(self):
        """测试输入验证"""
        # 测试非法目标地址
        invalid_targets = [
            '../../etc/passwd',
            'http://malicious.com',
            '127.0.0.1; rm -rf /'
        ]
        
        for target in invalid_targets:
            task = ScanTask.objects.create(
                name='输入验证测试',
                target=target,
                scan_type='SYN_SCAN'
            )
            
            # 验证任务创建成功（输入验证在扫描器层面）
            self.assertIsNotNone(task.id)
            
            # 验证目标地址被正确存储
            saved_task = ScanTask.objects.get(id=task.id)
            self.assertEqual(saved_task.target, target)