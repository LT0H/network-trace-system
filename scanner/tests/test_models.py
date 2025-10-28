import pytest
from django.test import TestCase
from django.contrib.auth.models import User
from scanner.models import ScanTask, ScanResult
from django.utils import timezone

class ScanTaskModelTest(TestCase):
    """扫描任务模型测试"""
    
    def setUp(self):
        """测试前置设置"""
        self.user = User.objects.create_user(
            username='testuser', 
            password='testpass123'
        )
        self.task = ScanTask.objects.create(
            name='测试任务',
            target='192.168.1.1',
            scan_type='SYN_SCAN',
            created_by=self.user
        )
    
    def test_task_creation(self):
        """测试任务创建"""
        self.assertEqual(self.task.name, '测试任务')
        self.assertEqual(self.task.target, '192.168.1.1')
        self.assertEqual(self.task.status, 'PENDING')
        self.assertTrue(isinstance(self.task, ScanTask))
    
    def test_task_string_representation(self):
        """测试任务字符串表示"""
        expected = '测试任务 (等待中)'
        self.assertEqual(str(self.task), expected)
    
    def test_task_duration_calculation(self):
        """测试任务时长计算"""
        # 测试未开始的任务
        self.assertIsNone(self.task.get_duration())
        
        # 测试已完成的任务
        self.task.started_at = timezone.now()
        self.task.completed_at = self.task.started_at + timezone.timedelta(minutes=5)
        self.task.save()
        
        duration = self.task.get_duration()
        self.assertIsNotNone(duration)
        self.assertEqual(duration.total_seconds(), 300)

class ScanResultModelTest(TestCase):
    """扫描结果模型测试"""
    
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.task = ScanTask.objects.create(
            name='测试任务',
            target='192.168.1.1',
            scan_type='SYN_SCAN',
            created_by=self.user
        )
        self.result = ScanResult.objects.create(
            task=self.task,
            ip_address='192.168.1.1',
            port=80,
            state='open',
            service='http'
        )
    
    def test_result_creation(self):
        """测试结果创建"""
        self.assertEqual(self.result.ip_address, '192.168.1.1')
        self.assertEqual(self.result.port, 80)
        self.assertEqual(self.result.state, 'open')
        self.assertEqual(self.result.service, 'http')
    
    def test_result_string_representation(self):
        """测试结果字符串表示"""
        expected = '192.168.1.1:80 (open)'
        self.assertEqual(str(self.result), expected)
        
        # 测试没有端口的情况
        result_no_port = ScanResult.objects.create(
            task=self.task,
            ip_address='192.168.1.1',
            state='up'
        )
        expected_no_port = '192.168.1.1 (up)'
        self.assertEqual(str(result_no_port), expected_no_port)