import pytest
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from scanner.models import ScanTask

class UserWorkflowTest(TestCase):
    """用户工作流测试"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.client.login(username='testuser', password='testpass123')
    
    def test_dashboard_access(self):
        """测试仪表盘访问"""
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '系统仪表盘')
    
    def test_task_creation_workflow(self):
        """测试任务创建工作流"""
        # 访问任务列表
        response = self.client.get(reverse('task_list'))
        self.assertEqual(response.status_code, 200)
        
        # 创建新任务
        task_data = {
            'name': '功能测试任务',
            'target': '127.0.0.1',
            'scan_type': 'SYN_SCAN',
            'ports': '80,443,22'
        }
        
        response = self.client.post(reverse('task_create'), task_data)
        self.assertEqual(response.status_code, 302)  # 重定向
        
        # 验证任务创建
        task = ScanTask.objects.filter(name='功能测试任务').first()
        self.assertIsNotNone(task)
        self.assertEqual(task.target, '127.0.0.1')
    
    def test_scan_result_view(self):
        """测试扫描结果查看"""
        # 创建测试任务和结果
        task = ScanTask.objects.create(
            name='结果测试任务',
            target='192.168.1.1',
            scan_type='SYN_SCAN',
            created_by=self.user
        )
        
        response = self.client.get(reverse('result_list'))
        self.assertEqual(response.status_code, 200)
        
        # 查看特定任务结果
        response = self.client.get(reverse('task_detail', args=[task.id]))
        self.assertEqual(response.status_code, 200)

class APITest(TestCase):
    """API接口测试"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='apiuser',
            password='apipass123'
        )
        self.client.login(username='apiuser', password='apipass123')
    
    def test_task_list_api(self):
        """测试任务列表API"""
        response = self.client.get('/api/tasks/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('success', response.json())
        self.assertTrue(response.json()['success'])
    
    def test_task_creation_api(self):
        """测试任务创建API"""
        task_data = {
            'name': 'API测试任务',
            'target': '10.0.0.1',
            'scan_type': 'SYN_SCAN'
        }
        
        response = self.client.post(
            '/api/tasks/create/', 
            task_data,
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertTrue(json_response['success'])
        self.assertIn('task_id', json_response)