import pytest
from django.test import TestCase
from unittest.mock import patch, MagicMock
from scanner.models import ScanTask
from scanner.tasks import run_scan_task, cleanup_old_tasks

class ScanTaskTest(TestCase):
    """扫描任务测试"""
    
    def setUp(self):
        self.task = ScanTask.objects.create(
            name='集成测试任务',
            target='127.0.0.1',
            scan_type='SYN_SCAN'
        )
    
    @patch('scanner.tasks.ScapyScanner')
    def test_run_scan_task_success(self, mock_scanner):
        """测试成功执行扫描任务"""
        # 模拟扫描器返回结果
        mock_instance = MagicMock()
        mock_instance.execute_scan.return_value = [
            {'ip_address': '127.0.0.1', 'port': 80, 'state': 'open'}
        ]
        mock_scanner.return_value = mock_instance
        
        # 执行任务
        result = run_scan_task(self.task.id)
        
        # 验证任务状态更新
        self.task.refresh_from_db()
        self.assertEqual(self.task.status, 'COMPLETED')
        self.assertEqual(self.task.progress, 100)
        
        # 验证结果保存
        from scanner.models import ScanResult
        results = ScanResult.objects.filter(task=self.task)
        self.assertEqual(results.count(), 1)
        self.assertEqual(results.first().port, 80)
    
    def test_run_scan_task_invalid_id(self):
        """测试无效任务ID"""
        result = run_scan_task(99999)  # 不存在的ID
        
        self.assertEqual(result['status'], 'failed')
        self.assertIn('不存在', result['error'])
    
    @patch('scanner.tasks.ScapyScanner')
    def test_run_scan_task_exception(self, mock_scanner):
        """测试任务执行异常"""
        mock_instance = MagicMock()
        mock_instance.execute_scan.side_effect = Exception('扫描失败')
        mock_scanner.return_value = mock_instance
        
        result = run_scan_task(self.task.id)
        
        self.task.refresh_from_db()
        self.assertEqual(self.task.status, 'FAILED')

class CleanupTaskTest(TestCase):
    """清理任务测试"""
    
    def test_cleanup_old_tasks(self):
        """测试清理旧任务"""
        from django.utils import timezone
        from datetime import timedelta
        
        # 创建旧任务和新任务
        old_task = ScanTask.objects.create(
            name='旧任务',
            target='192.168.1.1',
            scan_type='SYN_SCAN',
            created_at=timezone.now() - timedelta(days=31)
        )
        
        new_task = ScanTask.objects.create(
            name='新任务',
            target='192.168.1.2',
            scan_type='SYN_SCAN',
            created_at=timezone.now() - timedelta(days=29)
        )
        
        # 执行清理
        result = cleanup_old_tasks(days=30)
        
        # 验证结果
        self.assertIn('已清理 1 个', result)
        self.assertFalse(ScanTask.objects.filter(id=old_task.id).exists())
        self.assertTrue(ScanTask.objects.filter(id=new_task.id).exists())