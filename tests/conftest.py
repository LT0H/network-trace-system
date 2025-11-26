import pytest
import os
import django
from django.test import TestCase
from django.conf import settings

# 设置Django环境
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trace_system.settings')
django.setup()

@pytest.fixture(scope='session')
def django_db_setup():
    """设置测试数据库"""
    from django.test.utils import setup_test_environment, teardown_test_environment
    from django.db import connection
    
    setup_test_environment()
    connection.creation.create_test_db()

@pytest.fixture
def test_user(django_db_setup):
    """创建测试用户"""
    from django.contrib.auth.models import User
    return User.objects.create_user(
        username='testuser',
        password='testpass123',
        email='test@example.com'
    )

@pytest.fixture
def test_task(django_db_setup, test_user):
    """创建测试扫描任务"""
    from scanner.models import ScanTask
    return ScanTask.objects.create(
        name='测试扫描任务',
        target='127.0.0.1',
        scan_type='SYN_SCAN',
        created_by=test_user
    )

@patch('scanner.tasks.ScapyScanner')
def test_run_scan_task_ignore_response(self, mock_scanner):
    """测试忽略应答的扫描逻辑"""
    # 模拟扫描器不返回任何应答但仍记录扫描结果
    mock_instance = MagicMock()
    mock_instance.syn_scan.return_value = [
        {'ip_address': '127.0.0.1', 'port': 80, 'state': 'scanned'},
        {'ip_address': '127.0.0.1', 'port': 443, 'state': 'scanned'}
    ]
    mock_scanner.return_value = mock_instance
    
    # 执行任务
    result = run_scan_task(self.task.id)
    
    # 验证任务状态更新
    self.task.refresh_from_db()
    self.assertEqual(self.task.status, 'COMPLETED')
    self.assertEqual(self.task.progress, 100)
    
    # 验证结果保存（即使没有应答也应保存）
    from scanner.models import ScanResult
    results = ScanResult.objects.filter(task=self.task)
    self.assertEqual(results.count(), 2)  # 应该有2条记录，而不是根据应答判断