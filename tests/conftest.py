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