"""开发环境配置入口"""
import os
from .base import *

# 仅在明确指定生产环境时才加载production.py
current_env = os.environ.get('DJANGO_ENV', 'development')
if current_env == 'production':
    try:
        from .production import *
    except ImportError:
        pass
else:
    # 开发环境强制启用DEBUG和本地主机
    DEBUG = True
    ALLOWED_HOSTS = ['127.0.0.1', 'localhost']