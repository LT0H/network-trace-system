"""
基础设置文件
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# 关键配置：添加URL根配置
ROOT_URLCONF = 'trace_system.urls'
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',  # 必须包含此引擎
        'DIRS': [BASE_DIR / 'templates'],  # 模板文件目录
        'APP_DIRS': True,  # 允许从应用内加载模板
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

STATIC_URL = 'static/'  # 静态文件访问URL前缀，必填
STATIC_ROOT = BASE_DIR / 'staticfiles'  # 生产环境收集静态文件的目录（可选，建议添加）
STATICFILES_DIRS = [BASE_DIR / 'static']  # 开发环境静态文件存放目录（可选，根据项目结构添加）

# 其他基础配置（如INSTALLED_APPS、MIDDLEWARE等共享配置）
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'scanner',
    'dashboard', 
    'api',
    'rest_framework'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

