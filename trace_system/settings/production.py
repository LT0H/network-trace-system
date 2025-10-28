"""
生产环境配置
安全注意事项：此文件包含敏感信息，切勿提交到版本控制系统
"""

import os
from pathlib import Path
from .base import *

# 安全警告：生产环境不要开启调试模式！
DEBUG = False

# 允许的主机名
ALLOWED_HOSTS = [
    'yourdomain.com',  # 您的域名
    'localhost',
    '127.0.0.1',
    '::1',
    '.yourdomain.com',  # 允许所有子域名
]

# 安全密钥（生产环境必须设置独立的密钥）
SECRET_KEY = os.environ.get('SECRET_KEY', '')
if not SECRET_KEY:
    raise Exception("生产环境必须设置SECRET_KEY环境变量")

# 数据库配置 - PostgreSQL
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'network_trace_system'),
        'USER': os.environ.get('DB_USER', 'trace_user'),
        'PASSWORD': os.environ.get('DB_PASSWORD', ''),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
        'CONN_MAX_AGE': 600,  # 连接池保持时间（秒）
        'OPTIONS': {
            'sslmode': 'prefer',  # 生产环境建议使用'require'
        }
    }
}

# 缓存配置 - Redis
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/1'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'PASSWORD': os.environ.get('REDIS_PASSWORD', ''),
            'SOCKET_CONNECT_TIMEOUT': 5,  # 秒
            'SOCKET_TIMEOUT': 5,  # 秒
        },
        'KEY_PREFIX': 'trace_system'
    }
}

# Celery配置
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

# 静态文件配置
STATIC_ROOT = '/var/www/network-trace-system/staticfiles'
STATIC_URL = '/static/'

# 媒体文件配置
MEDIA_ROOT = '/var/www/network-trace-system/media'
MEDIA_URL = '/media/'

# 安全中间件配置
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# HTTPS配置（如果使用SSL）
# SECURE_SSL_REDIRECT = True
# SESSION_COOKIE_SECURE = True
# CSRF_COOKIE_SECURE = True
# SECURE_HSTS_SECONDS = 31536000  # 1年
# SECURE_HSTS_INCLUDE_SUBDOMAINS = True
# SECURE_HSTS_PRELOAD = True

# 日志配置
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/network-trace-system/django.log',
            'maxBytes': 1024 * 1024 * 100,  # 100MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'celery_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/network-trace-system/celery.log',
            'maxBytes': 1024 * 1024 * 100,  # 100MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler',
            'include_html': True,
        }
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
        'celery': {
            'handlers': ['celery_file'],
            'level': 'INFO',
            'propagate': True,
        },
        'scanner': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# 邮件配置（用于错误通知）
ADMINS = [
    ('Admin', 'admin@yourdomain.com'),
]

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'webmaster@yourdomain.com')

# 性能优化
# 数据库连接池
DATABASES['default']['CONN_MAX_AGE'] = 60

# 模板缓存
TEMPLATES[0]['OPTIONS']['loaders'] = [
    ('django.template.loaders.cached.Loader', [
        'django.template.loaders.filesystem.Loader',
        'django.template.loaders.app_directories.Loader',
    ]),
]

# GZip压缩
MIDDLEWARE.insert(0, 'django.middleware.gzip.GZipMiddleware')

# 安全密钥轮换（可选）
SECRET_KEY_FALLBACKS = [
    os.environ.get('SECRET_KEY_OLD', ''),
]