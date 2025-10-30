"""开发环境配置"""
from .base import *

# 开发环境必须开启DEBUG
DEBUG = True

# 允许本地访问
ALLOWED_HOSTS = ['127.0.0.1', 'localhost']

# 开发环境数据库（默认SQLite）
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# 开发环境缓存（可选，使用本地内存）
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# 开发环境日志（输出到控制台）
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
}