"""开发环境配置"""
from .base import *
import os

# 开发环境必须开启DEBUG
DEBUG = True

# 允许本地访问
ALLOWED_HOSTS = ['127.0.0.1', 'localhost']
SECRET_KEY = 'django-insecure-iti03+7m6ouwvj5v+k)g)0rtmdbd4^jv$#ospiodauzxp_*kdo'  # 与base.py保持一致
ROOT_URLCONF = 'trace_system.urls'

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

# 1. WS工具路径
WS_ANALYZER_PATH = "C:/Users/z1395/network_trace_system/ws-traffic-analyze-kit-main"
# 2. CIC工具路径
CIC_FLOW_METER_PATH = "C:/Users/z1395/network_trace_system/CICFlowMeter-master"
# 3. pcap文件存放路径
PCAP_SAVE_PATH = "C:/Users/z1395/network_trace_system/traffic_data"
# 4. CIC生成CSV存放路径）
CIC_CSV_SAVE_PATH = "C:/Users/z1395/network_trace_system/CICFlowMeter-master/data/daily"
# 5. WS处理结果存放路径
WS_RESULT_SAVE_PATH = "C:/Users/z1395/network_trace_system/traffic_data/ws_results"
# 6. 抓包时长（秒）、默认监控总时长（秒，可按需改）
CAPTURE_DURATION = 10
MONITOR_DURATION = 3600

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