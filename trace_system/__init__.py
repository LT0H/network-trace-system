from __future__ import absolute_import, unicode_literals

# 这确保当Django启动时app总是被导入
from .celery import app as celery_app

__all__ = ('celery_app',)