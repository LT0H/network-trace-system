#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trace_system.settings')
    try:
        from django.core.management import execute_from_command_line
        # 正确的配置模块路径查看方式（修复错误行）
        from django.conf import settings
        print(f"当前加载的配置模块: {settings.SETTINGS_MODULE}")  # 替换原打印语句
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()