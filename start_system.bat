@echo off
title 网络扫描溯源系统启动器
echo ========================================
echo   网络扫描溯源系统启动器（开发模式）
echo ========================================
echo.

:: 设置开发环境变量
set DJANGO_ENV=development
set DJANGO_SETTINGS_MODULE=trace_system.settings.development  # 确保这一行存在

echo 1. 启动Celery Worker (异步任务处理)...
start "Celery Worker" cmd /k "cd /d C:\Users\z1395\network_trace_system && venv\Scripts\activate.bat && set DJANGO_ENV=development && set DJANGO_SETTINGS_MODULE=trace_system.settings.development && celery -A trace_system worker --pool=solo -l info"

echo 2. 启动Celery Beat (定时任务)...
start "Celery Beat" cmd /k "cd /d C:\Users\z1395\network_trace_system && venv\Scripts\activate.bat && set DJANGO_ENV=development && set DJANGO_SETTINGS_MODULE=trace_system.settings.development && celery -A trace_system beat -l info"

echo 3. 等待3秒让Celery启动...
timeout /t 3 /nobreak >nul

echo 4. 启动流量监听服务? (y/n)
set /p start_monitor=
if /i "%start_monitor%"=="y" (
    echo 启动流量监听服务...
    start "Traffic Monitor" cmd /k "cd /d C:\Users\z1395\network_trace_system && venv\Scripts\activate.bat && set DJANGO_ENV=development && set DJANGO_SETTINGS_MODULE=trace_system.settings.development && python manage.py start_traffic_monitor"
    timeout /t 2 /nobreak >nul
)

echo 5. 启动Django开发服务器...
echo   访问: http://127.0.0.1:8000/
echo.
cd /d C:\Users\z1395\network_trace_system
venv\Scripts\activate.bat
python manage.py runserver --settings=trace_system.settings.development

pause