<# 
功能：启动 Redis 服务、Celery Worker 和 Django 开发服务器
使用：右键 "以 PowerShell 运行" 或在终端执行 .\scripts\start_redis_workers.ps1
#>

# 激活虚拟环境
Write-Host "`n激活虚拟环境..." -ForegroundColor Cyan
& .\venv\Scripts\activate

if (-not $?) {
    Write-Host "虚拟环境激活失败，请检查 venv 目录是否存在" -ForegroundColor Red
    exit 1
}

# 启动 Redis 服务（假设 Redis 已安装并添加到环境变量）
# 在启动Redis服务部分添加错误处理
Write-Host "`n检查Redis服务..." -ForegroundColor Cyan
try {
    $redisProcess = Get-Process redis-server -ErrorAction SilentlyContinue
    if (-not $redisProcess) {
        Write-Host "启动Redis服务..." -ForegroundColor Yellow
        Start-Process "redis-server" -NoNewWindow
        Start-Sleep -Seconds 3
    } else {
        Write-Host "Redis服务已在运行" -ForegroundColor Green
    }
} catch {
    Write-Host "Redis服务启动失败，将使用内存模式运行" -ForegroundColor Yellow
}

# 测试Redis连接
Write-Host "`n测试Redis连接..." -ForegroundColor Cyan
& "venv\Scripts\python.exe" scripts/check_redis.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "警告: Redis不可用，Celery将使用内存模式" -ForegroundColor Yellow
}
Write-Host "`n启动 Redis 服务..." -ForegroundColor Cyan
Start-Process "redis-server" -NoNewWindow

# 等待 Redis 启动（2秒）
Start-Sleep -Seconds 2

# 启动 Celery Worker（处理异步扫描任务）
Write-Host "`n启动 Celery Worker..." -ForegroundColor Cyan
Start-Process "powershell" -ArgumentList "celery -A trace_system worker --loglevel=info" -NoNewWindow

# 启动 Django 开发服务器
Write-Host "`n启动 Django 服务器..." -ForegroundColor Cyan
python manage.py runserver

# 提示：按 Ctrl+C 可终止所有服务