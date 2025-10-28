# Windows服务安装脚本
# 需要以管理员权限运行

param(
    [string]$ProjectPath = "C:\NetworkTraceSystem",
    [string]$PythonPath = "C:\Python311\python.exe",
    [string]$VirtualEnvPath = "C:\NetworkTraceSystem\venv"
)

# 检查管理员权限
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "需要管理员权限运行此脚本"
    exit 1
}

# 下载NSSM（如果没有）
$NSSMPath = "$PSScriptRoot\nssm.exe"
if (-Not (Test-Path $NSSMPath)) {
    Write-Host "下载NSSM..." -ForegroundColor Yellow
    $NSSMUrl = "https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip"
    $TempFile = "$env:TEMP\nssm.zip"
    
    Invoke-WebRequest -Uri $NSSMUrl -OutFile $TempFile
    Expand-Archive -Path $TempFile -DestinationPath "$env:TEMP\nssm" -Force
    Copy-Item "$env:TEMP\nssm\nssm-2.24-101-g897c7ad\win64\nssm.exe" -Destination $NSSMPath
    Remove-Item $TempFile -Force
    Remove-Item "$env:TEMP\nssm" -Recurse -Force
}

# 服务配置
$Services = @(
    @{
        Name = "NetworkTraceSystemWeb"
        DisplayName = "网络扫描溯源系统 Web服务"
        Description = "Django Web服务器 for 网络扫描溯源系统"
        Command = "$VirtualEnvPath\Scripts\waitress-serve.exe"
        Arguments = "--host=0.0.0.0 --port=8000 trace_system.wsgi:application"
        WorkingDirectory = $ProjectPath
    },
    @{
        Name = "NetworkTraceSystemCelery"
        DisplayName = "网络扫描溯源系统 Celery Worker"
        Description = "Celery Worker for 网络扫描溯源系统"
        Command = "$VirtualEnvPath\Scripts\celery.exe"
        Arguments = "-A trace_system worker --pool=solo -l INFO"
        WorkingDirectory = $ProjectPath
    },
    @{
        Name = "NetworkTraceSystemBeat"
        DisplayName = "网络扫描溯源系统 Celery Beat"
        Description = "Celery Beat Scheduler for 网络扫描溯源系统"
        Command = "$VirtualEnvPath\Scripts\celery.exe"
        Arguments = "-A trace_system beat -l INFO --scheduler django_celery_beat.schedulers:DatabaseScheduler"
        WorkingDirectory = $ProjectPath
    }
)

# 安装服务
foreach ($Service in $Services) {
    Write-Host "安装服务: $($Service.Name)..." -ForegroundColor Yellow
    
    # 检查服务是否已存在
    $ExistingService = Get-Service -Name $Service.Name -ErrorAction SilentlyContinue
    if ($ExistingService) {
        Write-Host "服务已存在，先删除..." -ForegroundColor Yellow
        & $NSSMPath stop $Service.Name
        & $NSSMPath remove $Service.Name confirm
        Start-Sleep -Seconds 2
    }
    
    # 安装新服务
    & $NSSMPath install $Service.Name $Service.Command
    & $NSSMPath set $Service.Name DisplayName $Service.DisplayName
    & $NSSMPath set $Service.Name Description $Service.Description
    & $NSSMPath set $Service.Name AppParameters $Service.Arguments
    & $NSSMPath set $Service.Name AppDirectory $Service.WorkingDirectory
    & $NSSMPath set $Service.Name Start SERVICE_AUTO_START
    & $NSSMPath set $Service.Name AppStdout "$ProjectPath\logs\$($Service.Name).log"
    & $NSSMPath set $Service.Name AppStderr "$ProjectPath\logs\$($Service.Name).log"
    & $NSSMPath set $Service.Name AppRotateFiles 1
    & $NSSMPath set $Service.Name AppRotateOnline 1
    & $NSSMPath set $Service.Name AppRotateSeconds 86400
    & $NSSMPath set $Service.Name AppRotateBytes 10485760
    
    # 设置服务账户（使用网络服务账户，权限较低）
    & $NSSMPath set $Service.Name ObjectName "NT AUTHORITY\NetworkService"
    
    Write-Host "服务 $($Service.Name) 安装完成" -ForegroundColor Green
}

# 启动服务
Write-Host "启动服务..." -ForegroundColor Yellow
foreach ($Service in $Services) {
    & $NSSMPath start $Service.Name
    Start-Sleep -Seconds 3
    
    $ServiceStatus = Get-Service -Name $Service.Name
    if ($ServiceStatus.Status -eq 'Running') {
        Write-Host "服务 $($Service.Name) 启动成功" -ForegroundColor Green
    } else {
        Write-Warning "服务 $($Service.Name) 启动失败，状态: $($ServiceStatus.Status)"
    }
}

Write-Host "所有服务安装完成！" -ForegroundColor Green
Write-Host "Web服务访问地址: http://localhost:8000" -ForegroundColor Yellow