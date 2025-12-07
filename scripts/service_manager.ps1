# Windows Service Management Script

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("start", "stop", "restart", "status", "remove")]  # 新增remove选项
    [string]$Action,
    
    [ValidateSet("web", "celery", "beat", "all")]
    [string]$Service = "all"
)

# 定义NSSM路径（与install_services.ps1保持一致）
$NSSMPath = "$PSScriptRoot\nssm.exe"

# Service mapping
$ServiceMap = @{
    "web" = "NetworkTraceSystemWeb"
    "celery" = "NetworkTraceSystemCelery" 
    "beat" = "NetworkTraceSystemBeat"
}

# Get services to operate on
if ($Service -eq "all") {
    $Services = $ServiceMap.Values
}
else {
    $Services = @($ServiceMap[$Service])
}

# Execute action
switch ($Action) {
    "status" {
        foreach ($ServiceName in $Services) {
            $ServiceObj = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($ServiceObj) {
                $StatusColor = if ($ServiceObj.Status -eq "Running") { "Green" } else { "Red" }
                Write-Host "$ServiceName : $($ServiceObj.Status)" -ForegroundColor $StatusColor
            }
            else {
                Write-Host "$ServiceName : Not installed" -ForegroundColor Yellow
            }
        }
    }
    
    "start" {
        foreach ($ServiceName in $Services) {
            try {
                Start-Service -Name $ServiceName
                Write-Host "Started service: $ServiceName" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to start service: $ServiceName - $_"
            }
        }
    }
    
    "stop" {
        foreach ($ServiceName in $Services) {
            try {
                Stop-Service -Name $ServiceName -Force
                Write-Host "Stopped service: $ServiceName" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to stop service: $ServiceName - $_"
            }
        }
    }
    
    "restart" {
        foreach ($ServiceName in $Services) {
            try {
                Restart-Service -Name $ServiceName -Force
                Write-Host "Restarted service: $ServiceName" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to restart service: $ServiceName - $_"
            }
        }
    }

    # 新增：删除服务功能
    "remove" {
        foreach ($ServiceName in $Services) {
            $ServiceObj = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if (-not $ServiceObj) {
                Write-Host "Service $ServiceName does not exist" -ForegroundColor Yellow
                continue
            }

            try {
                # 先停止服务
                if ($ServiceObj.Status -eq "Running") {
                    Write-Host "Stopping service $ServiceName before removal..." -ForegroundColor Yellow
                    Stop-Service -Name $ServiceName -Force
                    Start-Sleep -Seconds 2
                }

                # 使用NSSM删除服务（因为服务是通过NSSM安装的）
                if (Test-Path $NSSMPath) {
                    & $NSSMPath remove $ServiceName confirm
                    Write-Host "Removed service: $ServiceName" -ForegroundColor Green
                }
                else {
                    # 备选方案：直接删除Windows服务
                    Remove-Service -Name $ServiceName -ErrorAction Stop
                    Write-Host "Removed service: $ServiceName (using Windows native method)" -ForegroundColor Green
                }
            }
            catch {
                Write-Error "Failed to remove service: $ServiceName - $_"
            }
        }
    }
}