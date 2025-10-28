# 日志监控和告警脚本

param(
    [int]$CheckInterval = 60,  # 检查间隔（秒）
    [string]$LogPath = "C:\NetworkTraceSystem\logs",
    [string]$AlertEmail = "admin@yourdomain.com"
)

function Send-Alert {
    param([string]$Subject, [string]$Body)
    
    # 这里可以实现邮件、Slack、Webhook等告警方式
    Write-Warning "ALERT: $Subject"
    Write-Host $Body
    
    # 示例：发送邮件（需要配置SMTP）
    # Send-MailMessage -From "monitor@yourdomain.com" -To $AlertEmail -Subject $Subject -Body $Body -SmtpServer "smtp.yourdomain.com"
}

function Monitor-Logs {
    # 检查错误日志
    $ErrorPatterns = @(
        "ERROR",
        "CRITICAL",
        "Exception",
        "Traceback",
        "500 Internal Server Error"
    )
    
    # 检查每个日志文件
    Get-ChildItem "$LogPath\*.log" | ForEach-Object {
        $LogFile = $_.FullName
        $LogName = $_.Name
        
        # 读取最近新增的日志内容
        $NewContent = Get-Content $LogFile -Tail 100
        
        foreach ($Pattern in $ErrorPatterns) {
            $Errors = $NewContent | Select-String $Pattern
            if ($Errors) {
                $Subject = "系统告警: $LogName 中发现错误"
                $Body = "在 $LogName 中发现匹配模式 '$Pattern' 的错误:`n`n"
                $Body += ($Errors | Select-Object -First 5 | Out-String)
                
                Send-Alert -Subject $Subject -Body $Body
                break
            }
        }
    }
    
    # 检查服务状态
    $Services = @("NetworkTraceSystemWeb", "NetworkTraceSystemCelery", "NetworkTraceSystemBeat")
    foreach ($Service in $Services) {
        $ServiceObj = Get-Service -Name $Service -ErrorAction SilentlyContinue
        if (-Not $ServiceObj -or $ServiceObj.Status -ne "Running") {
            $Subject = "服务告警: $Service 服务异常"
            $Body = "服务 $Service 状态异常。当前状态: $($ServiceObj.Status)"
            Send-Alert -Subject $Subject -Body $Body
        }
    }
    
    # 检查磁盘空间
    $Disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
    $FreeSpacePercent = ($Disk.FreeSpace / $Disk.Size) * 100
    if ($FreeSpacePercent -lt 10) {
        $Subject = "磁盘空间告警: 剩余空间不足"
        $Body = "系统磁盘剩余空间仅剩 $([math]::Round($FreeSpacePercent, 2))%"
        Send-Alert -Subject $Subject -Body $Body
    }
}

# 主监控循环
Write-Host "开始日志监控，检查间隔: ${CheckInterval}秒" -ForegroundColor Green
Write-Host "按 Ctrl+C 停止监控" -ForegroundColor Yellow

try {
    while ($true) {
        Monitor-Logs
        Start-Sleep -Seconds $CheckInterval
    }
} catch {
    Write-Host "监控停止: $_" -ForegroundColor Red
}