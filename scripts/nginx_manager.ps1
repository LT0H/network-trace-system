# Nginx Service Management Script

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("start", "stop", "restart", "reload", "status")]
    [string]$Action
)

$NginxPath = "C:\nginx\nginx.exe"  # Update with actual installation path
$ConfigPath = "C:\Users\z1395\network_trace_system\config\nginx.conf"

function Test-Nginx {
    try {
        $process = Get-Process nginx -ErrorAction SilentlyContinue
        return $null -ne $process
    }
    catch {
        return $false
    }
}

function Start-NginxServer {
    if (Test-Nginx) {
        Write-Host "Nginx is already running" -ForegroundColor Yellow
        return
    }
    
    try {
        & $NginxPath -c $ConfigPath
        Start-Sleep -Seconds 2
        
        if (Test-Nginx) {
            Write-Host "Nginx started successfully" -ForegroundColor Green
        }
        else {
            Write-Error "Nginx failed to start"
        }
    }
    catch {
        Write-Error "Error starting Nginx: $_"
    }
}

function Stop-NginxServer {
    if (-Not (Test-Nginx)) {
        Write-Host "Nginx is not running" -ForegroundColor Yellow
        return
    }
    
    try {
        & $NginxPath -s stop
        Start-Sleep -Seconds 3
        
        # Force terminate if normal stop fails
        if (Test-Nginx) {
            Get-Process nginx | Stop-Process -Force
            Write-Host "Nginx was force stopped" -ForegroundColor Yellow
        }
        else {
            Write-Host "Nginx stopped successfully" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Error stopping Nginx: $_"
    }
}

function Restart-NginxServer {
    Stop-NginxServer
    Start-Sleep -Seconds 2
    Start-NginxServer
}

function Reload-NginxConfig {
    if (-Not (Test-Nginx)) {
        Write-Error "Nginx is not running, cannot reload configuration"
        return
    }
    
    try {
        # Test configuration file syntax
        & $NginxPath -t -c $ConfigPath
        if ($LASTEXITCODE -eq 0) {
            & $NginxPath -s reload -c $ConfigPath
            Write-Host "Nginx configuration reloaded successfully" -ForegroundColor Green
        }
        else {
            Write-Error "Nginx configuration file syntax error"
        }
    }
    catch {
        Write-Error "Error reloading Nginx configuration: $_"
    }
}

# Execute action
switch ($Action) {
    "start" { Start-NginxServer }
    "stop" { Stop-NginxServer }
    "restart" { Restart-NginxServer }
    "reload" { Reload-NginxConfig }
    "status" { 
        if (Test-Nginx) {
            Write-Host "Nginx is running" -ForegroundColor Green
        }
        else {
            Write-Host "Nginx is not running" -ForegroundColor Red
        }
    }
}