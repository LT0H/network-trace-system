# Windows Service Management Script

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("start", "stop", "restart", "status")]
    [string]$Action,
    
    [ValidateSet("web", "celery", "beat", "all")]
    [string]$Service = "all"
)

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
}