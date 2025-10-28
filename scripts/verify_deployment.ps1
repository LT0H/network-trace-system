# Deployment Verification Script

Write-Host "Starting deployment verification..." -ForegroundColor Green

# 1. Check service status
Write-Host "1. Checking service status..." -ForegroundColor Yellow
$Services = @("NetworkTraceSystemWeb", "NetworkTraceSystemCelery", "NetworkTraceSystemBeat")
$AllRunning = $true

foreach ($Service in $Services) {
    $ServiceObj = Get-Service -Name $Service -ErrorAction SilentlyContinue
    if ($ServiceObj -and $ServiceObj.Status -eq "Running") {
        Write-Host "   OK $Service is running" -ForegroundColor Green
    }
    else {
        Write-Host "   ERROR $Service is not running" -ForegroundColor Red
        $AllRunning = $false
    }
}

# 2. Check port listening
Write-Host "2. Checking port listening..." -ForegroundColor Yellow
$Ports = @(80, 8000, 6379, 5432)

foreach ($Port in $Ports) {
    $Listener = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($Listener) {
        Write-Host "   OK Port $Port is listening" -ForegroundColor Green
    }
    else {
        Write-Host "   WARNING Port $Port is not listening" -ForegroundColor Yellow
    }
}

# 3. Health check
Write-Host "3. Performing health check..." -ForegroundColor Yellow
try {
    $Response = Invoke-WebRequest -Uri "http://localhost/health/" -UseBasicParsing -TimeoutSec 30
    if ($Response.StatusCode -eq 200) {
        $HealthData = $Response.Content | ConvertFrom-Json
        Write-Host "   OK Health check passed" -ForegroundColor Green
        Write-Host "      Status: $($HealthData.status)" -ForegroundColor Gray
    }
    else {
        Write-Host "   ERROR Health check failed: HTTP $($Response.StatusCode)" -ForegroundColor Red
    }
}
catch {
    Write-Host "   ERROR Health check exception: $_" -ForegroundColor Red
}

# 4. Function test
Write-Host "4. Testing functionality..." -ForegroundColor Yellow
try {
    # Test API endpoint
    $ApiTest = Invoke-WebRequest -Uri "http://localhost/api/tasks/" -UseBasicParsing -TimeoutSec 30
    if ($ApiTest.StatusCode -eq 200) {
        Write-Host "   OK API interface is working" -ForegroundColor Green
    }
    else {
        Write-Host "   WARNING API interface returned: HTTP $($ApiTest.StatusCode)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "   ERROR API interface exception: $_" -ForegroundColor Red
}

# 5. Performance check
Write-Host "5. Checking performance..." -ForegroundColor Yellow
try {
    $CPU = Get-WmiObject -Class Win32_Processor | Measure-Object -Property LoadPercentage -Average
    $Memory = Get-WmiObject -Class Win32_OperatingSystem

    $FreeMemory = [math]::Round($Memory.FreePhysicalMemory / 1MB, 2)
    $TotalMemory = [math]::Round($Memory.TotalVisibleMemorySize / 1MB, 2)
    $MemoryUsage = [math]::Round(($TotalMemory - $FreeMemory) / $TotalMemory * 100, 2)

    Write-Host "   CPU Usage: $([math]::Round($CPU.Average, 2))%" -ForegroundColor Gray
    Write-Host "   Memory Usage: $MemoryUsage%" -ForegroundColor Gray

    if ($CPU.Average -gt 80) {
        Write-Host "   WARNING High CPU usage" -ForegroundColor Yellow
    }
    if ($MemoryUsage -gt 80) {
        Write-Host "   WARNING High memory usage" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "   WARNING Performance check failed: $_" -ForegroundColor Yellow
}

# Summary
Write-Host "`nDeployment verification completed!" -ForegroundColor Green
if ($AllRunning) {
    Write-Host "All services are running normally. System deployment successful!" -ForegroundColor Green
    Write-Host "Access URL: http://localhost" -ForegroundColor Yellow
}
else {
    Write-Host "Some services are abnormal. Please check logs!" -ForegroundColor Red
}

Write-Host "`nRecommended next steps:" -ForegroundColor Cyan
Write-Host "1. Check log files: C:\Users\z1395\network_trace_system\logs\" -ForegroundColor Gray
Write-Host "2. Verify scanning functionality" -ForegroundColor Gray
Write-Host "3. Configure regular backups" -ForegroundColor Gray