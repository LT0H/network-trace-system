# Complete Deployment Script

param(
    [string]$Environment = "production",
    [switch]$SkipTests = $false,
    [switch]$Force = $false
)

# Configuration variables
$ProjectPath = "C:\Users\z1395\network_trace_system"
$BackupPath = "C:\Backups\NetworkTraceSystem"
$DateTime = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Host "Starting deployment of Network Trace System ($Environment)..." -ForegroundColor Green

# 1. Backup current version
Write-Host "Step 1: Backing up current version..." -ForegroundColor Yellow
if (Test-Path $ProjectPath) {
    $BackupDir = "$BackupPath\$DateTime"
    New-Item -ItemType Directory -Path $BackupDir -Force
    
    # Backup critical files
    $ItemsToBackup = @(
        "*.py",
        "requirements.txt",
        ".env",
        "templates",
        "static",
        "media"
    )
    
    foreach ($Item in $ItemsToBackup) {
        if (Test-Path "$ProjectPath\$Item") {
            Copy-Item "$ProjectPath\$Item" -Destination $BackupDir -Recurse -Force
        }
    }
    Write-Host "Backup completed: $BackupDir" -ForegroundColor Green
}
else {
    New-Item -ItemType Directory -Path $ProjectPath -Force
}

# 2. Stop services
Write-Host "Step 2: Stopping services..." -ForegroundColor Yellow
try {
    & "$PSScriptRoot\service_manager.ps1" -Action stop -Service all
}
catch {
    Write-Warning "Error stopping services: $_"
}

try {
    & "$PSScriptRoot\nginx_manager.ps1" -Action stop
}
catch {
    Write-Warning "Error stopping Nginx: $_"
}

# 3. Code deployment (assuming Git, modify according to your setup)
Write-Host "Step 3: Deploying code..." -ForegroundColor Yellow
try {
    Set-Location $ProjectPath
    
    # This should be your actual code deployment logic
    # For example: git pull, or extract from archive, etc.
    Write-Host "Code deployment logic needs to be implemented according to your setup" -ForegroundColor Cyan
    Write-Host "Current directory: $(Get-Location)" -ForegroundColor Gray
    
}
catch {
    Write-Error "Code deployment failed: $_"
    # Restore backup
    Write-Host "Restoring backup..." -ForegroundColor Red
    if (Test-Path $BackupDir) {
        Copy-Item "$BackupDir\*" -Destination $ProjectPath -Recurse -Force
    }
    exit 1
}

# 4. Install dependencies
Write-Host "Step 4: Installing dependencies..." -ForegroundColor Yellow
Set-Location $ProjectPath

# Create/activate virtual environment
if (-Not (Test-Path "venv")) {
    python -m venv venv
}

# Activate virtual environment and install dependencies
& "venv\Scripts\activate.ps1"
pip install --upgrade pip
pip install -r requirements.txt

if ($LASTEXITCODE -ne 0) {
    Write-Error "Dependency installation failed"
    if (-Not $Force) {
        exit 1
    }
}

# 5. Database migrations
Write-Host "Step 5: Running database migrations..." -ForegroundColor Yellow
$SettingsModule = "trace_system.settings.$Environment"
& "venv\Scripts\python.exe" manage.py migrate --settings=$SettingsModule

if ($LASTEXITCODE -ne 0) {
    Write-Error "Database migration failed"
    if (-Not $Force) {
        exit 1
    }
}

# 6. Collect static files
Write-Host "Step 6: Collecting static files..." -ForegroundColor Yellow
& "venv\Scripts\python.exe" manage.py collectstatic --noinput --settings=$SettingsModule

if ($LASTEXITCODE -ne 0) {
    Write-Warning "Static file collection failed, but continuing deployment..."
}

# 7. Run tests (optional)
if (-Not $SkipTests) {
    Write-Host "Step 7: Running tests..." -ForegroundColor Yellow
    & "venv\Scripts\python.exe" manage.py test --settings=$SettingsModule
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Tests failed"
        if (-Not $Force) {
            # Restore backup
            if (Test-Path $BackupDir) {
                Copy-Item "$BackupDir\*" -Destination $ProjectPath -Recurse -Force
            }
            exit 1
        }
    }
}

# 8. Start services
Write-Host "Step 8: Starting services..." -ForegroundColor Yellow
try {
    & "$PSScriptRoot\service_manager.ps1" -Action start -Service all
}
catch {
    Write-Warning "Error starting services: $_"
}

try {
    & "$PSScriptRoot\nginx_manager.ps1" -Action start
}
catch {
    Write-Warning "Error starting Nginx: $_"
}

# 9. Health check
Write-Host "Step 9: Performing health check..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

try {
    $HealthResponse = Invoke-WebRequest -Uri "http://localhost/health/" -UseBasicParsing -TimeoutSec 30
    if ($HealthResponse.StatusCode -eq 200) {
        Write-Host "Health check passed" -ForegroundColor Green
    }
    else {
        Write-Warning "Health check returned status code: $($HealthResponse.StatusCode)"
    }
}
catch {
    Write-Warning "Health check failed: $_"
}

Write-Host "Deployment completed!" -ForegroundColor Green
Write-Host "Application URL: http://localhost" -ForegroundColor Yellow
if (Test-Path $BackupDir) {
    Write-Host "Backup location: $BackupDir" -ForegroundColor Gray
}