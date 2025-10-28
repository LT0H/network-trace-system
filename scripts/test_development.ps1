# Development Environment Test Script

Write-Host "Testing development environment..." -ForegroundColor Green

cd C:\Users\z1395\network_trace_system

# Activate virtual environment
& "venv\Scripts\activate.ps1"

# 1. Check Django configuration
Write-Host "1. Checking Django configuration..." -ForegroundColor Yellow
& "venv\Scripts\python.exe" manage.py check

if ($LASTEXITCODE -eq 0) {
    Write-Host "  Django configuration: OK" -ForegroundColor Green
}
else {
    Write-Host "  Django configuration: FAILED" -ForegroundColor Red
    exit 1
}

# 2. Test database connection
Write-Host "2. Testing database connection..." -ForegroundColor Yellow
& "venv\Scripts\python.exe" -c "
import django
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trace_system.settings.development')
django.setup()

from django.db import connection
try:
    with connection.cursor() as cursor:
        cursor.execute('SELECT 1')
    print('  Database connection: OK')
except Exception as e:
    print(f'  Database connection: FAILED - {e}')
"

# 3. Test scanner models
Write-Host "3. Testing scanner models..." -ForegroundColor Yellow
& "venv\Scripts\python.exe" -c "
import django
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trace_system.settings.development')
django.setup()

try:
    from scanner.models import ScanTask
    task_count = ScanTask.objects.count()
    print(f'  Scanner models: OK (Tasks in DB: {task_count})')
except Exception as e:
    print(f'  Scanner models: FAILED - {e}')
"

# 4. Start development server (briefly)
Write-Host "4. Starting development server test..." -ForegroundColor Yellow
$serverProcess = Start-Process -FilePath "venv\Scripts\python.exe" -ArgumentList "manage.py runserver --noreload" -PassThru

# Wait a moment for server to start
Start-Sleep -Seconds 5

# Test if server is responding
try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8000/" -TimeoutSec 10 -UseBasicParsing
    if ($response.StatusCode -eq 200) {
        Write-Host "  Development server: OK" -ForegroundColor Green
    }
    else {
        Write-Host "  Development server: Unexpected status - $($response.StatusCode)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  Development server: FAILED - $_" -ForegroundColor Red
}

# Stop the server
Stop-Process -Id $serverProcess.Id -Force

Write-Host "`nDevelopment environment test completed!" -ForegroundColor Green