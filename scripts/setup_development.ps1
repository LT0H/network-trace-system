# Development Environment Setup Script

Write-Host "Setting up development environment..." -ForegroundColor Green

# 1. Create virtual environment and install dependencies
Write-Host "1. Setting up Python environment..." -ForegroundColor Yellow
cd C:\Users\z1395\network_trace_system

if (-Not (Test-Path "venv")) {
    python -m venv venv
}

# Activate virtual environment
& "venv\Scripts\activate.ps1"

# Upgrade pip and install requirements
pip install --upgrade pip
pip install -r requirements.txt

# 2. Database setup (SQLite for development)
Write-Host "2. Setting up database..." -ForegroundColor Yellow

# Create migrations
& "venv\Scripts\python.exe" manage.py makemigrations

# Apply migrations
& "venv\Scripts\python.exe" manage.py migrate

# Create superuser (optional)
Write-Host "Would you like to create a superuser? (y/n)" -ForegroundColor Cyan
$createSuperuser = Read-Host
if ($createSuperuser -eq 'y' -or $createSuperuser -eq 'Y') {
    & "venv\Scripts\python.exe" manage.py createsuperuser
}

# 3. Collect static files
Write-Host "3. Collecting static files..." -ForegroundColor Yellow
& "venv\Scripts\python.exe" manage.py collectstatic --noinput

# 4. Create necessary directories
Write-Host "4. Creating directories..." -ForegroundColor Yellow
$directories = @(
    "logs",
    "media\uploads",
    "media\exports",
    "static\css",
    "static\js",
    "static\images",
    "scanner\scanners",
    "scanner\management\commands"
)

foreach ($dir in $directories) {
    if (-Not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force
        Write-Host "  Created: $dir" -ForegroundColor Gray
    }
}

# Create __init__.py files
$initFiles = @(
    "scanner\scanners\__init__.py",
    "scanner\management\__init__.py",
    "scanner\management\commands\__init__.py"
)

foreach ($file in $initFiles) {
    if (-Not (Test-Path $file)) {
        New-Item -ItemType File -Path $file -Force
    }
}

Write-Host "`nDevelopment environment setup completed!" -ForegroundColor Green
Write-Host "You can now start the development server with:" -ForegroundColor Cyan
Write-Host "  python manage.py runserver" -ForegroundColor White
Write-Host "`nAccess the application at: http://127.0.0.1:8000/" -ForegroundColor Yellow
Write-Host "Admin interface: http://127.0.0.1:8000/admin/" -ForegroundColor Yellow