# Prerequisites Installation Script
# Run as Administrator

param(
    [switch]$InstallPostgreSQL = $false,
    [switch]$InstallRedis = $false,
    [switch]$InstallNginx = $false
)

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "Installing prerequisites for Network Trace System..." -ForegroundColor Green

# 1. Install Chocolatey (Windows package manager)
Write-Host "1. Installing Chocolatey..." -ForegroundColor Yellow
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 2. Install required packages
$Packages = @(
    'python',
    'git',
    'nmap',
    'npcap'
)

if ($InstallPostgreSQL) {
    $Packages += 'postgresql'
}

if ($InstallRedis) {
    $Packages += 'redis-64'
}

if ($InstallNginx) {
    $Packages += 'nginx'
}

foreach ($Package in $Packages) {
    Write-Host "Installing $Package..." -ForegroundColor Yellow
    choco install $Package -y --no-progress
}

# 3. Verify installations
Write-Host "`nVerifying installations..." -ForegroundColor Yellow

$Tools = @{
    'Python' = 'python --version';
    'Git' = 'git --version';
    'Nmap' = 'nmap --version';
}

if ($InstallPostgreSQL) {
    $Tools['PostgreSQL'] = 'psql --version'
}

if ($InstallRedis) {
    $Tools['Redis'] = 'redis-cli --version'
}

if ($InstallNginx) {
    $Tools['Nginx'] = 'nginx -v'
}

foreach ($Tool in $Tools.GetEnumerator()) {
    try {
        $output = Invoke-Expression $Tool.Value 2>&1
        Write-Host "  $($Tool.Key): Installed" -ForegroundColor Green
    }
    catch {
        Write-Host "  $($Tool.Key): Failed - $_" -ForegroundColor Red
    }
}

Write-Host "`nPrerequisites installation completed!" -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Restart your terminal to refresh environment variables" -ForegroundColor Gray
Write-Host "2. Run the development setup script" -ForegroundColor Gray