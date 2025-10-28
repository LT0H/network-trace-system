# Windows生产环境部署脚本
# 需要以管理员权限运行

# 检查管理员权限
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "需要管理员权限运行此脚本"
    exit 1
}

Write-Host "开始部署网络扫描溯源系统生产环境..." -ForegroundColor Green

# 1. 创建项目目录
$ProjectPath = "C:\NetworkTraceSystem"
Write-Host "创建项目目录: $ProjectPath" -ForegroundColor Yellow
if (-Not (Test-Path $ProjectPath)) {
    New-Item -ItemType Directory -Path $ProjectPath -Force
}

# 2. 安装 Chocolatey (Windows包管理器)
Write-Host "安装 Chocolatey..." -ForegroundColor Yellow
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 3. 使用 Chocolatey 安装必要软件
$Packages = @(
    'python311',
    'git',
    'postgresql13',
    'redis-64',
    'nmap',
    'npcap'
)

foreach ($Package in $Packages) {
    Write-Host "安装 $Package..." -ForegroundColor Yellow
    choco install $Package -y
}

# 4. 配置环境变量
Write-Host "配置环境变量..." -ForegroundColor Yellow
[Environment]::SetEnvironmentVariable("Path", "$env:Path;C:\Program Files\PostgreSQL\13\bin;C:\Program Files\Redis", "Machine")

# 5. 重启使环境变量生效
Write-Host "环境配置完成，建议重启计算机使配置生效" -ForegroundColor Green
Write-Host "重启后请继续执行部署步骤2" -ForegroundColor Yellow