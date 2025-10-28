# 网络扫描溯源系统 - 生产环境部署指南

## 系统要求

- Windows Server 2019+ 或 Windows 10/11
- Python 3.8+
- PostgreSQL 13+
- Redis 6+
- Npcap 1.0+
- Nmap 7.90+

## 部署步骤

### 1. 环境准备

```powershell
# 以管理员权限运行
.\scripts\setup_production.ps1