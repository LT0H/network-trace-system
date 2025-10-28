# PostgreSQL Database Configuration Script
# Requires PostgreSQL to be installed and running

param(
    [string]$Hostname = "localhost",
    [string]$Port = "5432", 
    [string]$AdminUser = "postgres",
    [string]$AdminPassword = "YourSecurePassword123!",  # Change in production
    [string]$DatabaseName = "network_trace_system",
    [string]$DatabaseUser = "trace_user", 
    [string]$DatabasePassword = "TraceUserPassword123!"  # Change in production
)

Write-Host "Configuring PostgreSQL database..." -ForegroundColor Green

# Set PostgreSQL password
$env:PGPASSWORD = $AdminPassword

try {
    # Check if PostgreSQL is available
    Write-Host "Checking PostgreSQL connection..." -ForegroundColor Yellow
    $testConn = & "psql" -U $AdminUser -h $Hostname -p $Port -c "SELECT version();" 2>$null
    if (-not $testConn) {
        throw "Cannot connect to PostgreSQL. Please ensure the service is running"
    }
    
    # Create database user
    Write-Host "Creating database user: $DatabaseUser" -ForegroundColor Yellow
    $createUser = & "psql" -U $AdminUser -h $Hostname -p $Port -c "CREATE USER $DatabaseUser WITH PASSWORD '$DatabasePassword';" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "User already exists or creation failed, continuing..." -ForegroundColor Yellow
    }
    
    # Create database
    Write-Host "Creating database: $DatabaseName" -ForegroundColor Yellow
    $createDb = & "psql" -U $AdminUser -h $Hostname -p $Port -c "CREATE DATABASE $DatabaseName OWNER $DatabaseUser;" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Database already exists or creation failed, continuing..." -ForegroundColor Yellow
    }
    
    # Grant privileges
    Write-Host "Granting database privileges..." -ForegroundColor Yellow
    & "psql" -U $AdminUser -h $Hostname -p $Port -c "GRANT ALL PRIVILEGES ON DATABASE $DatabaseName TO $DatabaseUser;" 2>$null
    
    # Test new user connection
    $env:PGPASSWORD = $DatabasePassword
    $testUserConn = & "psql" -U $DatabaseUser -h $Hostname -p $Port -d $DatabaseName -c "SELECT 1 as test;" 2>$null
    
    if ($testUserConn -match "test") {
        Write-Host "Database configuration completed successfully!" -ForegroundColor Green
        Write-Host "Database Name: $DatabaseName" -ForegroundColor Yellow
        Write-Host "Username: $DatabaseUser" -ForegroundColor Yellow
        Write-Host "Host: $Hostname" -ForegroundColor Yellow
        Write-Host "Port: $Port" -ForegroundColor Yellow
    }
    else {
        Write-Warning "User connection test failed, but database was created"
    }
}
catch {
    Write-Error "Database configuration failed: $_"
}
finally {
    # Clean up password
    $env:PGPASSWORD = ""
}

Write-Host "`nNext step: Update database configuration in .env file" -ForegroundColor Cyan