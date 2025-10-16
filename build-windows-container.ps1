# PowerShell script to build and run Windows container
# Run this on a Windows machine with Docker Desktop

Write-Host "Building Ecliptix Windows Container..." -ForegroundColor Green

# Ensure Docker is in Windows containers mode
Write-Host "Checking Docker mode..." -ForegroundColor Yellow
$dockerInfo = docker info --format json | ConvertFrom-Json
if ($dockerInfo.OSType -ne "windows") {
    Write-Host "ERROR: Docker is not in Windows containers mode!" -ForegroundColor Red
    Write-Host "Please switch Docker Desktop to Windows containers and try again." -ForegroundColor Red
    Write-Host "Right-click Docker Desktop tray icon -> 'Switch to Windows containers...'" -ForegroundColor Yellow
    exit 1
}

Write-Host "Docker is in Windows containers mode ✓" -ForegroundColor Green

# Build the Windows container
Write-Host "Building Windows container image..." -ForegroundColor Yellow
docker build -f Dockerfile.windows -t ecliptix-windows:latest .

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Windows container built successfully!" -ForegroundColor Green
    Write-Host "Image name: ecliptix-windows:latest" -ForegroundColor Cyan

    Write-Host "`nTo run the container:" -ForegroundColor Yellow
    Write-Host "docker run -p 8080:8080 -p 5051:5051 ecliptix-windows:latest" -ForegroundColor Cyan

    Write-Host "`nTo run with Docker Compose:" -ForegroundColor Yellow
    Write-Host "docker-compose -f docker-compose.windows.yml up" -ForegroundColor Cyan

} else {
    Write-Host "❌ Windows container build failed!" -ForegroundColor Red
    exit 1
}