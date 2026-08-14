@echo off
echo ============================================
echo Edge Tunnel Manager - Deployment Script
echo ============================================
echo.

REM Check if wrangler is installed
where wrangler >nul 2>nul
if %errorlevel% neq 0 (
    echo Installing wrangler...
    npm install -g wrangler
)

REM Step 1: Merge files
echo Step 1: Merging Edge Tunnel with Management System...
python merge.py "_worker (1).js" "src/edge-tunnel-managed.js"
if %errorlevel% neq 0 (
    echo ERROR: Merge failed!
    pause
    exit /b 1
)

echo.
echo Step 2: Deploying to Cloudflare...
wrangler deploy

echo.
echo Step 3: Initializing database...
wrangler d1 execute edge-manager-db --remote --file=./schema.sql

echo.
echo ============================================
echo DEPLOYMENT COMPLETE!
echo ============================================
echo.
echo Admin Panel: https://edge-manager.YOUR-SUBDOMAIN.workers.dev
echo Status Panel: https://edge-manager.YOUR-SUBDOMAIN.workers.dev/status
echo.
echo Default password: admin123
echo.
pause
