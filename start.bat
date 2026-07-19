@echo off
setlocal

cd /d "%~dp0"

echo === ATI-EVN startup ===

echo [1/3] Starting Postgres (docker compose)...
docker compose up -d
if errorlevel 1 (
    echo Docker compose failed to start. Is Docker Desktop running?
    pause
    exit /b 1
)

echo [2/3] Starting Bot 1 (alert dispatch)...
start "ATI-EVN Bot 1 - Alert" cmd /k "set PYTHONUTF8=1 && .venv\Scripts\python.exe scripts\run_alert_bot.py"

echo [3/3] Starting Bot 2 (analyst commands)...
start "ATI-EVN Bot 2 - Analyst" cmd /k "set PYTHONUTF8=1 && .venv\Scripts\python.exe scripts\run_analyst_bot.py"

echo.
echo All services launched in separate windows. Close those windows (or Ctrl+C inside them) to stop each bot.
echo Postgres keeps running in Docker until you run: docker compose down
endlocal
