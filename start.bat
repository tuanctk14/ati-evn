@echo off
setlocal

cd /d "%~dp0"
set PYTHONUTF8=1

echo === ATI-EVN startup ===

if not exist logs mkdir logs

echo [1/3] Starting Postgres (docker compose)...
docker compose up -d
if errorlevel 1 (
    echo Docker compose failed to start. Is Docker Desktop running?
    pause
    exit /b 1
)

echo [2/3] Starting Bot 1 (alert dispatch) in background, logging to logs\bot1.log ...
powershell -NoProfile -Command "Start-Process -FilePath '.venv\Scripts\python.exe' -ArgumentList 'scripts\run_alert_bot.py' -WorkingDirectory '%~dp0' -RedirectStandardOutput 'logs\bot1.log' -RedirectStandardError 'logs\bot1_stderr.log' -WindowStyle Hidden"

echo [3/3] Starting Bot 2 (analyst commands) in background, logging to logs\bot2.log ...
powershell -NoProfile -Command "Start-Process -FilePath '.venv\Scripts\python.exe' -ArgumentList 'scripts\run_analyst_bot.py' -WorkingDirectory '%~dp0' -RedirectStandardOutput 'logs\bot2.log' -RedirectStandardError 'logs\bot2_stderr.log' -WindowStyle Hidden"

echo.
echo All services launched in the background (no extra windows opened).
echo They keep running even after you close this window.
echo Logs: logs\bot1.log / logs\bot1_stderr.log (alert bot)
echo       logs\bot2.log / logs\bot2_stderr.log (analyst bot)
echo To stop the bots: run stop.bat
echo Postgres keeps running in Docker until you run: docker compose down
endlocal
