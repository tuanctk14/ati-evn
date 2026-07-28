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
start /b "" .venv\Scripts\python.exe scripts\run_alert_bot.py > logs\bot1.log 2>&1

echo [3/3] Starting Bot 2 (analyst commands) in background, logging to logs\bot2.log ...
start /b "" .venv\Scripts\python.exe scripts\run_analyst_bot.py > logs\bot2.log 2>&1

echo.
echo All services launched in the background (no extra windows opened).
echo Logs: logs\bot1.log (alert bot), logs\bot2.log (analyst bot)
echo To stop the bots: close this window, or run stop.bat
echo Postgres keeps running in Docker until you run: docker compose down
endlocal
