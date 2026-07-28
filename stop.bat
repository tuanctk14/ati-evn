@echo off
setlocal

echo Stopping ATI-EVN bots (run_alert_bot.py / run_analyst_bot.py)...

wmic process where "name='python.exe' and commandline like '%%run_alert_bot.py%%'" call terminate >nul 2>&1
wmic process where "name='python.exe' and commandline like '%%run_analyst_bot.py%%'" call terminate >nul 2>&1

echo Done. Postgres is left running -- use "docker compose down" to stop it too.
endlocal
