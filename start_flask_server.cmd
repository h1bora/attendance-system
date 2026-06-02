@echo off
cd /d "%~dp0"
set "PYTHONPATH=%~dp0.codex_pydeps"
"C:\Users\h1bor\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" -u app.py > "%~dp0flask.server.log" 2>&1
