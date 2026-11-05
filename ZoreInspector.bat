@echo off
title Zore Client Inspector
echo Starting Zore Client Inspector...
rem Always runs the newest version straight from GitHub - nothing else is downloaded or installed.
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { irm 'https://raw.githubusercontent.com/wesskolen1-sys/zore-client-inspector/main/ZoreClientInspector.ps1' | iex } catch { Write-Host ('Could not start Zore Client Inspector: ' + $_) -ForegroundColor Red; Read-Host 'Press Enter to close' }"
