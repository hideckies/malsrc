# Clear Event Logs

To hide malicious activities, we can remove Windows Event Logs.  There are several ways:

## Remove-EventLog

```powershell
Remove-EventLog -LogName System
Remove-EventLog -LogName Application
Remove-EventLog -LogName Security
```

## Webtutil

```powershell
wevtutil cl system
wevtutil cl application
wevtutil cl security
```
