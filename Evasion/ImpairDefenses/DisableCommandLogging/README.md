# Disable Command Logging

## Disable PowerShell Command Logging

The following command avoids storing PowerShell command history, and removes the history file.

```powershell
# Disable storing command history
Set-PSReadlineOption -HistorySaveStyle SaveNothing
# Remove history file
Remove-Item (Get-PSReadlineOption).HistorySavePath
```

## Disable Command Line Process Auditing

This command disables command line process auditing:

```powershell
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 0 /f
```

To enable it again, set `1` to the value:

```powershell
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```
