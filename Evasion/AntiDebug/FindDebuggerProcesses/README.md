# Detect Debugger Processes

The following command finds common debugger processes.

```powershell
Get-Process | Where-Object { $_.ProcessName -match "dbg" -or $_.ProcessName -match "debug" }
```