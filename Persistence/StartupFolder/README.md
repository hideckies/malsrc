# Startup Folder for Persistence

Applications in the startup folders are executed when system starts.  
If we want to run our own executable file at system startup, we can do so with the following command:

```powershell
# For all users (Administrator privileges required)
mv .\evil.exe 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\'
# For specific user
mv .\evil.exe 'C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\'
```

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/001/)