# Find Credentials in Registry

The following command finds the keyword `password` in Registry.

```powershell
reg query HKLM /f password /t REG_SZ /s
```
