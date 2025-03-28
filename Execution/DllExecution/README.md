# DLL Execution

DLL files can often be used by attackers to execute or inject malicious code.

```powershell
regsvr32 /s .\evil.dll

# Replace "EntryPoint" with an actual entry point of DLL such as "DllMain" or
# other exported function marked with `__declspec(dllexport)`
rundll32 evil.dll,EntryPoint

# A dll path (e.g. "C:\evil.dll") must be absolute path.
rundll32 shell32.dll,Control_RunDLL C:\evil.dll

msiexec /y C:\evil.dll
msiexec /z C:\evil.dll
C:\Windows\SysWOW64\Register-CimProvider.exe -Path .\evil.dll
```