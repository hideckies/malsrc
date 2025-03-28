# Hide Files

Hiding files in a target system is a technique used to avoid the victim finds out. There are several methods to do that.

## Changing File Attributes

This command hides a file so innocent users cannot see the file and add System Attribute (SA) to disallow to delete this file with common operations. However, the `-Hidden` or `-Force` options of the `dir` command can display them.

```powershell
attrib +h +s .\evil.exe

$file = Get-Item .\evil.exe; $file.attributes = 'Hidden,System'
```

## Modifying Registry

These commands hide files in explorer.

```powershell
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 0 /f
```