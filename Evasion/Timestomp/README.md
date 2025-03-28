# Timestomp

Timestomp technique is used to prevent victims from becoming suspicious of a file.

This command changes the creation time and the last modified time of the file.

```powershell
Get-ChildItem .\evil.exe | % {$_.CreationTime = "06/24/2022 05:03:18";$_.LastWriteTime = "06/24/2022 05:03:18"}
```