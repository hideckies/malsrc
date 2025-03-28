# Mark-of-the-Web Bypass

When we download our malicious files in a target system, these files are tagged with a hidden NTFS Alternate Data Streams named `Zone.Identifier`. Files tagged with it may not be able to execute by Windows Defender, so it is recommended to remove the tags with the following command:

```powershell
Unblock-File -Path evil.exe
```

Assume that the `evil.exe` was downloaded into a target system via an external host.
