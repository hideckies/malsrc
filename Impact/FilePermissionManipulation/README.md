# File Permission Manipulation

## Icacls

The command grands permission of the file/directory to all users.

```powershell
icacls .\file_or_dir /grant Everyone:F
```

## Takeown

The command resets a file/directory permission to allow the current user to own.

```powershell
takeown /f .\file_or_dir /r
```