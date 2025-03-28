# Archive Collected Data

## Compress-Archive

The PowerShell's `Compress-Archive` cmdlet can compress files:

```powershell
Compress-Archive -Path data.txt -DestinationPath data.zip -Force
```

To decompress it, use `Expand-Archive` cmdlet:

```powershell
Expand-Archive -Path data.zip -DestinationPath .\extracted -Force
```

## Tar

The `tar` command is common to compress files.

```powershell
tar -czvf data.tar.gz data.txt
```

To extract it, use `-x` flag:

```powershell
tar -xzvf data.tar.gz
```

## Makecab

The `makecab` command can also be used.

```powershell
makecab data.txt data.cab
```

To decompress it, use `expand` command:

```powershell
expand data.cab
```
