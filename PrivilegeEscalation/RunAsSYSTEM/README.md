# Start Process as SYSTEM Privileges

If we are already Administrator, we can further elevate privileges to the `SYSTEM` using `psexec`:

```powershell
psexec -i -s cmd
# or
psexec -i -s powershell
```