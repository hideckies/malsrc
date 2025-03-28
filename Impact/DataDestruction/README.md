# Data Destruction

After getting into a target system, attackers may destruct the system by deleting data.  
The `sdelete` command deletes files securely by overwriting random bytes before deleting. The deleted files cannot be recovered easily.

```powershell
sdelete -p 3 .\example.txt
```
