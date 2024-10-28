# Self-Signed Code Signing Certificate

## Code Signing

Open **Developer PowerShell for VS{VERSION}** and execute the following commands.

```sh
$CertName = "MyCert"
$CertDomain = "example.com"
$CertLocation = "Cert:\CurrentUser\My"
$CertFilePath = "C:\$MyCert.pfx"
$CertPassword = "Password123"
$TargetFile = "C:\evil.exe"

$Cert = New-SelfSignedCertificate -Type "CodesigningCert" -KeyExportPolicy "Exportable" -Subject $CertName -KeyUsageProperty @("Sign") -KeyUsage @("DigitalSignature") -DnsName $CertDomain -CertStoreLocation $CertLocation -KeyLength 2048 -Provider "Microsoft Software Key Storage Provider"

Export-PfxCertificate -Cert $Cert -FilePath $CertFilePath -Password (ConvertTo-SecureString -String $CertPassword -Force -AsPlainText)

signtool sign /fdws /f $CertFilePath /p $CertPassword $TargetFile
```

### (Optional 1) Verify Certificate

```sh
signtool verify /pa C:\evil.exe
```

### (Optional 2) Remove the Certificate

If we no longer need the certificate, remove it as below:

```sh
# 1. Find the generated certificate.
Get-ChildItem "Cert:\CurrentUser\My"

# 2. Remove it
Remove-Item -Path "Cert:\CurrentUser\My\<Thumbprint>"
```

Alternatively, we can remove it in the **CertMgr**.
