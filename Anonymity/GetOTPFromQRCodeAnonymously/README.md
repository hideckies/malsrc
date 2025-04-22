# Get OTP (One-Time Password) from QR Code Anonymously

Sometimes we need to scan a QR code to get an OTP for login or MFA in web services. At that time, scanning it with our regular mobile Authenticator app is not a good idea for those of us who value anonymity.  
Therefore, we can obtain the OTP almost anonymously using the commands below.

As a side note, if we want the best possible anonymity, we may want to run the following commands using a VM (Whonix, Tails, etc.) + VPN + Tor. However, some services may block access from Tor.    

## 1. Download a QR Code Image File

At first, we need to download a QR code image as `.jpg` or `.png`. So right-lick on an image of a QR code, then save it as image file.  

### 2. Analyze It

After downloading, analyze the image file using the `zbarimg`:

```sh
zbarimg qrcode.jpg
```

Our desired URI (`otpauth://totp/<SERVICE>?secret=<SECRET>`) is shown in the results.  
Copy this secret value in the URI.

### 3. Get an OTP from the Secret

Using the secret, we can get an OTP with the `oathtool`:

```sh
oathtool --totp -b '<SECRET>'
```

Note: **That secret must be managed properly.** This is because we will need it the next time we need to get an OTP when login/MFA. In that case, simply run the `oathtool` command above to get the OTP using the secret.

