# Qishing: Phishing Leveraging QR Codes

Threat actors leverages QR codes to hide their malicious URLs for phishing campaigns.  
They use online QR code generators such as below:

- [QR Code Generator](https://www.qr-code-generator.com/)
- [The QR Code Generator](https://www.the-qrcode-generator.com/)

For example, the generated QR codes are embedded in phishing emails disguised as MFA from legitimate sites.

## Mitigatio

For analyzing QR code, first we save the QR code image in local machine. Then run the following command:

```sh
zbarimg qrcode.jpg
```

The URL will be displayed in the output, so copy it and research this URL with anti-phishing tools or URL scanners such as:

- [PhishTank](https://phishtank.org/)
- [urlscan.io](https://urlscan.io/)
- [VirusTotal](https://www.virustotal.com/gui/home/upload)

## Resources

- [Think Before You Scan: The Rise of QR Codes in Phishing](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/think-before-you-scan-the-rise-of-qr-codes-in-phishing/)
