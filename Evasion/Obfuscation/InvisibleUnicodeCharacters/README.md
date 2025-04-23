# Invisible Unicode Characters

This technique takes advantage of the fact that a special character called **Hangul Filler** is output as a blank character.

## Usage

### 1. Generate an obfuscated payload

Open `obfuscator.py` in your editor and replace the value of the `PAYLOAD` variable with your own payload for JavaScript.  
Then run the following command:

```sh
python3 obfuscator.py
```

Copy the entire result containing `const obfsPayload = '          ';`.  
And then open `index.html` and Paste it to replace the variable named `obfsPayload` with yours.

### 2. Start Local Server

Finally we can test this technique by starting a local server:

```sh
python3 -m http.server
```

And access to `http://localhost:8000` in browser and check if your code will be executed.  

## Resources

- [Tycoon2FA New Evasion Technique for 2025](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/tycoon2fa-new-evasion-technique-for-2025/)
- [urlscan.io](https://urlscan.io/result/0195c73f-bfd0-7000-8386-94b11ace6088/dom/)