# Fake reCAPTCHA

This is a simple ClickFix, also called Fake reCAPTCHA, that does not use `mshta` command. This is because in my Windows environment I could not execute HTA from the URL with `mshta`. So I changed the RCE part with the `cmd /c ...` command. 

## Usage

```sh
python3 -m http.server
```

Now access to `http://127.0.0.1:8000` in browser.

## Resources

- [reCAPTCHA Phish by John Hammond](https://github.com/JohnHammond/recaptcha-phish)