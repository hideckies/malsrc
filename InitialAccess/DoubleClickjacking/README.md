# DoubleClickjacking

DoubleClickjacking is an applied version of Clickjacking, and is a new attack method devised as a workaround for attacks such as X-Frame-Options and SameSite.

## Usage

1. Edit `index.html` to change parameters of the `openDoubleWindow` function with your own.
2. Start a web server.

```sh
python3 -m http.server
```

3. Access to `http://localhost:8000` in your browser and click the button.
4. If you accidentally click the button on a target (legitimate) page, this attack will succeed.

## Resources

- [DoubleClickjacking: A New Era of UI Redressing](https://www.paulosyibelo.com/2024/12/doubleclickjacking-what.html)