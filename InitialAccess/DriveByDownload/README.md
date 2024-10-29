# Drive-by Download

This technique lets victims to download malicious files when they access to the website.

## Usage

### 1. Generate JavaScript File

First of all, generate `downloader.js` that lets victims to download our arbitrary file. This JavaScript file will be loaded in the HTML.    
As below, specify the path of the file to download:

```sh
python3 scripts/generator.py path/to/file
```

### 2. Start Web Server

After that, start web server to host our malicious website:

```sh
python3 -m http.server
```

Then access to `http://localhost:8000` in your browser.  
After loading the page, our file will be downloaded.

## Resources

- [https://github.com/demetriusford/drive-by-download](https://github.com/demetriusford/drive-by-download)