# URL Obfuscation

This technique is leveraged by malicious actors to confuse the victims in social engineering such as phishing.

## Technique 1. URL Shortening

Malisiouc links are often obfuscated with URL shortener services such as below:

- [TinyURL](https://tinyurl.com/)
- [Cuttly](https://cutt.ly/)

## Technique 2. Subdomain Spoofing

This technique is used to make the domain appear legitimate to the victims.  
Here is the spoofed domain examples:

- `hxxps://www.google.com.evil.com`
- `hxxps://www.facebook.com.evil.com`

## Technique 3. '@' Spoofing

This technique leverages `@` for confusing victims. The string before `@` is interpreted as just a username and is therefore meaningless.  
Here is the spoofed domain examples:

- `hxxps://www.google.com@evil.com`
- `hxxps://www.facebook.com@evil.com`

## Technique 4. Hex Encoding

Malicious actors confuse the victims by encoding IP address in Hex.  
For example, we can convert `127.0.0.1` to `0x7f000001` and then can access to `http://0x7f000001` in browser.  

Oneline tools are available for converting as follow:

- [Best IP to Hex Converter](https://codebeautify.org/ip-to-hex-converter)
- [IP to Hex Converter](https://www.browserling.com/tools/ip-to-hex)

## Technique 5. Typosquatting

This technique uses alphabets/numbers that are similar to others to make the domain appear legitimate.  
Here is the examples:

- `hxxps://www.goog1e.com` (`l` -> `1`)
- `hxxps://www.facabook.com` (`e` -> `a`)

## Technique 6. IDN Homograph Attack

Internationalized Domain Name (IDN) is leveraged to make it look like a legitimate domain.  
The following domains may look legitimate at first glance, but they are not.  

- `hxxps://www.аpple.com` (`a` (Latin) -> `а` (Cyrillic))
- `hxxps://www.googlе.com` (`e` (Latin) -> `е` (Cyrillic))

## Technique 7. Search Engine Click Tracking URLs

URLs generated by search engine's results can also be used for obfuscation purposes.

- Bing

    In the Bing search, type the keyword `site:evil.com` (replace it with your desired domain) in the search bar and get the results. Once the results are displayed, we can use the Bing redirect URL such as `https://www.bing.com/ck/a?!&&p=abcd...` by hovering the site title listed in the results.  
    In my easy research, these click tracking URLs are generated in only the following browsers: Microsoft Edge, FireFox with almost default settings.
