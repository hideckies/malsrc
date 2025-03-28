# Encryption with Base64

## Malicious Program

We can build `Base64.cpp` in Visual Studio, then execute it in a target system.

## Certutil

The `certutil` command can simply encode/decode Base64.

```powershell
certutil -encode evil.exe evil_enc.exe
```

To decode it, use `-decode` flag:

```powershell
certutil -decode evil_enc.exe evil.exe
```

## Python

This command leverages Python script to encode/decode/execute Base64.

```powershell
# Encode
$encPayload = $(python3 -c 'import base64;enc=base64.b64encode(\"echo hello\".encode());print(enc.decode())')

# Decode & Execute
iex $(python3 -c "import base64;print(base64.b64decode('$encPayload').decode())")
```