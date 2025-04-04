# PowerShell Obfuscation

Adversaries often use obfuscation techniques to PowerShell commands. They are often used in combination.

## Random Case

This is probably the easiest and simplest obfuscation technique.  
PowerShell recognizes uppercase and lowercase letters without distinguishing between them.

```powershell
cAlC.eXe
```

## Replacing

We can convert it into a payload command by replacing the harmless string, and then execute it.

```powershell
$string = "Hello, World!"
$cmd = $string.Replace("Hel", "cal").Replace("lo, ", "c.e").Replace("World!", "xe")
powershell -nop -c $cmd
```

## Reversing

The payload command can be reversed to confuse the analyst.

```powershell
$reversed = 'exe.clac'.ToCharArray();[Array]::Reverse($reversed);iex(-join $reversed)
```

## Splitting

It is also possible to split the characters of the payload command and then combine them and execute them.

```powershell
$cmd = [char[]]('c'+'a'+'l'+'c'+'.'+'e'+'x'+'e') -Join ''
Invoke-Expression $cmd
```

## Base64 Encoding

PowerShell can execute a Base64 encoded command.

- Method 1. `powershell -e`

    ```powershell
    # Encode a payload with Base64 (UTF16LE)
    $cmd = "calc.exe"
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
    $encodedCmd = [Convert]::ToBase64String($bytes)

    # Execute the command
    powershell -nop -e $encodedCmd
    ```

- Method 2. Python

    Python script can also be used in PowerShell.

    ```powershell
    # Encode a payload with Base64 (UTF8)
    $cmd = "calc.exe"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($cmd)
    $encodedCmd = [Convert]::ToBase64String($bytes)

    # Execute the command
    iex $(python -c "import base64; print(base64.b64decode('$encodedCmd').decode())")
    ```

## Double-Quotes

Inserting double quotes inside the command can confuse analysts a bit.

```powershell
ca'l'c.exe
```

## Hex

Hex encoded command can be executed with `Invoke-Expression (iex)`.

```powershell
# calc.exe = 0x63616c632e657865
iex $([char]0x63 + [char]0x61 + [char]0x6c + [char]0x63 + [char]0x2e + [char]0x65 + [char]0x78 + [char]0x65)
```

## Encryption

In addition to Base64 encoding, it is also possible to execute commands using encryption and decryption.

### AES-CBC

```powershell
# Payload
$cmd = "calc.exe"

# Set key and iv
$password = "secret"
$key = [System.Text.Encoding]::UTF8.GetBytes($password.PadRight(32, ' '))
$iv = [System.Text.Encoding]::UTF8.GetBytes("1234567890123456")

# Set AES-CBC
$aes = [System.Security.Cryptography.AesManaged]::new()
$aes.Key = $key
$aes.IV = $iv
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC

# Encrypt
$encryptor = $aes.CreateEncryptor()
$bytes = [System.Text.Encoding]::UTF8.GetBytes($cmd)
$encryptedBytes = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
# Base64 encode
$encryptedBase64 = [Convert]::ToBase64String($encryptedBytes)

# Decrypt & Execute
$encBytes = [Convert]::FromBase64String($encryptedBase64)
$decryptor = $aes.CreateDecryptor()
$decBytes = $decryptor.TransformFinalBlock($encBytes, 0, $encBytes.Length)
iex $([System.Text.Encoding]::UTF8.GetString($decBytes))
```

## Resources

- [A Beginner’s Guide to PowerShell String Replace Techniques by Netwrix](https://blog.netwrix.com/2025/04/03/a-beginners-guide-to-powershell-string-replace-techniques/)
