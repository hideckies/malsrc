# Entropy Reduction with English Words

## Usage

### 1. Obfuscate Shellcode with Reducing Entropy and RC4 Encryption

If needed, edit the `shellcode` value in the `obfuscate.py`, and then execute the following command:

```sh
python3 obfuscate.py
```

### 2. Execute the Encoded Shellcode

Paste the above output values (`words` and `encodedShellcode`) to the `EnglishWords.cpp`, and build the project in Visual Studio.  
After that, execute it.

## Resources

- [Sekuro: Obfuscating Shellcode Entropy](https://sekuro.io/blog/obfuscating-shellcode-entropy/)