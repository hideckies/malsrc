# Shellcode Encoder/Decoder

## Usage

### 1. Generate Shellcode

```sh
msfvenom -p windows/x64/exec CMD=calc.exe -f py -v shellcode
```

### 2. Encode the Shellcode

Open `EncodeXOR.py` and replace the `shellcode` value with our generated shellcode, then execute it:

```sh
python3 EncodeXOR.py
```

### 3. Decode & Execute Shellcode

Edit `DecodeXOR.cpp` to replace the `encodedShellcode` with our own.  
Then build/execute it.