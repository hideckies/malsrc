# Shellcode Obfuscation: UUID

## Usage

### 1. Generate Original Shellcode

```sh
msfvenom -p windows/x64/exec CMD=calc.exe -f py -v shellcode
```

### 2. Encode with UUID

```sh
python3 UUID.py
```

### 3. Decode UUIDs to Shellcode and Execute

Open `UUID.cpp` and replace the `shellcodeUUIDs` value with the above result. Then build/execute.
