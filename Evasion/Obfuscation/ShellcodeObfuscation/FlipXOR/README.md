# Shellcode Obfuscation: Flip XOR

This technique flips original shellcode and then XOR.

## Usage

### 1. Generate Original Shellcode

```sh
msfvenom -p windows/x64/exec CMD=calc.exe -f py -v shellcode
```

### 2. Encode the Shellcode

Open `FlipXOR.py` and replace the `shellcode` value with our generated shellcode, then execute it:

```sh
python3 FlipXOR.py
```

### 3. Decode & Execute Shellcode

Edit `FlipXOR.cpp` to replace the `encodedShellcode` with the generated shellcode above.  
Then build/execute it.

## Resources

- [Red Siege: Flipping the Script](https://redsiege.com/blog/2024/08/adventures-in-shellcode-obfuscation-part-7-flipping-the-script/)

