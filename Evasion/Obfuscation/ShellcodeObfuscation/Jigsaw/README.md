# Jigsaw

## Usage

### 1. Generate Original Shellcode

```sh
msfvenom -p windows/x64/exec CMD=calc.exe -f py -v shellcode
```

### 2. Encode the Shellcode

Open `Jigsaw.py` and replace the `shellcode` value with our generated shellcode, then execute it:

```sh
python3 Jigsaw.py
```

### 3. Decode & Execute Shellcode

Edit `Jigsaw.cpp` to replace the `jigsaw` and the `positions` with the generated results above.  
Then build/execute it.

## Resources

- [Red Siege: Jigsaw](https://redsiege.com/blog/2024/09/adventures-in-shellcode-obfuscation-part-12-jigsaw/)

