# Shellcoding

## Usage

### (Optional) 0. Calculate hashes for modules/functions

```sh
python3 scripts/hash.py kernel32.dll WinExec
```

We can use the generated hash in the `exec.asm` or others.

### 1. Compile Assembly

```sh
nasm -f win64 -o exec.o exec.asm
```

### 2. Extract Shellcode

```sh
for i in $(objdump -D exec.o | grep "^ " | cut -f2); do echo -n "\x$i" ; done
```

Copy the output.

### 3. Inject Shellcode

We use the [Classic Shellcode Injection Local](../ClassicShellcodeInjection/ClassicShellcodeInjectionLocal.cpp) to inject our shellcode.  
Paste our shellcode in the code and build/run it.

## Resources

- [Metasploit Framework](https://github.com/rapid7/metasploit-framework/tree/master/external/source/shellcode/windows/x64)