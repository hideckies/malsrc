# Module Hashing

This technique dynamatically resolves module base addresses and gets handles using calculated hashes.

## Usage

### 1. Calculate Module Hashes

First of all, edit `CalcHashes.ps1` to add/remove module names and execute it as below:

```powershell
.\CalcHashes.ps1

# output
KERNEL32.DLL = 0x0058dc794
NTDLL.DLL = 0x004644894
```

### 2. Set KEY, RANDOM_ADDR, Module Hashes

In `Helper.hpp`, set `KEY`, `RANDOM_ADDR` and module hashes.

### 3. Edit Source Code

Depending on the situation, edit `ModuleHashing.cpp`.

### 4. Build & Run

After that, build and run the project in Visual Studio.
