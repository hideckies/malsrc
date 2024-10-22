# API Hashing

This technique dynamatically resolves API addresses using calculated hashes.

## Usage

### 1. Calculate API Hashes

First of all, edit `CalcHashes.ps1` to add/remove APIs and execute it as below:

```powershell
.\CalcHashes.ps1

# output
MESSAGEBOXA = 0x006815eed
```

### 2. Set KEY, RANDOM_ADDR, API Hashes

In `Helper.hpp`, set `KEY`, `RANDOM_ADDR` and API hashes.

### 3. Edit Source Code

Depending on the situation, edit `APIHashing.cpp`.

### 4. Build & Run

After that, build and run the project in Visual Studio.

<br />

## Resources

- [Red Team Notes](https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware)