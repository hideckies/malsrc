# Powershell via LNK

## 1. Create a Shortcut (.lnk)

In Desktop (or somewhere else), right-click and select `New` -> `Shortcut`.  
Then input the PowerShell command in the dialog. Below is the example:

```powershell
powershell.exe -ExecutionPolicy Bypass -nop -w hidden -c "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Hello from PowerShell!')"
```

## (Option) Change Icon

Right-click on the shortcut file (`.lnk`) and click `Properties`.  
In the Properties window, go to the `Shortcut` tab and click on the `Change icon`.

## 2. Execute

Now double-click the shortcut file (`.lnk`). The PowerShell command will be executed.
