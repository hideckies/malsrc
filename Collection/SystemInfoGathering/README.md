# System Info Gathering

## Malicious Program

We can build `Nt.hpp` and `SystemInfoGathering.cpp` files to collect system information via C++ program.

## Living Off The Land

Alternatively, we can enumerate several information via legitimate commands of a target system.

### Enumerate System Information

```powershell
systeminfo
cmd /c ver
hostname
net time \\ComputerName
Get-ComputerInfo
Get-Date
Get-PSDrive
(Get-CimInstance -Classname Win32_BIOS -Property SerialNumber).SerialNumber
psinfo
reg query HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language
wmic os get buildnumber,caption,countrycode,osarchitecture,oslanguage,ostype,registereduser,serialnumber,version,windowsdirectory /format:csv
```

### Enumerate Computer Accounts

```powershell
Get-ADComputer -Filter *
dsquery computer -name *
```

### Enumerate Users

```powershell
net user
net user /domain
Get-LocalUser
Get-ADUser -Filter *
wmic useraccount get /ALL /format:csv
dsquery user -name *
```

### Enumerate Groups

```powershell
net localgroup
net group /domain
Get-LocalGroup
Get-WmiObject Win32_Group
dsquery group -name *
```

### Enumerate Backups/Shadow Copies

```powershell
vssadmin list shadows
vssadmin list volumes
```

### Enumerate Event Logs

```powershell
# 4624: Successful logon event ID
Get-EventLog security -InstanceId 4624 -Newest 10
psloglist
# This command enumerates successful logon events
wevtutil qe Security "/q:*[System[(EventID=4624)]]" /f:text /c:10
```

### Enumerate Networks

```powershell
arp -a
ipconfig /all
nbtstat -n
net config workstation
net share
new view \\RemoteComputer
netsh advfirewall firewall show rule name=all
netsh interface show interface
netsh wlan show profile * key=clear
netstat -ano
Get-NetAdapter
Get-NetFirewallRule
Get-NetIPConfiguration
Get-SmbShare
route print
tcpvcon -a
type C:\Windows\System32\drivers\etc\hosts
wmic nic get macaddress,name /format:csv
```

### Enumerate Processes

```powershell
Get-CimInstance -Query 'Select * from Win32_Process'
Get-Process
Get-WmiObject -Class Win32_Process
pslist -t
tasklist
wmic process get caption,executablepath,commandline,processid /format:csv
```

### Enumerate Services

```powershell
net start
Get-Service | Where-Object {$_.Status -eq "Running"}
psservice query -s active
sc.exe query
wmic service list brief
```

### Enumerate Environment Variables

```powershell
cmd /c set
dir env:
Get-ChildItem Env:
```

### Enumerate Device Drivers

```powershell
driverquery /v /fo list;driverquery /si /fo list
fsutil fsinfo drives
```

### Enumerate Patches

```powreshell
Get-HotFix -description "Security update"
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

### Enumerate WSL

If a target system enables WSL, we can investigate it:

```powershell
wsl -e cat /etc/passwd
wsl -u root -e cat /etc/shadow
```

### Scan Open Ports

The command scans opening ports.

```powershell
@(21,22,23,25,53,80,88,135,139,389,443,445,464,593,636,3000,3268,3269,3306,3389,5432,5900,5985,6379,8000,8080) | % {echo ((New-Object Net.Sockets.TcpClient).Connect("localhost",$_)) "Port $_ open"} 2>$null
```
