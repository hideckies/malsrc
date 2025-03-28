# Capture Packets

## Pktmon

These commands capture packets in 5 seconds, then save and convert the saved file to the `.pcapng` file for analyzing with WireShark.

```powershell
pktmon start --etw -f .\trace.etl
timeout /t 5
pktmon stop
pktmon etl2pcap .\trace.etl -o .\trace.pcapng
```

## Pktmon with PowerShell CmdLets

```powershell
$CaptureFile = "C:\trace.etl"
$PcapFile = "C:\trace.pcapng"
New-NetEventSession -Name EvilSniff -LocalFilePath $CaptureFile
Add-NetEventPacketCaptureProvider -SessionName EvilSniff -TruncationLength 100
Start-NetEventSession -Name EvilSniff
timeout /t 5
Stop-NetEventSession -Name EvilSniff
Remove-NetEventSession -Name EvilSniff
pktmon etl2pcap $CaptureFile -o $PcapFile
```