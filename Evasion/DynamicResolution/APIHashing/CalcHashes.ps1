<#
Title: APIs to Hashes
Resources:
    - https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware
#>

# Set APIs to calculate the hashes.
$APIs = @("MessageBoxA")

# Replace the following values with your own. They will be used in APIHashing.cpp
$Key        = 0x48
$RandomAddr = 0x14da703d

$APIs | % {
	$api = $_.ToUpper()

	$hash = $Key
	[int]$i = 0

	$api.ToCharArray() | % {
		$c = $_
		$d = [int64]$c
		$x = '0x{0:x}' -f $d
		$hash += $hash * $RandomAddr + $c -band 0xffffff
		$hashHex = '0x{0:x}' -f $hash
		$i++
	}
	Write-Host "$api = $('0x00{0:x}' -f $hash)"
}