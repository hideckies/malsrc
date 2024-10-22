<#
Title: Modules to Hashes
#>

# Set modules to calculate the hashes.
$Modules = @("kernel32.dll", "ntdll.dll")

# Replace the following values with your own. They will be used in APIHashing.cpp
$Key        = 0x48
$RandomAddr = 0x14da703d

$Modules | % {
	$mod = $_.ToUpper()

	$hash = $Key
	[int]$i = 0

	$mod.ToCharArray() | % {
		$c = $_
		$d = [int64]$c
		$x = '0x{0:x}' -f $d
		$hash += $hash * $RandomAddr + $c -band 0xffffff
		$hashHex = '0x{0:x}' -f $hash
		$i++
	}
	Write-Host "$mod = $('0x00{0:x}' -f $hash)"
}