# Disable Firewall

## Using Netsh

The `netsh` command can be used for disabling firewall.

```powershell
netsh advfirewall set currentprofile state on
```

To enable it again, set `state off`:

```powershell
netsh advfirewall set currentprofile state off
```

## Using Registry

By setting `0` to the `EnableFirewall` in registry, we can disable Firewall:

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile /v "EnableFirewall" /t REG_DWARD /d 0 /f
```

To enable againt, set `1`:

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile /v "EnableFirewall" /t REG_DWARD /d 1 /f
```
