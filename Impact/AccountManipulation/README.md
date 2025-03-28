# Account Manipulation

## Creating Computer Accounts

- Dsadd

    This command creates a new computer account in a target Active Directory.

    ```powershell
    dsadd computer "CN=MACHINE-0,CN=Computers,DC=example,DC=local"
    ```

    To delete it, use `dsrm` command:

    ```powershell
    dsrm "CN=MACHINE-0,CN=Computers,DC=example,DC=local
    ```

- New-ADComputer

    ```powershell
    New-ADComputer -Name "MACHINE-0"
    ```

    To delete it, use `Remove-ADComputer`:

    ```powershell
    Remove-ADComputer -Identity "CN=MACHINE-0,CN=Computers,DC=example,DC=local"
    ```

## Creating User Accounts

- Net

    This command creates a new local user account and adds it to `Domain Admins` group.

    ```powershell
    net user "evil" "Password@123" /add /domain
    net group "Domain Admins" "evil" /add /domain
    ```

- Dsadd

    This command creates a new user account in a target Active Directory.

    ```powershell
    dsadd user "CN=Evil,CN=Users,DC=example,DC=local" -pwd "Password@123" -ln "Hell" -fn "Evil" -email "evil@example.local" -display "Evil"
    ```

    To delete it, use `dsrm` command:

    ```powershell
    dsrm "CN=Evil,CN=Users,DC=example,DC=local"
    ```

- New-ADUser

    ```powershell
    New-ADUser Evil -SurName Hell -GivenName Evil -DisplayName Evil -EmailAddress evil@example.local -AccountPassword (ConvertTo-SecureString -AsPlainText "Password@123" -Force) -Enabled $true
    ```

    To delete it, use `Remove-ADUser`:

    ```powershell
    Remove-ADUser -Identity "CN=Evil,CN=Users,DC=example,DC=local"
    ```

## Creating Hidden User Accounts

By creating a new user named `$`, it is not displayed in the result of the `net user` command.

```powershell
net user $ Password123 /add
```

To delete it, run the following command:

```powershell
net user $ Password123 /add
```

## Changing User Passwords

These commands change an existing user's password.

```powershell
net user "John" "password123"

pspasswd "John" "password123"
```

## Changing Computer Names

The command changes the current computer name. The system need to restart to apply the change.

```powershell
Rename-Computer -NewName MYSERVER -Force
```