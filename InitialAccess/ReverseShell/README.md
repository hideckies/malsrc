# Reverse Shell

## Usage

### 1. Replace IP and port

Edit `ReverseShell.cpp` to replace the `ip` and `port` with your attack machine.  
Then build it.

### 2. Start Listener

In our attack machine, start listeenr:

```sh
nc -lvnp 4444
```

### 3. Execute ReverseShell

When a victim executes our malicious `ReverseShell` executable, we can receive a reverse connection.