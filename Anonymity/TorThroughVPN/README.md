# Tor through VPN

We need to make our computers redundant for things like OSINT for security research and dark web research. Although it is difficult to completely conceal our identity, here are some ways we can strengthen our privacy to some extent at home with Tor over VPN.

## Setup

### Option 1. Whonix on VM

When we use Whonix, the setup may be easier than other OSs. Follow the steps:

1. Start VPN on host machine for Tor through VPN.
2. Start Whonix Gateway and Workstation in VirtualBox.
3. Use Whonix Workstation.

Thanks to Whonix Gateway, all internet connections are made through Tor by default, so no additional configuration is required.  

### Option 2. Kali/Parrot through Whonix Gateway on VM

Using Kali/Parrot through Whonix Gateway provides a more robust internet connection.

1. Start VPN on host machine for Tor through VPN.
2. In VirtualBox, select Kali/Parrot and go to `Settings` -> `Network` -> `Adapter 1` and set the following:

    ```txt
    - Attached to: Internal Network
    - Name: whonix
    ```

3. Start Kali/Parrot guest machine in VirtualBox.
4. After starting, edit the network settings with `sudo nano /etc/network/interfaces` command and modify addresses as below:

    ```txt
    auto eth0
    iface eth0 inet static
        address 10.152.152.11
        netmask 255.255.192.0
        gateway 10.152.152.10
    ```

    Whonix Gateway typically provides `10.152.152.10` as a gateway on the internal network.

5. Edit the DNS settings with `sudo nano /etc/resolv.conf` command and the following line:

    ```txt
    nameserver 10.152.152.10
    ```

6. Restart guest machine, or run the `sudo systemctl restart networking` command to apply the settings above.

### Option 3. Kali/Parrot through Tor on VM

Although this method provides less privacy than the above two methods, it will still provide sufficient anonymity in most cases.

1. Start VPN on host machine for Tor through VPN.
2. Start Kali/Parrot in VirtualBox or VMWare or other VM.
3. In guest machine, start Tor with `sudo apt install tor && sudo systemctl start tor` command.
4. (optional) Make Tor start at system startup with `sudo systemctl enable tor` command.

After that, we can run commands through Tor proxy with the `torsocks` command:

```sh
torsocks <command>
# for example,
torsocks curl https://check.torproject.org
```

Or use **Tor Browser**.

## Check Our Public IP

After setting up the environment, we need to check if our IP have been changed from the original IP.

1. Check public IP with `curl ifconfig.me` or `nyx` commands.
2. Also check `https://check.torproject.org/` and `https://ipleak.net/`.
3. Also check the internet route with `traceroute google.com` commands out of curiosity.
