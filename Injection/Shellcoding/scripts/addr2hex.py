import sys


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 addr2hex.py <ip> <port>")
        return
    
    lhost = sys.argv[1]
    lport = int(sys.argv[2])
    
    # Adjust host and port
    lhost_b = [int(octet) for octet in lhost.split('.')]
    lport_b = [(lport >> 8) & 0xFF, lport & 0xFF]

    # Convret to HEX (little-endian) and concatenate
    # e.g. {hex(127.0.0.1(7f.00.00.01)) = 7f000001} + {hex(4444) = 0x115C} + {AF_INET = 0x0002}
    addr_hex = "0x{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}0002".format(
        lhost_b[3], lhost_b[2], lhost_b[1], lhost_b[0], lport_b[1], lport_b[0]
    )

    print(addr_hex)


if __name__ == '__main__':
    main()