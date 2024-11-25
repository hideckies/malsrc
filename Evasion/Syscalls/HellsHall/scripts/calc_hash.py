import sys


def crc32b(data: bytes) -> int:
    seed = 0xEDB88320
    crc = 0xFFFFFFFF  # Initial value

    for byte in data:
        crc ^= byte
        for _ in range(8):  # Process each bit
            if crc & 1:
                crc = (crc >> 1) ^ seed
            else:
                crc >>= 1

    return crc ^ 0xFFFFFFFF  # Final XOR


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 calc_hash.py <API>")
        print("Example: python3 calc_hash.py NtCreateThreadEx")
        sys.exit(1)

    api = sys.argv[1].encode('utf-8')
    checksum = crc32b(api)
    print(f"{api.decode()} = 0x{checksum:x}")