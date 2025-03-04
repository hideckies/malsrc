# Resources:
# - https://github.com/WafflesExploits/hide-payload-in-images/blob/main/code/payload-embedder.py

import os
import sys


def embed_payload(target_file_path, payload_file_path, output_file_path):
    if not os.path.exists(target_file_path):
        print(f"Error: Target file not found: {target_file_path}")
        sys.exit(1)
    if not os.path.exists(payload_file_path):
        print(f"Error: Payload file not found: {payload_file_path}")
        sys.exit(1)
    if os.path.exists(output_file_path):
        response = input(f"Warning: Output file '{output_file_path}' already exists. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print("Operation canceled by user.")
            sys.exit(0)

    try:
        with open(target_file_path, 'rb') as tf:
            target_data = tf.read()
            target_size = len(target_data)
            print(f"Target file size: {target_size} bytes")
        with open(payload_file_path, 'rb') as pf:
            payload_data = pf.read()
            payload_size = len(payload_data)
            print(f"Payload file size: {payload_size} bytes")

        # Combine the target data with the payload data
        combined_data = target_data + payload_data
        combined_size = len(combined_data)

        # Write the combined data to the new output file
        with open(output_file_path, 'wb') as of:
            of.write(combined_data)
            print(f"Payloaed embedded to {output_file_path}")
            print(f"Embedded file size: {combined_size} bytes")
    except IOError as e:
        print(f"Error: {e}")
        sys.exit(1)


def main():
    if len(sys.argv) != 4:
        print("Usage:\n\tpython3 embedder.py <target_file> <payload_file> <output_file>")
        print("Example:\n\tpython3 embedder.py original.png payload.bin embedded.png")
        sys.exit(1)

    target_file = sys.argv[1]
    payload_file = sys.argv[2]
    output_file = sys.argv[3]

    embed_payload(target_file, payload_file, output_file)


if __name__ == "__main__":
    main()