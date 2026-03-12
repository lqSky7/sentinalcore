#!/usr/bin/env python3
import base64
import random

# Generate high entropy data (encrypted/packed simulation)
high_entropy_data = bytes([random.randint(0, 255) for _ in range(8192)])

# Embed it in the script
ENCRYPTED_PAYLOAD = base64.b64encode(high_entropy_data).decode()

# Some suspicious configuration
C2_SERVERS = ["evil-domain.com", "malware-host.net"]
BACKDOOR_PORTS = [4444, 31337, 8080]

def main():
    # Simulate unpacking
    payload = base64.b64decode(ENCRYPTED_PAYLOAD)
    print(f"Unpacked {len(payload)} bytes of payload")

if __name__ == "__main__":
    main()