#!/usr/bin/env python3
import socket
import time

# Configuration
PORT = 9  # Standard port for Wake-on-LAN
BROADCAST_IP = "192.168.188.255"
COOLDOWN_SECONDS = 10  # Minimum seconds between relays to the same MAC

# Tracks last trigger time per MAC address
last_trigger_times = {}

def extract_mac_from_magic_packet(packet: bytes) -> str | None:
    """Extracts the target MAC address from a valid magic packet."""
    if len(packet) < 102 or not packet.startswith(b'\xff' * 6):
        return None

    mac = packet[6:12]
    if packet[6:] != mac * 16:
        return None

    return ':'.join(f"{b:02X}" for b in mac)

def send_wol(mac_address: str):
    """Sends a magic Wake-on-LAN packet to the given MAC address via broadcast."""
    mac_bytes = bytes.fromhex(mac_address.replace(":", ""))
    magic_packet = b'\xff' * 6 + mac_bytes * 16

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(magic_packet, (BROADCAST_IP, PORT))
        print(f"[+] Relayed WoL to {mac_address}")

def main():
    print(f"[~] Listening for Wake-on-LAN packets on UDP port {PORT}...")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("0.0.0.0", PORT))

        while True:
            data, addr = listener.recvfrom(1024)
            now = time.time()

            mac_address = extract_mac_from_magic_packet(data)
            if mac_address:
                last_time = last_trigger_times.get(mac_address, 0)
                if now - last_time >= COOLDOWN_SECONDS:
                    print(f"[!] Valid WoL packet detected for {mac_address} from {addr}")
                    send_wol(mac_address)
                    last_trigger_times[mac_address] = now
                else:
                    print(f"[~] WoL packet for {mac_address} ignored (cooldown)")
            else:
                print(f"[~] Invalid or non-magic packet from {addr}, ignored.")

if __name__ == "__main__":
    main()
