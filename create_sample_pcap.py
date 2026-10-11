import struct
import socket
from pathlib import Path

output = Path("samples/pcap/sample.pcapng")
output.parent.mkdir(parents=True, exist_ok=True)

def block(block_type, body):
    length = 12 + len(body)
    padding = b"\x00" * ((-len(body)) % 4)
    length += len(padding)
    return (
        struct.pack("<II", block_type, length)
        + body + padding
        + struct.pack("<I", length)
    )

# PCAPNG section header block
section = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
data = block(0x0A0D0D0A, section)

# Ethernet interface description block
interface = struct.pack("<HHI", 1, 0, 65535)
data += block(1, interface)

# A sample Ethernet/IPv4/UDP packet (DNS-like destination port 53)
ethernet = bytes.fromhex("0200000000020200000000010800")
ip_header = bytes.fromhex(
    "4500001c0001000040110000c0000201c6336402"
)
udp_header = struct.pack("!HHHH", 53000, 53, 8, 0)
packet = ethernet + ip_header + udp_header

# Enhanced packet block
packet_body = struct.pack("<IIIII", 0, 0, 1, len(packet), len(packet))
packet_body += packet
data += block(6, packet_body)

output.write_bytes(data)
print(f"Sample capture created: {output}")

