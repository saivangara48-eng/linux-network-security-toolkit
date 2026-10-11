from pathlib import Path
import subprocess

pcap = Path("samples/pcap/sample.pcapng")

if not pcap.exists():
    print("PCAP file not found.")
    raise SystemExit(1)

result = subprocess.run(
    [
        "tshark", "-r", str(pcap),
        "-T", "fields",
        "-e", "frame.number",
        "-e", "_ws.col.Protocol",
        "-e", "frame.len",
    ],
    capture_output=True,
    text=True,
)

if result.returncode != 0:
    print(result.stderr)
    raise SystemExit(result.returncode)

print("PACKET PROTOCOL SUMMARY")
print("Frame | Protocol | Length")
print("-------------------------")

if result.stdout.strip():
    for line in result.stdout.strip().splitlines():
        print(line.replace("\t", " | "))
else:
    print("No packets found.")
