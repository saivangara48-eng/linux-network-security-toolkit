from pathlib import Path
import subprocess
from collections import Counter
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
PCAP = BASE_DIR / "samples/pcap/sample.pcapng"
REPORT = BASE_DIR / "reports/protocol_summary.txt"

if not PCAP.exists():
    print(f"Capture not found: {PCAP}")
    raise SystemExit(1)

result = subprocess.run(
    [
        "tshark", "-r", str(PCAP),
        "-T", "fields",
        "-e", "_ws.col.Protocol",
    ],
    capture_output=True,
    text=True,
)

if result.returncode != 0:
    print("TShark error:")
    print(result.stderr)
    raise SystemExit(result.returncode)

protocols = Counter(
    line.strip()
    for line in result.stdout.splitlines()
    if line.strip()
)

lines = [
    "PROTOCOL STATISTICS REPORT",
    f"Generated: {datetime.now().astimezone().isoformat()}",
    f"Capture: {PCAP.name}",
    f"Total packets: {sum(protocols.values())}",
    "",
]

for protocol, count in protocols.most_common():
    lines.append(f"{protocol}: {count} packet(s)")

REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")

print("\n".join(lines))
print(f"\nReport saved to: {REPORT}")
