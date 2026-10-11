
import platform
import subprocess
import stat
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
PERMISSIONS_DIR = BASE_DIR / "samples" / "permissions"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


def ruN_commaNd(commaNd):
    """RuN a local system commaNd safely."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )

        output = result.stdout.strip() or result.stderr.strip()
        return output or "No output."

    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        return f"Could not complete command: {error}"


def collect_network_info(report):
    """Collect network interfaces, routes, and listening ports."""
    sections = [
        ("NETWORK INFORMATION", ["ip", "addr"]),
        ("NETWORK ROUTES", ["ip", "route"]),
        ("LISTENING TCP/UDP PORTS", ["ss", "-tuln"]),
    ]

    for title, command in sections:
        output = run_command(command)

        print(f"\n[{title}]")
        print(output)

        report.write(f"\n{'=' * 15} {title} {'=' * 15}\n")
        report.write(output + "\n")


def collect_system_info(report):
    """Display and record basic system information."""
    info = (
        f"Operating system: {platform.system()}\n"
        f"OS details: {platform.platform()}\n"
        f"Python version: {platform.python_version()}\n"
    )

    print("\n[SYSTEM INFORMATION]")
    print(info)

    report.write("\nSYSTEM INFORMATION\n")
    report.write(info)


def scan_file_permissions(report):
    """Find files writable by group or other users in the lab directory."""
    print("\n[FILE PERMISSION INVESTIGATION]")
    report.write("\nFILE PERMISSION INVESTIGATION\n")
    report.write(f"Scan directory: {PERMISSIONS_DIR}\n")

    if not PERMISSIONS_DIR.is_dir():
        message = (
            f"Test directory not found: {PERMISSIONS_DIR}\n"
            "Create the test directory and try again."
        )
        print(message)
        report.write(message + "\n")
        return

    files_found = 0

    for file_path in sorted(PERMISSIONS_DIR.iterdir()):
        if not file_path.is_file():
            continue

        files_found += 1

        try:
            file_stat = file_path.stat()
            mode = file_stat.st_mode
            permission_text = stat.filemode(mode)
            octal_permissions = format(stat.S_IMODE(mode), "04o")

            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                status = "REVIEW: group/others can write"
            else:
                status = "OK: no group/other write permission"

            finding = (
                f"{file_path.name}: {permission_text} "
                f"({octal_permissions}) - {status}"
            )

        except OSError as error:
            finding = f"{file_path.name}: ERROR - {error}"

        print(finding)
        report.write(finding + "\n")

    if files_found == 0:
        message = "No regular files found in the test directory."
        print(message)
        report.write(message + "\n")
     
import platform
import subprocess
import stat
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
PERMISSIONS_DIR = BASE_DIR / "samples" / "permissions"
PCAP_DIR = BASE_DIR / "samples" / "pcap"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


def run_command(command):
    """Run a local command and return its output."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False
        )
        output = result.stdout.strip() or result.stderr.strip()
        return output or "No output."

    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        return f"Command error: {error}"


def collect_system_info(report):
    """Collect basic system information."""
    info = (
        f"Operating system: {platform.system()}\n"
        f"System details: {platform.platform()}\n"
        f"Python version: {platform.python_version()}\n"
    )

    print("\n[SYSTEM INFORMATION]")
    print(info)
    report.write("\n[SYSTEM INFORMATION]\n" + info)


def collect_network_info(report):
    """Collect network interfaces, routes, and listening ports."""
    sections = [
        ("NETWORK INTERFACES", ["ip", "addr"]),
        ("NETWORK ROUTES", ["ip", "route"]),
        ("LISTENING TCP/UDP PORTS", ["ss", "-tuln"]),
    ]

    for title, command in sections:
        output = run_command(command)
        print(f"\n[{title}]")
        print(output)
        report.write(f"\n[{title}]\n{output}\n")


def scan_file_permissions(report):
    """Review group/other write permissions in the lab directory."""
    print("\n[FILE PERMISSION INVESTIGATION]")
    report.write("\n[FILE PERMISSION INVESTIGATION]\n")
    report.write(f"Directory: {PERMISSIONS_DIR}\n")

    if not PERMISSIONS_DIR.is_dir():
        message = f"Directory not found: {PERMISSIONS_DIR}"
        print(message)
        report.write(message + "\n")
        return

    files_found = 0

    for file_path in sorted(PERMISSIONS_DIR.iterdir()):
        if not file_path.is_file():
            continue

        files_found += 1

        try:
            file_mode = file_path.stat().st_mode
            permission_text = stat.filemode(file_mode)
            octal = format(stat.S_IMODE(file_mode), "04o")

            if file_mode & (stat.S_IWGRP | stat.S_IWOTH):
                status = "REVIEW: group/others can write"
            else:
                status = "OK: no group/other write permission"

            finding = (
                f"{file_path.name}: {permission_text} "
                f"({octal}) - {status}"
            )

        except OSError as error:
            finding = f"{file_path.name}: ERROR - {error}"

        print(finding)
        report.write(finding + "\n")

    if files_found == 0:
        message = "No regular files found in the test directory."
        print(message)
        report.write(message + "\n")


def analyze_pcap(report):
    """Read a saved PCAP or PCAPNG file using TShark."""
    print("\n[PCAP PACKET ANALYSIS]")
    report.write("\n[PCAP PACKET ANALYSIS]\n")

    if not PCAP_DIR.is_dir():
        message = f"PCAP directory not found: {PCAP_DIR}"
        print(message)
        report.write(message + "\n")
        return

    capture_files = sorted(
        list(PCAP_DIR.glob("*.pcap")) +
        list(PCAP_DIR.glob("*.pcapng"))
    )

    if not capture_files:
        message = "No .pcap or .pcapng files found."
        print(message)
        report.write(message + "\n")
        return

    print("Available capture files:")
    for index, capture in enumerate(capture_files, start=1):
        print(f"{index}. {capture.name}")

    choice = input("Choose a capture number: ").strip()

    if not choice.isdigit():
        print("Invalid selection.")
        return

    index = int(choice)
    if index < 1 or index > len(capture_files):
        print("Invalid selection.")
        return

    capture_file = capture_files[index - 1]

    # -n disables name resolution; fields provide a concise summary.
    command = [
        "tshark",
        "-n",
        "-r", str(capture_file),
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-e", "frame.number",
        "-e", "frame.time",
        "-e", "ip.src",
        "-e", "frame.protocols",
        "-e", "frame.len",
    ]

    output = run_command(command)

    print(f"\nCapture: {capture_file.name}")
    print(output)

    report.write(f"Capture: {capture_file.name}\n")
    report.write(output + "\n")


def main():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = REPORT_DIR / f"security_report_{timestamp}.txt"

    print("=" * 58)
    print(" LINUX & NETWORK SECURITY INVESTIGATION TOOLKIT")
    print("=" * 58)
    print("1. Network investigation")
    print("2. File permission investigation")
    print("3. Run all investigations")
    print("4. PCAP packet analysis")
    print("5. Exit")

    choice = input("\nEnter your choice (1-5): ").strip()

    if choice == "5":
        print("Exiting toolkit.")
        return

    if choice not in {"1", "2", "3", "4"}:
        print("Invalid choice. Please select 1, 2, 3, 4, or 5.")
        return

    with report_path.open("w", encoding="utf-8") as report:
        report.write("LINUX & NETWORK SECURITY INVESTIGATION REPORT\n")
        report.write(f"Generated: {datetime.now().astimezone()}\n")
        report.write(f"System: {platform.platform()}\n")

        if choice in {"1", "3"}:
            collect_system_info(report)
            collect_network_info(report)

        if choice in {"2", "3"}:
            scan_file_permissions(report)

        if choice == "4":
            analyze_pcap(report)

    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()

