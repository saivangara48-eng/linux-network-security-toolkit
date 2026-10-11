
from pathlib import Path
import stat
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
SCAN_DIR = BASE_DIR / "samples" / "permissions"
REPORT_DIR = BASE_DIR / "reports"


def scan_permissions():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    if not SCAN_DIR.is_dir():
        print(f"Test directory not found: {SCAN_DIR}")
        return

    findings = []

    for file_path in sorted(SCAN_DIR.iterdir()):
        if not file_path.is_file():
            continue

        try:
            mode = file_path.stat().st_mode
            permissions = stat.filemode(mode)
            octal_permissions = oct(mode & 0o777)

            # Flag files writable by group or others.
            risky = bool(mode & (stat.S_IWGRP | stat.S_IWOTH))

            status = (
                "REVIEW: group/others can write"
                if risky
                else "OK: no group/other write permission"
            )

            findings.append(
                f"{file_path.name}: {permissions} ({octal_permissions}) - {status}"
            )

        except OSError as error:
            findings.append(f"{file_path.name}: ERROR - {error}")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = REPORT_DIR / f"permission_report_{timestamp}.txt"

    with report_path.open("w", encoding="utf-8") as report:
        report.write("FILE PERMISSION INVESTIGATION REPORT\n")
        report.write(f"Scan directory: {SCAN_DIR}\n")
        report.write(f"Generated: {datetime.now().astimezone()}\n\n")

        for finding in findings:
            report.write(finding + "\n")
            print(finding)

    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    scan_permissions()

