import sys

from .scanner import scan_path
from .models import Warning


def print_warnings(warnings: list[Warning]) -> None:
    if not warnings:
        print("No issues found.")
        return

    for w in warnings:
        loc = f"{w.file}:{w.line_no}"
        cwe = f" ({w.cwe})" if w.cwe else ""
        print(f"[{w.severity}] {loc}{cwe}")
        print(f"  {w.message}")
        print(f"  > {w.line}")
        print()


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: python -m c_unsafe_scan.cli <path-to-file-or-dir>")
        sys.exit(1)

    target = sys.argv[1]
    warnings = scan_path(target)
    print_warnings(warnings)


if __name__ == "__main__":
    main()
