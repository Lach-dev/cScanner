import sys
import argparse
from typing import TextIO

from .scanner import scan_path
from .models import Warning


class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def format_severity(severity: str, use_colors: bool) -> str:
    if not use_colors:
        return severity

    color = Colors.RED if severity == "HIGH" else Colors.YELLOW
    return f"{color}{severity}{Colors.RESET}"


def print_warnings(warnings: list[Warning], output: TextIO, use_colors: bool) -> None:
    """
    Print the list of warnings to the given output.
    """
    if not warnings:
        output.write("✓ No issues found.\n")
        return

    # Group warnings by severity
    high = [w for w in warnings if w.severity == "HIGH"]
    med = [w for w in warnings if w.severity == "MED"]
    low = [w for w in warnings if w.severity == "LOW"]

    # Output
    total = len(warnings)
    if use_colors:
        output.write(f"\n{Colors.BOLD}Security Analysis Results{Colors.RESET}\n")
        output.write(f"{'=' * 50}\n")
        output.write(f"Total Issues: {total} ")
        if high:
            output.write(f"({Colors.RED}HIGH: {len(high)}{Colors.RESET} ")
        if med:
            output.write(f"{Colors.YELLOW}MED: {len(med)}{Colors.RESET} ")
        if low:
            output.write(f"LOW: {len(low)} ")
        output.write(")\n\n")
    else:
        output.write(f"\nSecurity Analysis Results\n")
        output.write(f"{'=' * 50}\n")
        output.write(f"Total Issues: {total} (HIGH: {len(high)} MED: {len(med)} LOW: {len(low)})\n\n")

    # Print each warning
    for i, w in enumerate(warnings, 1):
        severity_str = format_severity(w.severity, use_colors)

        if use_colors:
            output.write(f"{Colors.BOLD}[{i}/{total}] {severity_str}{Colors.RESET}")
        else:
            output.write(f"[{i}/{total}] {severity_str}")

        cwe = f" ({w.cwe})" if w.cwe else ""

        if use_colors:
            output.write(f" {Colors.CYAN}{w.file}:{w.line_no}{Colors.RESET}{cwe}\n")
        else:
            output.write(f" {w.file}:{w.line_no}{cwe}\n")

        output.write(f"  {w.message}\n")
        output.write(f"  > {w.line}\n")
        output.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mini static analyzer for C programs",
        prog="python -m scanner.cli"
    )
    parser.add_argument(
        "path",
        help="Path to C file or directory to scan"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: stdout)",
        type=str,
        default=None
    )
    parser.add_argument(
        "--no-color",
        help="Disable colored output",
        action="store_true"
    )

    args = parser.parse_args()

    # Scan file(s)
    warnings = scan_path(args.path)
    severity_rank = {"HIGH": 0, "MED": 1, "LOW": 2}

    # Sort warnings by severity, then file, then line number
    warnings = sorted(
        warnings,
        key=lambda w: (severity_rank.get(w.severity, 99), w.file, w.line_no)
    )

    # Output destination and color usage
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            print_warnings(warnings, f, use_colors=False)
        print(f"Results written to {args.output}")
    else:
        use_colors = not args.no_color and sys.stdout.isatty()
        print_warnings(warnings, sys.stdout, use_colors)


if __name__ == "__main__":
    main()
