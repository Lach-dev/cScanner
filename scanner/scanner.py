import os
import re
from typing import Dict, List

from .models import Warning
from .rules import (
    UNSAFE_FUNCTIONS,
    CHAR_ARRAY_DECL_RE,
    MEMCPY_RE,
    PRINTF_CALL_RE,
)


def strip_comments(lines: List[str]) -> List[str]:
    """
    Lightweight comment stripper for C
    - Removes // comments
    - Removes /* ... */ blocks
    """
    stripped: List[str] = []
    in_block = False

    for line in lines:
        if in_block:
            end_idx = line.find("*/")
            if end_idx != -1:
                line = line[end_idx + 2 :]
                in_block = False
            else:
                stripped.append("")
                continue

        while "/*" in line:
            start = line.find("/*")
            end = line.find("*/", start + 2)
            if end == -1:
                line = line[:start]
                in_block = True
                break
            else:
                line = line[:start] + line[end + 2 :]

        # Strip // comments.
        line = re.split(r"//", line, maxsplit=1)[0]
        stripped.append(line)

    return stripped


def collect_char_arrays(lines: List[str]) -> Dict[str, int]:
    """
    Collects char buf[N] declarations into a simple symbol table:
    name -> size
    """
    table: Dict[str, int] = {}
    for line in lines:
        m = CHAR_ARRAY_DECL_RE.search(line)
        if m:
            name = m.group(1)
            size = int(m.group(2))
            table[name] = size
    return table


def check_unsafe_functions(filename: str, lines: List[str]) -> List[Warning]:
    warnings: List[Warning] = []
    for i, line in enumerate(lines, start=1):
        for func, meta in UNSAFE_FUNCTIONS.items():
            if re.search(r"\b" + re.escape(func) + r"\s*\(", line):
                warnings.append(
                    Warning(
                        file=filename,
                        line_no=i,
                        severity=meta["severity"],
                        cwe=meta["cwe"],
                        message=f"{func} used. {meta['msg']}",
                        line=line.rstrip(),
                    )
                )
    return warnings


def check_memcpy_overflows(
    filename: str,
    lines: List[str],
    char_arrays: Dict[str, int],
) -> List[Warning]:
    """
    Check for memcpy(buf, ..., N) where N is a literal larger than
    the declared size of buf.
    """
    warnings: List[Warning] = []
    for i, line in enumerate(lines, start=1):
        m = MEMCPY_RE.search(line)
        if not m:
            continue

        dest = m.group(1)
        size_lit = int(m.group(2))

        if dest in char_arrays:
            decl_size = char_arrays[dest]
            if size_lit > decl_size:
                warnings.append(
                    Warning(
                        file=filename,
                        line_no=i,
                        severity="HIGH",
                        cwe="CWE-120",
                        message=(
                            f"memcpy to '{dest}' copies {size_lit} bytes "
                            f"but buffer is only {decl_size} bytes."
                        ),
                        line=line.rstrip(),
                    )
                )
    return warnings


def _is_string_literal(expr: str) -> bool:
    expr = expr.strip()
    return expr.startswith('"')


def check_printf_format(filename: str, lines: List[str]) -> List[Warning]:
    """
    Flag printf(x) where x is not a string literal, which can indicate
    a format string vulnerability if attacker controlled.
    """
    warnings: List[Warning] = []
    for i, line in enumerate(lines, start=1):
        m = PRINTF_CALL_RE.search(line)
        if not m:
            continue

        args = m.group(1)
        first_arg = args.split(",", 1)[0].strip()

        if not _is_string_literal(first_arg):
            warnings.append(
                Warning(
                    file=filename,
                    line_no=i,
                    severity="HIGH",
                    cwe="CWE-134",
                    message=(
                        "printf called with non-literal format string; "
                        "possible format string vulnerability."
                    ),
                    line=line.rstrip(),
                )
            )
    return warnings

def check_large_stack_buffers(filename: str, lines: List[str], threshold: int = 1024) -> List[Warning]:
    """Flag large stack allocated buffers that could cause stack overflow."""
    warnings: List[Warning] = []
    for i, line in enumerate(lines, start=1):
        m = CHAR_ARRAY_DECL_RE.search(line)
        if m:
            size = int(m.group(2))
            if size > threshold:
                warnings.append(
                    Warning(
                        file=filename,
                        line_no=i,
                        severity="MED",
                        cwe="CWE-770",
                        message=f"Large stack buffer ({size} bytes) may cause stack overflow.",
                        line=line.rstrip(),
                    )
                )
    return warnings


def check_alloca_usage(filename: str, lines: List[str]) -> List[Warning]:
    """Flag alloca() usage which can cause stack overflow."""
    warnings: List[Warning] = []
    alloca_re = re.compile(r"\balloca\s*\(")
    for i, line in enumerate(lines, start=1):
        if alloca_re.search(line):
            warnings.append(
                Warning(
                    file=filename,
                    line_no=i,
                    severity="MED",
                    cwe="CWE-770",
                    message="alloca() can cause stack overflow; prefer heap allocation.",
                    line=line.rstrip(),
                )
            )
    return warnings

def scan_file(path: str) -> List[Warning]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            raw_lines = f.readlines()
    except OSError as e:
        print(f"[ERROR] Could not read {path}: {e}")
        return []

    lines = strip_comments(raw_lines)
    char_arrays = collect_char_arrays(lines)

    warnings: List[Warning] = []
    warnings.extend(check_unsafe_functions(path, lines))
    warnings.extend(check_memcpy_overflows(path, lines, char_arrays))
    warnings.extend(check_printf_format(path, lines))

    return warnings


def scan_path(root: str) -> List[Warning]:
    """
    Scan a single file or recursively scan a directory tree for .c/.h files.
    """
    all_warnings: List[Warning] = []

    if os.path.isfile(root):
        if root.endswith((".c", ".h")):
            all_warnings.extend(scan_file(root))
        return all_warnings

    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            if not fname.endswith((".c", ".h")):
                continue
            full_path = os.path.join(dirpath, fname)
            all_warnings.extend(scan_file(full_path))

    return all_warnings
