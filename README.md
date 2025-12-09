# Mini C Static Analyzer

Lightweight static analysis tool for C source files. Detects common unsafe patterns. 

## Features

- Detects usage of known unsafe functions (`gets`, `strcpy`, `strcat`, `sprintf`, `scanf`, etc.)
- Flags `memcpy` calls that copy more bytes than a declared `char` buffer
- Detects non-literal `printf` format strings
- Flags large stack-allocated buffers and `alloca()` usage
- CLI and programmatic API

## Requirements

- Python 3.12
- Works on Windows, Linux, macOS

## Installation

Clone the repository and install dependencies:

```bash
git clone git@github.com:Lach-dev/cScanner.git
cd cScanner
pip install -r requirements.txt 
pip install -e .
```

## CLI Usage

Scan a single file or a directory tree for `.c` and `.h` files:

```bash
python -m scanner.cli PATH_TO_FILE_OR_DIR
```

Options:

- `-o, --output` Write results to a file (default: stdout)
- `--no-color` Disable colored output

Examples:

```bash
# Scan a project directory
python -m scanner.cli ./src

# Write results to a file
python -m scanner.cli ./src -o results.txt

# Force plain output (no colors)
python -m scanner.cli ./src --no-color
```

Output includes severity, CWE (if available), file and line number, and a brief message.

```bash
Security Analysis Results
==================================================
Total Issues: 12 (HIGH: 11 MED: 1 )

[1/12] HIGH .\test_c\basic_overflow.c:7 (CWE-120)
  strcpy used. Potential buffer overflow; use strncpy()/strlcpy().
  >     strcpy(buffer, name);

[2/12] HIGH .\test_c\basic_overflow.c:8 (CWE-120)
  strcat used. Potential buffer overflow; use strncat()/strlcat().
  >     strcat(buffer, suffix);
```

## Programmatic API

Import high-level functions from the package:

```python
from scanner import (
    scan_path,
    scan_file,
    strip_comments,
    collect_char_arrays,
    check_unsafe_functions,
    check_memcpy_overflows,
    check_printf_format,
    check_large_stack_buffers,
    check_alloca_usage,
)
```

Examples:

```python
# Scan a single file
warnings = scan_file("examples/test.c")

# Scan a directory
all_warnings = scan_path("examples/")

# Use helpers on file contents
with open("examples/test.c") as f:
    lines = strip_comments(f.readlines())
char_tables = collect_char_arrays(lines)
warnings = check_memcpy_overflows("test.c", lines, char_tables)
```

Each warning is a `Warning` dataclass instance with fields:
- `file`
- `line_no`
- `severity` (e.g., HIGH, MED, LOW)
- `cwe` (optional)
- `message`
- `line` (source line text)

See `scanner/models.py` for the dataclass definition.

## Testing & Linting

Run tests with `pytest`:

```bash
pytest
```

Lint with `flake8`:

```bash
flake8 .
```


## Contributing

- Open issues or PRs for bugs and improvements.
- Follow existing code style; run tests locally before submitting.
- Add unit tests for new rules or edge cases.

```
