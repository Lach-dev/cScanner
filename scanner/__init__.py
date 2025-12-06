"""
Mini static analyzer for C programs that detects unsafe or suspicious usage patterns.
"""

__version__ = "0.1.0"

# Re-export commonly used functions so consumers can import directly from the package.
from .scanner import (
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

__all__ = [
    "scan_path",
    "scan_file",
    "strip_comments",
    "collect_char_arrays",
    "check_unsafe_functions",
    "check_memcpy_overflows",
    "check_printf_format",
    "check_large_stack_buffers",
    "check_alloca_usage",
    "__version__",
]
