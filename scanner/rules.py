import re

# Metadata for obviously unsafe functions.
UNSAFE_FUNCTIONS = {
    "gets": {
        "severity": "HIGH",
        "cwe": "CWE-242",
        "msg": "gets() is inherently unsafe; use fgets() instead.",
    },
    "strcpy": {
        "severity": "HIGH",
        "cwe": "CWE-120",
        "msg": "Potential buffer overflow; use strncpy()/strlcpy().",
    },
    "strcat": {
        "severity": "HIGH",
        "cwe": "CWE-120",
        "msg": "Potential buffer overflow; use strncat()/strlcat().",
    },
    "sprintf": {
        "severity": "MED",
        "cwe": "CWE-120/CWE-134",
        "msg": "Use snprintf() to limit buffer size.",
    },
    "vsprintf": {
        "severity": "MED",
        "cwe": "CWE-120/CWE-134",
        "msg": "Use vsnprintf() to limit buffer size.",
    },
    "scanf": {
        "severity": "HIGH",
        "cwe": "CWE-120",
        "msg": "Unbounded scanf can overflow buffers; prefer fgets() or bounded width (e.g., \"%%31s\").",
    },
    "fscanf": {
        "severity": "HIGH",
        "cwe": "CWE-120",
        "msg": "Unbounded fscanf can overflow buffers; prefer fgets() or bounded width.",
    },
    "sscanf": {
        "severity": "HIGH",
        "cwe": "CWE-120",
        "msg": "Unbounded sscanf can overflow buffers; ensure bounded width in format string.",
    },
}


# Regexes used across scanner logic.
CHAR_ARRAY_DECL_RE = re.compile(r"\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]")
MEMCPY_RE = re.compile(r"\bmemcpy\s*\(\s*(\w+)\s*,\s*[^,]+,\s*(\d+)\s*\)")
PRINTF_CALL_RE = re.compile(r"\bprintf\s*\((.+)\);")
STACK_BUFFER_RE = re.compile(r"\bchar\s+\w+\s*\[\s*(\d+)\s*\]")
ALLOCA_RE = re.compile(r"\balloca\s*\(")
