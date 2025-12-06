from dataclasses import dataclass
from typing import Optional


@dataclass
class Warning:
    file: str
    line_no: int
    severity: str
    cwe: Optional[str]
    message: str
    line: str
