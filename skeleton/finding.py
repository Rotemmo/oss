from dataclasses import dataclass

@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    issue: str
    severity: str  # -> critical | high | medium | low
    snippet: str
    explanation: str | None = None
    fix: str | None = None