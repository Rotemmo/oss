import re
from core.findings import Finding

R_MEMCPY = re.compile(r"\bmemcpy\s*\(")
R_NEW_ARRAY = re.compile(r"\bnew\s+char\s*\[\s*([^\]]+)\s*\]")

def _add(finds, file, i, rule, sev, line_text, issue, fix=None):
    finds.append(Finding(
        file=file,
        line=i+1,
        rule_id=rule,
        issue=issue,
        severity=sev,
        snippet=line_text.strip(),
        fix=fix
    ))

def scan_cpp_lines(file, lines):
    findings = []
    for i, line in enumerate(lines):
        if R_MEMCPY.search(line):
            _add(findings, file, i, "CPP001_MEMCPY", "medium", line,
                 "memcpy in C++ — check bounds; consider std::copy or safe wrappers.",
                 "Ensure copy length does not exceed destination buffer size.")
        if R_NEW_ARRAY.search(line):
            _add(findings, file, i, "CPP002_NEW_CHAR_ARRAY", "low", line,
                 "raw new[] for char buffer — ensure size is validated; prefer std::vector/std::string.",
                 "Validate sizes and prefer RAII containers to avoid leaks/overflows.")
    return findings