import re
from core.findings import Finding

# Very naive regex-based heuristics for C
R_GETS = re.compile(r"\bgets\s*\(")
R_STRCPY = re.compile(r"\bstrcpy\s*\(")
R_STRCAT = re.compile(r"\bstrcat\s*\(")
R_SCANF_FMT = re.compile(r'\bscanf\s*\(\s*"([^"]*)"')
R_FREE = re.compile(r"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)\s*;")
R_PRINTF = re.compile(r"\bprintf\s*\(")
R_MEMCPY = re.compile(r"\bmemcpy\s*\(")

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

def _scanf_has_unsafe_s(file, i, line_text, fmt):
    # Flag %s that is NOT preceded by a width like %10s
    # Very naive: look for any '%s' that does not have a digit before it
    unsafe = False
    for m in re.finditer(r"(%)([^%]*)s", fmt):
        # m.group(2) is what's between % and s
        if not re.search(r"\d", m.group(2)):
            unsafe = True
            break
    if unsafe:
        return True
    return False

def _printf_first_arg_is_literal(line_text):
    # True if the first argument of printf is a string literal (starts with ")
    # This is naive and only looks for printf("..."
    stripped = line_text.strip()
    # remove leading 'printf(' and spaces
    try:
        idx = stripped.index("printf")
        rest = stripped[idx+6:].lstrip()  # after 'printf'
        # Expect '('
        p = rest.index("(")
        args = rest[p+1:].lstrip()
        return args.startswith('"')
    except Exception:
        return False

def scan_c_lines(file, lines):
    findings = []
    # Track frees to detect naive UAF: use within the next few lines
    freed_vars = {}

    for i, line in enumerate(lines):
        if R_GETS.search(line):
            _add(findings, file, i, "C001_GETS", "critical", line,
                 "Unsafe gets() call (unbounded input).",
                 "Use fgets(buffer, sizeof buffer, stdin) instead of gets().")

        if R_STRCPY.search(line) or R_STRCAT.search(line):
            which = "strcpy" if R_STRCPY.search(line) else "strcat"
            _add(findings, file, i, "C002_STRCPY_CAT", "high", line,
                 f"Potential overflow: {which} without bounds check.",
                 "Use strncpy/strncat (and ensure null-termination) or safer alternatives.")

        m = R_SCANF_FMT.search(line)
        if m:
            fmt = m.group(1)
            if "%s" in fmt and _scanf_has_unsafe_s(file, i, line, fmt):
                _add(findings, file, i, "C003_SCANF_S", "medium", line,
                     'scanf with "%s" and no width → possible overflow.',
                     'Use width like "%99s" to limit input length.')

        # Naive use-after-free: record var freed, then if used soon after, flag
        fm = R_FREE.search(line)
        if fm:
            var = fm.group(1)
            freed_vars[var] = i  # remember line index

        # If a recently freed var appears with -> or . usage
        for var, free_line in list(freed_vars.items()):
            if i - free_line > 5:
                # stop tracking after a few lines
                del freed_vars[var]
                continue
            if re.search(rf"\b{re.escape(var)}\s*->", line) or re.search(rf"\b{re.escape(var)}\s*\.", line):
                _add(findings, file, i, "C004_UAF", "high", line,
                     f"Use-after-free: '{var}' used after free() on a nearby line.",
                     "Avoid using a pointer after free(); set it to NULL and reassign before use.")
                # stop tracking this var
                del freed_vars[var]
                break

        if R_PRINTF.search(line) and not _printf_first_arg_is_literal(line):
            _add(findings, file, i, "C005_PRINTF_FMT", "medium", line,
                 "printf with non-literal first argument → possible format string vulnerability.",
                 "Ensure the first argument is a string literal format; use '%s' for user input.")

        if R_MEMCPY.search(line):
            _add(findings, file, i, "C006_MEMCPY", "low", line,
                 "memcpy present — verify destination buffer is large enough.",
                 "Limit length to the smaller of (dst capacity, src length).")

    return findings