import os
from skeleton.findings import Finding
from rules.c_rules import scan_c_lines
from rules.cpp_rules import scan_cpp_lines

def scan_file(path: str, lang: str = 'auto', llm=None) -> list[Finding]:
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    ext = os.path.splitext(path)[1].lower()
    if lang == 'auto':
        if ext in ('.cpp', '.cc', '.cxx', '.hpp', '.hh'):
            lang = 'cpp'
        else:
            lang = 'c'  
    findings = []
    
    if lang == 'cpp':
        findings = scan_cpp_lines(path, lines)
    else:
        findings = scan_c_lines(path, lines)

    if llm and getattr(llm, "enabled", False):
        for f in findings:
            if not f.explanation:
                f.explanation = llm.explain(f)
            if not f.fix:
                f.fix = llm.suggest_fix(f)
    return findings