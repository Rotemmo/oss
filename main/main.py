import argparse, json, sys
from core.scan import scan_file
from llm.engine import LocalLLM

def main():
    ap = argparse.ArgumentParser(description="C/C++ security analyzer (offline).")
    ap.add_argument("path", help="Path to a C/C++ source file")
    ap.add_argument("--format", choices=["json"], help="Output format")
    ap.add_argument("--lang", choices=["auto","c","cpp"], default="auto", help="Language mode")
    ap.add_argument("--llm", action="store_true", help="Enable LLM assistance")
    ap.add_argument("--model-path", defaקרult=None, help="Path to the local LLM model")
    args = ap.parse_args()

    llm = LocalLLM(enabled=args.llm, model_path=args.model_path)
    findings = scan_file(args.path, lang=args.lang, llm=llm)

    print(json.dumps([f.__dict__ for f in findings], ensure_ascii=False, indent=2))

if __name__ == "__main__":
    sys.exit(main())