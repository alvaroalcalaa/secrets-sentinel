"""Secrets Sentinel: lightweight local secret scanner."""
from __future__ import annotations
import argparse,json,re
from pathlib import Path
RULES=[
 ("HIGH","AWS access key",r"AKIA[0-9A-Z]{16}"),
 ("HIGH","GitHub token-like value",r"gh[pousr]_[A-Za-z0-9_]{20,}"),
 ("HIGH","Private key header",r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
 ("MEDIUM","URL with embedded credentials",r"://[^\s/:]+:[^\s@]+@"),
 ("MEDIUM","Generic API key assignment",r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][^'\"]{8,}"),
]
SKIP={".git","node_modules",".venv","__pycache__"}
def scan(root):
 findings=[]
 for path in Path(root).rglob("*"):
  if not path.is_file() or any(x in SKIP for x in path.parts): continue
  try: lines=path.read_text(encoding="utf-8",errors="ignore").splitlines()
  except OSError: continue
  for number,line in enumerate(lines,1):
   for severity,name,pattern in RULES:
    if re.search(pattern,line): findings.append({"severity":severity,"rule":name,"file":str(path),"line":number})
 return findings
def main():
 p=argparse.ArgumentParser();p.add_argument("path",nargs="?",default=".");p.add_argument("--report");p.add_argument("--strict",action="store_true");a=p.parse_args()
 findings=scan(a.path)
 for f in findings: print(f"{f['severity']:<6} {f['file']}:{f['line']}  {f['rule']}")
 print(f"Summary: {len(findings)} findings")
 if a.report: Path(a.report).write_text(json.dumps(findings,indent=2),encoding="utf-8")
 if a.strict and findings: raise SystemExit(1)
if __name__=="__main__": main()
