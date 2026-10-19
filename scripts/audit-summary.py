#!/usr/bin/env python3
"""Print non-secret advisory summaries while keeping full JSON in CI artifacts."""
import json
from pathlib import Path
import sys
for path in sorted(Path(sys.argv[1]).glob("*.json")):
    try:
        report=json.loads(path.read_text())
    except (OSError,ValueError):
        print(path.name+": incomplete report")
        continue
    if path.name=="gitleaks.json":
        print("gitleaks history findings:",len(report) if isinstance(report,list) else "invalid report")
        if isinstance(report,list):
            for item in report:print("gitleaks",item.get("RuleID"),item.get("File"),item.get("StartLine"),item.get("Commit"))
        continue
    findings=report.get("vulnerabilities",{})
    if path.name=="npm.json":
        print("npm totals:",report.get("metadata",{}).get("vulnerabilities",{}))
        for name,item in findings.items():
            print("npm",name,item.get("severity"),"fixAvailable="+str(item.get("fixAvailable")))
    else:
        print(path.name,"database:",report.get("database"),"vulnerabilities:",findings.get("count"))
        for item in findings.get("list",[]):
            advisory=item["advisory"];package=item["package"]
            print(advisory["id"],package["name"],package["version"],advisory["title"])
        for kind,items in report.get("warnings",{}).items():
            print(path.name,"warning",kind,len(items))
