"""Report bounded native compilation/test evidence without raw Maven or credential output."""
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[1]
status = int(sys.argv[1])
reports = []
for path in sorted((root / "extensions").glob("*/target/surefire-reports/TEST-*.xml")):
    tree = ET.parse(path).getroot()
    record = {"module": path.parts[-4], "suite": tree.get("name"),
              **{key: int(tree.get(key, "0")) for key in ("tests", "failures", "errors", "skipped")}}
    problems = []
    for case in tree.findall("testcase"):
        for issue in list(case):
            if issue.tag not in ("failure", "error"):
                continue
            name, kind = case.get("name", ""), issue.get("type", "")
            frames = re.findall(r"(?m)^\s+at (io\.firefly\.[\w.$]+\([\w.]+:\d+\))", issue.text or "")
            problems.append({"test": name if re.fullmatch(r"[\w$]+", name) else "parameterized-case",
                             "type": kind if re.fullmatch(r"[\w.$]+", kind) else "unclassified",
                             "source_frames": frames[:3]})
    if problems:
        record["problems"] = problems[:10]
    reports.append(record)
summary = {"maven_exit": status, "suites": reports,
           "scope": "Native extension compilation and tests; real provider/integration acceptance is separate."}
target = root / ".qualification/native-build-summary.json"
target.parent.mkdir(exist_ok=True)
target.write_text(json.dumps(summary, indent=2) + "\n")
for line in (root / ".qualification/native-maven.log").read_text(errors="replace").splitlines():
    if re.match(r"^\[ERROR\]\s+(?:/[^:]+\.java:\[\d+,\d+\]|symbol:\s+(?:class|method|variable)\s+[\w$]+|package\s+[\w.]+\s+does not exist)", line):
        print(line[:350])
print(json.dumps(summary))
if status or not reports or any(row["failures"] or row["errors"] or row["skipped"] for row in reports):
    raise SystemExit(1)
