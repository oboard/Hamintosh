#!/usr/bin/env python3
"""Collect the latest native diagnostics and a screenshot from a connected phone."""
import argparse
import json
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, default=Path("artifacts"))
parser.add_argument("--device", help="HDC connection identifier")
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
hdc = ["hdc"] + (["-t", args.device] if args.device else [])


def run(*command):
    return subprocess.run(hdc + list(command), capture_output=True, text=True, check=True).stdout


logs = run("shell", "hilog", "-x", "-T", "Hamintosh")
(args.output / "gate0-device.log").write_text(logs)
records = run("shell", "hilog", "-x", "-T", "HamintoshReport")
(args.output / "report-device.log").write_text(records)
chunks = {}
for match in re.finditer(r"HamintoshReport: (\d+) (.*)", records):
    offset = int(match[1])
    if offset == 0:
        chunks = {}
    chunks[offset] = match[2]
if not chunks:
    raise SystemExit("No report found. Launch Hamintosh and wait for diagnostics to finish.")
text = ""
for offset in sorted(chunks):
    if offset != len(text):
        raise SystemExit("Incomplete device report; run diagnostics again and retry collection")
    text += chunks[offset]
report = json.loads(text)
path = args.output / "device-compat-report.json"
path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
print(f"Report: {path.resolve()}")
print("Mach-O AOT probe:", report["gate0"]["packaged"]["status"], report["gate0"]["packaged"]["value"])
print("App executed:", report["preflight"]["appExecuted"])
remote = "/data/local/tmp/hamintosh-latest.jpeg"
run("shell", "snapshot_display", "-f", remote)
run("file", "recv", remote, str(args.output / "hamintosh-latest.jpeg"))
print(f"Screenshot: {(args.output / 'hamintosh-latest.jpeg').resolve()}")
