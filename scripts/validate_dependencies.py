#!/usr/bin/env python3
"""
Dependency validation script for Elastic LOLBin Detection Pack.
Validates that all dependencies can be imported and are compatible.
"""

import sys
import subprocess
import importlib
from typing import List, Tuple, Dict

# Core dependencies to validate
CORE_PACKAGES = {
    'requests': 'HTTP client library',
    'urllib3': 'HTTP library with connection pooling',
    'yaml': 'YAML parser (pyyaml)',
    'jinja2': 'Template engine',
    'pytest': 'Testing framework',
    'pysigma': 'Sigma rule processing',
    'elasticsearch': 'Elasticsearch client',
    'jsonschema': 'JSON schema validation',
    'black': 'Code formatter',
    'isort': 'Import sorter',
    'flake8': 'Linting tool'
}

def check_import(package_name: str, description: str) -> Tuple[bool, str]:
    """Check if a package can be imported."""
    try:
        if package_name == 'yaml':
            # pyyaml imports as yaml
            import yaml
            version = getattr(yaml, '__version__', 'unknown')
        elif package_name == 'pysigma':
            # pySigma imports as sigma
            import sigma
            version = getattr(sigma, '__version__', 'unknown')
        else:
            module = importlib.import_module(package_name)
            version = getattr(module, '__version__', 'unknown')
        
        return True, version
    except ImportError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Unexpected error: {e}"

def run_pip_check() -> Tuple[bool, str]:
    """Run pip check to verify no broken dependencies."""
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'check'],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Timeout running pip check"
    except Exception as e:
        return False, f"Error running pip check: {e}"

def test_sigma_functionality():
    """Test basic Sigma rule processing functionality."""
    try:
        # Test basic import and backend creation
        from sigma.backends.elasticsearch import LuceneBackend
        from sigma.rule import SigmaRule
        
        # Just test that the backend can be created
        backend = LuceneBackend()
        
        # Test basic SigmaRule creation
        rule_yaml = """
title: Test Rule
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
"""
        
        rule = SigmaRule.from_yaml(rule_yaml)
        
        # Basic validation that the rule was created
        if hasattr(rule, 'title') and rule.title == 'Test Rule':
            return True, f"Successfully created rule: {rule.title}"
        else:
            return False, "Rule creation didn't work as expected"
            
    except Exception as e:
        return False, f"Sigma functionality test failed: {e}"

def test_elasticsearch_client():
    """Test Elasticsearch client creation."""
    try:
        from elasticsearch import Elasticsearch
        
        # Create client without connecting
        es = Elasticsearch(['localhost:9200'], verify_certs=False)
        
        return True, f"Client created: {type(es).__name__}"
    except Exception as e:
        return False, f"Elasticsearch client test failed: {e}"

def test_json_schema():
    """Test JSON schema validation."""
    try:
        import jsonschema
        
        schema = {
            'type': 'object',
            'properties': {
                'name': {'type': 'string'},
                'age': {'type': 'number'}
            }
        }
        
        # Valid data
        data = {'name': 'test', 'age': 25}
        jsonschema.validate(data, schema)
        
        return True, "Schema validation successful"
    except Exception as e:
        return False, f"JSON schema test failed: {e}"

def main():
    """Main validation function."""
    print("🔍 Elastic LOLBin Detection Pack - Dependency Validation")
    print("=" * 60)
    
    all_passed = True
    results = []
    
    # Test package imports
    print("\n📦 Testing Package Imports:")
    print("-" * 30)
    
    for package, description in CORE_PACKAGES.items():
        success, message = check_import(package, description)
        status = "✅" if success else "❌"
        print(f"{status} {package:15} ({description}): {message}")
        results.append((package, success, message))
        if not success:
            all_passed = False
    
    # Run pip check
    print("\n🔧 Running pip check:")
    print("-" * 20)
    pip_success, pip_output = run_pip_check()
    status = "✅" if pip_success else "❌"
    print(f"{status} Dependency consistency: {'OK' if pip_success else 'ISSUES FOUND'}")
    if not pip_success:
        print(f"   Output: {pip_output}")
        all_passed = False
    
    # Test functionality
    print("\n🧪 Testing Core Functionality:")
    print("-" * 30)
    
    # Test Sigma processing
    sigma_success, sigma_message = test_sigma_functionality()
    status = "✅" if sigma_success else "❌"
    print(f"{status} Sigma rule processing: {sigma_message}")
    if not sigma_success:
        all_passed = False
    
    # Test Elasticsearch client
    es_success, es_message = test_elasticsearch_client()
    status = "✅" if es_success else "❌"
    print(f"{status} Elasticsearch client: {es_message}")
    if not es_success:
        all_passed = False
    
    # Test JSON schema
    json_success, json_message = test_json_schema()
    status = "✅" if json_success else "❌"
    print(f"{status} JSON schema validation: {json_message}")
    if not json_success:
        all_passed = False
    
    # Summary
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 All dependency validation tests PASSED!")
        print("✅ Your environment is ready for Elastic LOLBin Detection Pack")
        return 0
    else:
        print("💥 Some dependency validation tests FAILED!")
        print("❌ Please check the issues above and run:")
        print("   pip install -r requirements.txt -c constraints.txt")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 