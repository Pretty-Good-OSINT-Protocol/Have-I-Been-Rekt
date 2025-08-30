#!/usr/bin/env python3
"""
Minimal test to validate core infrastructure without heavy dependencies
"""

import sys
import os
import json
import tempfile

# Add src to path  
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_basic_imports():
    """Test that core classes can be imported"""
    print("Testing basic imports...")
    
    # Test data collector enums and models without dependencies
    try:
        import importlib.util
        
        # Load data_collector module
        spec = importlib.util.spec_from_file_location(
            "data_collector", 
            os.path.join(os.path.dirname(__file__), 'src', 'data_collector.py')
        )
        data_collector = importlib.util.module_from_spec(spec)
        
        # Mock missing dependencies
        sys.modules['aiohttp'] = type('MockModule', (), {})()
        sys.modules['requests'] = type('MockModule', (), {})()
        sys.modules['diskcache'] = type('MockModule', (), {})()
        
        # Execute the module
        spec.loader.exec_module(data_collector)
        
        # Test basic classes exist
        assert hasattr(data_collector, 'RiskLevel')
        assert hasattr(data_collector, 'RiskFactor')
        assert hasattr(data_collector, 'WalletAnalysis')
        assert hasattr(data_collector, 'BaseDataCollector')
        
        # Test enums work
        RiskLevel = data_collector.RiskLevel
        assert RiskLevel.CRITICAL == "critical"
        assert RiskLevel.HIGH == "high"
        assert RiskLevel.MEDIUM == "medium"
        
        print("✓ Core classes can be imported")
        
    except Exception as e:
        print(f"✗ Import failed: {e}")
        raise

def test_config_structure():
    """Test configuration structure without pydantic"""
    print("Testing config file structure...")
    
    config_file = os.path.join(os.path.dirname(__file__), 'config', 'config.example.json')
    assert os.path.exists(config_file), "config.example.json not found"
    
    with open(config_file) as f:
        config = json.load(f)
    
    # Test required sections exist
    required_sections = [
        'api_keys', 'rate_limits', 'cache', 'data_sources', 
        'logging', 'risk_scoring'
    ]
    
    for section in required_sections:
        assert section in config, f"Missing config section: {section}"
    
    # Test API keys section
    assert 'chainalysis' in config['api_keys']
    assert 'haveibeenpwned' in config['api_keys']
    assert 'virustotal' in config['api_keys']
    
    # Test data sources
    assert 'ofac_sanctions' in config['data_sources']
    assert 'cryptoscamdb' in config['data_sources']
    
    # Test risk scoring
    assert 'weights' in config['risk_scoring']
    assert 'thresholds' in config['risk_scoring']
    
    print("✓ Configuration structure valid")

def test_directory_structure():
    """Test directory structure is complete"""
    print("Testing directory structure...")
    
    base_dir = os.path.dirname(__file__)
    expected_dirs = [
        'src',
        'src/collectors',
        'src/processors', 
        'src/models',
        'src/utils',
        'data',
        'data/raw',
        'data/processed',
        'data/models',
        'config',
        'tests',
        'scripts'
    ]
    
    missing_dirs = []
    for dir_path in expected_dirs:
        full_path = os.path.join(base_dir, dir_path)
        if not os.path.exists(full_path):
            missing_dirs.append(dir_path)
    
    assert len(missing_dirs) == 0, f"Missing directories: {missing_dirs}"
    print("✓ Directory structure complete")

def test_required_files():
    """Test all required files exist and have content"""
    print("Testing required files...")
    
    base_dir = os.path.dirname(__file__)
    required_files = [
        'requirements.txt',
        'pytest.ini', 
        'src/__init__.py',
        'src/data_collector.py',
        'src/utils/__init__.py',
        'src/utils/config.py',
        'src/utils/logging.py',
        'config/config.example.json',
        'tests/conftest.py',
        'tests/test_data_collector.py',
        'tests/test_config.py'
    ]
    
    for file_path in required_files:
        full_path = os.path.join(base_dir, file_path)
        assert os.path.exists(full_path), f"Missing file: {file_path}"
        
        # Check file has content
        size = os.path.getsize(full_path)
        assert size > 0, f"Empty file: {file_path}"
        
        # Spot check a few critical files
        if file_path == 'src/data_collector.py':
            with open(full_path) as f:
                content = f.read()
                assert 'class BaseDataCollector' in content
                assert 'class WalletAnalysis' in content
                assert 'class RiskLevel' in content
        
        elif file_path == 'requirements.txt':
            with open(full_path) as f:
                content = f.read()
                assert 'requests' in content
                assert 'pydantic' in content
                assert 'pytest' in content
    
    print("✓ All required files present and valid")

def test_package_structure():
    """Test Python package structure"""
    print("Testing Python package structure...")
    
    base_dir = os.path.dirname(__file__)
    
    # Check __init__.py files exist
    init_files = [
        'src/__init__.py',
        'src/utils/__init__.py'
    ]
    
    for init_file in init_files:
        full_path = os.path.join(base_dir, init_file)
        assert os.path.exists(full_path), f"Missing __init__.py: {init_file}"
        
        # Check content of main __init__.py
        if init_file == 'src/__init__.py':
            with open(full_path) as f:
                content = f.read()
                assert '__version__' in content
                assert '__all__' in content
    
    print("✓ Package structure valid")

def main():
    """Run all minimal tests"""
    print("🧪 Minimal AI Training Infrastructure Test")
    print("=" * 45)
    
    try:
        test_directory_structure()
        test_required_files()
        test_package_structure()
        test_config_structure()
        test_basic_imports()
        
        print("=" * 45)
        print("✅ All infrastructure tests passed!")
        print("\n📋 Infrastructure Summary:")
        print("• Directory structure: ✓ Complete")
        print("• Core files: ✓ Present")  
        print("• Configuration: ✓ Valid")
        print("• Python packages: ✓ Structured")
        print("• Core classes: ✓ Importable")
        print("\n🚀 Ready for Issue #38 - Sanctions Integration")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)