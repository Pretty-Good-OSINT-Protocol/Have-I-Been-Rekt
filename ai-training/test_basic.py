#!/usr/bin/env python3
"""
Basic test to validate infrastructure without heavy dependencies
"""

import sys
import os
import json
import tempfile

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_config_system():
    """Test configuration system"""
    print("Testing configuration system...")
    
    # Test basic config loading
    from utils.config import ConfigManager, AppConfig
    
    # Test with temporary config
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        test_config = {
            "api_keys": {"test": "value"},
            "cache": {"enabled": True}
        }
        json.dump(test_config, f)
        temp_path = f.name
    
    try:
        manager = ConfigManager(temp_path)
        config = manager.load_config()
        
        assert isinstance(config, AppConfig)
        assert config.cache.enabled is True
        print("✓ Configuration system working")
        
    finally:
        os.unlink(temp_path)

def test_data_collector_structure():
    """Test data collector structure"""
    print("Testing data collector structure...")
    
    from data_collector import RiskLevel, RiskFactor, WalletAnalysis, RateLimiter
    
    # Test enums
    assert RiskLevel.CRITICAL == "critical"
    assert RiskLevel.HIGH == "high"
    
    # Test RiskFactor
    factor = RiskFactor(
        source="test",
        factor_type="scam",
        severity=RiskLevel.HIGH,
        weight=0.8,
        description="Test factor"
    )
    assert factor.source == "test"
    assert factor.severity == RiskLevel.HIGH
    
    # Test WalletAnalysis (basic validation)
    analysis = WalletAnalysis(
        address="0x1234567890123456789012345678901234567890",
        risk_score=0.7,
        risk_level=RiskLevel.HIGH,
        confidence=0.8
    )
    assert analysis.address == "0x1234567890123456789012345678901234567890"
    assert analysis.risk_score == 0.7
    
    # Test RateLimiter basic functionality
    limiter = RateLimiter(calls_per_minute=60, burst_limit=10)
    assert limiter.calls_per_minute == 60
    
    print("✓ Data collector structures working")

def test_directory_structure():
    """Test directory structure"""
    print("Testing directory structure...")
    
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
    
    for dir_path in expected_dirs:
        full_path = os.path.join(os.path.dirname(__file__), dir_path)
        assert os.path.exists(full_path), f"Missing directory: {dir_path}"
    
    print("✓ Directory structure complete")

def test_files_exist():
    """Test required files exist"""
    print("Testing required files...")
    
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
        full_path = os.path.join(os.path.dirname(__file__), file_path)
        assert os.path.exists(full_path), f"Missing file: {file_path}"
        assert os.path.getsize(full_path) > 0, f"Empty file: {file_path}"
    
    print("✓ All required files present")

def main():
    """Run all tests"""
    print("🧪 Testing AI Training Infrastructure")
    print("=" * 40)
    
    try:
        test_directory_structure()
        test_files_exist()
        test_config_system()
        test_data_collector_structure()
        
        print("=" * 40)
        print("✅ All infrastructure tests passed!")
        print("\n🚀 Ready to implement data collectors")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()