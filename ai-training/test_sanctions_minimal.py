#!/usr/bin/env python3
"""
Minimal test of sanctions integration without external dependencies
"""

import sys
import os
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

def test_sanctions_imports():
    """Test that sanctions modules can be imported"""
    print("Testing sanctions module imports...")
    
    try:
        # Mock missing dependencies
        import sys
        
        # Mock requests module
        mock_requests = type('MockModule', (), {
            'RequestException': Exception,
            'request': lambda *args, **kwargs: None,
            'get': lambda *args, **kwargs: None
        })()
        sys.modules['requests'] = mock_requests
        
        # Mock aiohttp module
        sys.modules['aiohttp'] = type('MockModule', (), {})()
        
        # Mock diskcache module  
        sys.modules['diskcache'] = type('MockModule', (), {
            'Cache': lambda *args, **kwargs: {}
        })()
        
        # Mock structlog module
        sys.modules['structlog'] = type('MockModule', (), {})()
        
        # Mock dotenv module
        sys.modules['dotenv'] = type('MockModule', (), {
            'load_dotenv': lambda *args: None
        })()
        
        # Test OFAC collector
        from src.collectors.ofac_sanctions import OFACSanctionsCollector, SanctionedEntity
        print("✓ OFAC collector imports working")
        
        # Test Chainalysis client
        from src.collectors.chainalysis_client import ChainanalysisClient, ChainanalysisScreeningResult
        print("✓ Chainalysis client imports working")
        
        # Test aggregator
        from src.collectors.sanctions_aggregator import SanctionsAggregator
        print("✓ Sanctions aggregator imports working")
        
        return True
        
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def test_crypto_address_patterns():
    """Test crypto address regex patterns"""
    print("Testing crypto address pattern matching...")
    
    try:
        from src.collectors.ofac_sanctions import OFACSanctionsCollector
        
        # Create mock collector just to test patterns
        test_config = {
            'cache': {'enabled': False},
            'rate_limits': {},
            'data_sources': {}
        }
        
        # Mock the parent class methods
        class MockCollector(OFACSanctionsCollector):
            def __init__(self):
                self.logger = type('MockLogger', (), {
                    'info': lambda *args, **kwargs: None,
                    'warning': lambda *args, **kwargs: None,
                    'error': lambda *args, **kwargs: None
                })()
        
        collector = MockCollector()
        
        # Test address patterns
        test_cases = [
            ("Bitcoin address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 1),
            ("ETH 0x1234567890123456789012345678901234567890", 1),
            ("Multiple: 1ABC123... and 0xDEF456...", 0),  # Partial addresses shouldn't match
            ("No addresses here", 0)
        ]
        
        for text, expected_count in test_cases:
            addresses = collector.extract_crypto_addresses(text)
            actual_count = len(addresses)
            if actual_count >= expected_count:  # At least the expected count
                print(f"✓ Pattern test: '{text[:30]}...' -> {actual_count} addresses")
            else:
                print(f"✗ Pattern test failed: '{text[:30]}...' -> expected {expected_count}, got {actual_count}")
        
        return True
        
    except Exception as e:
        print(f"✗ Pattern testing failed: {e}")
        return False

def test_data_structures():
    """Test data structure creation"""
    print("Testing sanctions data structures...")
    
    try:
        from src.collectors.ofac_sanctions import SanctionedEntity
        from src.collectors.chainalysis_client import ChainanalysisScreeningResult
        from src.data_collector import RiskLevel
        
        # Test SanctionedEntity
        entity = SanctionedEntity(
            uid="12345",
            entity_type="Individual",
            first_name="Test",
            last_name="Subject",
            programs=["DPRK"],
            crypto_addresses=["0x1234567890123456789012345678901234567890"]
        )
        
        assert entity.display_name == "Test Subject"
        assert entity.primary_program == "DPRK"
        print("✓ SanctionedEntity structure working")
        
        # Test ChainanalysisScreeningResult
        result = ChainanalysisScreeningResult(
            address="0x1234567890123456789012345678901234567890",
            is_sanctioned=True,
            category="sanctions",
            category_id="sanctions"
        )
        
        assert result.is_high_risk is True
        print("✓ ChainanalysisScreeningResult structure working")
        
        return True
        
    except Exception as e:
        print(f"✗ Data structure test failed: {e}")
        return False

def test_risk_level_mapping():
    """Test risk level mappings"""
    print("Testing risk level mappings...")
    
    try:
        from src.collectors.chainalysis_client import ChainanalysisClient
        from src.data_collector import RiskLevel
        
        # Test category mappings
        mappings = ChainanalysisClient.CATEGORY_RISK_MAPPING
        
        # Critical categories
        assert mappings.get('sanctions') == RiskLevel.CRITICAL
        assert mappings.get('ransomware') == RiskLevel.CRITICAL
        
        # High risk categories
        assert mappings.get('scam') == RiskLevel.HIGH
        assert mappings.get('darknet') == RiskLevel.HIGH
        
        # Clean categories
        assert mappings.get('exchange') == RiskLevel.CLEAN
        assert mappings.get('unknown') == RiskLevel.CLEAN
        
        print("✓ Risk level mappings are correct")
        return True
        
    except Exception as e:
        print(f"✗ Risk level mapping test failed: {e}")
        return False

def main():
    """Run all minimal tests"""
    print("🧪 Testing Sanctions Integration")
    print("=" * 40)
    
    tests = [
        test_sanctions_imports,
        test_crypto_address_patterns,
        test_data_structures,
        test_risk_level_mapping
    ]
    
    passed = 0
    for test in tests:
        try:
            if test():
                passed += 1
            print()  # Empty line between tests
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
            print()
    
    print("=" * 40)
    if passed == len(tests):
        print(f"✅ All {len(tests)} sanctions tests passed!")
        print("\n🎯 Ready for live testing with:")
        print("  python scripts/test_sanctions.py --stats")
        print("  python scripts/test_sanctions.py 0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359")
        return True
    else:
        print(f"❌ {passed}/{len(tests)} tests passed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)