#!/usr/bin/env python3
"""
Test Enhanced Intelligence Integration - Shodan and DeHashed
Demonstrates the enhanced multi-source intelligence gathering capabilities
with your Shodan and DeHashed API keys.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.collectors.historical_crime_aggregator import HistoricalCrimeAggregator
from src.collectors.shodan_client import ShodanClient
from src.collectors.dehashed_client import DeHashedClient
from src.utils.config import ConfigManager
from src.utils.logging import setup_logging

def test_enhanced_intelligence():
    """Test enhanced intelligence gathering with Shodan and DeHashed"""
    
    print("🔍 Enhanced Intelligence Integration Test")
    print("=" * 60)
    
    # Setup logging
    logger = setup_logging(log_level="DEBUG")
    
    # Load configuration
    config_manager = ConfigManager()
    config = config_manager.load_config()
    
    # Initialize aggregator
    aggregator = HistoricalCrimeAggregator(
        config=config,
        cache_dir="./cache",
        logger=logger
    )
    
    print(f"📊 Available intelligence sources: {list(aggregator.available_sources)}")
    
    # Test DeHashed email intelligence (if configured)
    if 'dehashed' in aggregator.available_sources:
        print("\n🔍 Testing DeHashed Email Intelligence")
        print("-" * 40)
        
        test_emails = [
            "test@example.com",  # Test email
            "admin@suspicious-domain.com"  # Suspicious pattern
        ]
        
        for email in test_emails:
            print(f"\n📧 Analyzing email: {email}")
            
            try:
                result = aggregator.collect_email_intelligence(email)
                
                if result:
                    print(f"✅ Analysis complete - Sources: {result['sources_checked']}")
                    
                    # DeHashed specific results
                    if result.get('dehashed_result'):
                        dehashed = result['dehashed_result']
                        if dehashed.get('found_dehashed_data'):
                            print(f"🚨 DeHashed: {dehashed.get('total_records', 0)} records found")
                            print(f"   Database sources: {len(dehashed.get('database_sources', []))}")
                            print(f"   Risk level: {dehashed.get('risk_assessment', {}).get('risk_level', 'unknown')}")
                        else:
                            print("✅ DeHashed: No breach records found")
                    
                    # Combined assessment
                    assessment = result['aggregated_assessment']
                    print(f"📊 Overall Assessment:")
                    print(f"   Breach exposure: {'Yes' if result['breach_exposure_found'] else 'No'}")
                    print(f"   Risk score: {assessment['risk_score']:.2f}")
                    print(f"   Confidence: {assessment['confidence']:.2f}")
                    
                else:
                    print("❌ No intelligence gathered")
                    
            except Exception as e:
                print(f"❌ Error analyzing {email}: {e}")
    
    # Test Shodan infrastructure intelligence (if configured)
    if 'shodan' in aggregator.available_sources:
        print("\n🌐 Testing Shodan Infrastructure Intelligence")
        print("-" * 50)
        
        test_targets = [
            "8.8.8.8",  # Google DNS - should be clean
            "1.1.1.1",  # Cloudflare DNS - should be clean
            "example.com"  # Test domain
        ]
        
        for target in test_targets:
            print(f"\n🔍 Analyzing infrastructure: {target}")
            
            try:
                result = aggregator.collect_address_intelligence(target)
                
                if result:
                    print(f"✅ Analysis complete - Sources: {result['sources_checked']}")
                    
                    # Shodan specific results
                    if result.get('shodan_result'):
                        shodan = result['shodan_result']
                        if shodan.get('found_shodan_data'):
                            infra = shodan.get('infrastructure_intelligence', {})
                            print(f"🌐 Shodan Infrastructure:")
                            print(f"   Services detected: {infra.get('total_services', 0)}")
                            print(f"   Open ports: {len(infra.get('open_ports', []))}")
                            print(f"   Vulnerabilities: {infra.get('vulnerability_count', 0)}")
                            print(f"   Crypto services: {infra.get('crypto_related_services', 0)}")
                            
                            suspicious = infra.get('suspicious_indicators', [])
                            if suspicious:
                                print(f"   ⚠️  Suspicious indicators: {', '.join(suspicious)}")
                            
                            risk = shodan.get('risk_assessment', {})
                            print(f"   Risk level: {risk.get('risk_level', 'unknown')}")
                            print(f"   Threat score: {infra.get('threat_score', 0):.2f}")
                        else:
                            print("ℹ️  Shodan: No infrastructure data found")
                    
                    # Combined assessment
                    assessment = result['aggregated_assessment']
                    print(f"📊 Overall Assessment:")
                    print(f"   Criminal activity: {'Yes' if result['criminal_activity_found'] else 'No'}")
                    print(f"   Risk score: {assessment['risk_score']:.2f}")
                    
                else:
                    print("❌ No intelligence gathered")
                    
            except Exception as e:
                print(f"❌ Error analyzing {target}: {e}")
    
    # Test direct client capabilities
    print("\n🧪 Testing Direct Client Capabilities")
    print("-" * 40)
    
    # DeHashed direct test
    if config.get('dehashed_api_key'):
        print("\n📊 DeHashed Client Statistics:")
        dehashed_client = DeHashedClient(config)
        stats = dehashed_client.get_statistics()
        for key, value in stats.items():
            print(f"   {key}: {value}")
    
    # Shodan direct test
    if config.get('shodan_api_key'):
        print("\n🌐 Shodan Client Statistics:")
        shodan_client = ShodanClient(config)
        stats = shodan_client.get_statistics()
        for key, value in stats.items():
            print(f"   {key}: {value}")
    
    print("\n✅ Enhanced Intelligence Test Complete!")
    print("\nNext steps:")
    print("1. Configure your API keys in .env file")
    print("2. Run ML training with enhanced data sources")
    print("3. Deploy the API server with full intelligence coverage")

if __name__ == "__main__":
    test_enhanced_intelligence()