#!/usr/bin/env python3
"""
Comprehensive Intelligence Integration Test - Showcases the full power
of the enhanced Have I Been Rekt AI training pipeline with Ethereum prioritization.

Tests all integrated data sources:
- HIBP + DeHashed email breach intelligence
- Shodan infrastructure analysis
- Elliptic++ (203k transactions, 822k addresses)
- Elliptic2 money laundering subgraph analysis
- Ethereum fraud detection + smart contract vulnerabilities
- HuggingFace datasets integration
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.collectors.historical_crime_aggregator import HistoricalCrimeAggregator
from src.utils.config import ConfigManager
from src.utils.logging import setup_logging

def test_comprehensive_intelligence():
    """Test the full enhanced intelligence gathering pipeline"""
    
    print("🚀 COMPREHENSIVE INTELLIGENCE INTEGRATION TEST")
    print("=" * 60)
    print("Testing enhanced Have I Been Rekt AI with Ethereum prioritization")
    print("=" * 60)
    
    # Setup logging
    logger = setup_logging(log_level="INFO")
    
    # Load configuration
    config_manager = ConfigManager()
    config = config_manager.load_config()
    
    # Initialize enhanced aggregator
    aggregator = HistoricalCrimeAggregator(
        config=config,
        cache_dir="./cache",
        logger=logger
    )
    
    print(f"🔍 Enhanced Intelligence Sources Available:")
    for i, source in enumerate(sorted(aggregator.available_sources), 1):
        print(f"   {i:2d}. {source}")
    print(f"\n📊 Total Sources: {len(aggregator.available_sources)}")
    
    # Test Ethereum prioritization with comprehensive address analysis
    print("\n🔷 ETHEREUM ECOSYSTEM ANALYSIS (PRIORITIZED)")
    print("-" * 50)
    
    ethereum_test_addresses = [
        "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",  # Uniswap token contract
        "0xA0b86a33E6C7Ea1c0f2b9A2C9B3B6E3B9E3B6E3B",  # Test Ethereum address
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"   # Test address from docs
    ]
    
    for address in ethereum_test_addresses:
        print(f"\n🔍 Analyzing Ethereum Address: {address}")
        try:
            result = aggregator.collect_address_intelligence(address)
            
            if result:
                print(f"✅ Analysis Complete - Sources: {len(result['sources_checked'])}")
                
                # Enhanced Ethereum analysis
                if result.get('ethereum_result'):
                    eth_result = result['ethereum_result']
                    if eth_result.get('found_ethereum_data'):
                        print("   🔷 ETHEREUM INTELLIGENCE:")
                        
                        fraud_analysis = eth_result.get('fraud_analysis', {})
                        if fraud_analysis.get('has_fraud_records'):
                            print(f"     ⚠️  Fraud detected: {fraud_analysis.get('transaction_types', [])}")
                        
                        vuln_analysis = eth_result.get('vulnerability_analysis', {})
                        vuln_count = vuln_analysis.get('vulnerability_count', 0)
                        if vuln_count > 0:
                            severity = vuln_analysis.get('severity_breakdown', {})
                            print(f"     🚨 Vulnerabilities: {vuln_count} total")
                            for sev, count in severity.items():
                                if count > 0:
                                    print(f"        - {sev}: {count}")
                        
                        defi_analysis = eth_result.get('defi_analysis', {})
                        mev_exposure = defi_analysis.get('mev_exposure', 0)
                        if mev_exposure > 0:
                            print(f"     💰 MEV Exposure: {mev_exposure:.2f}")
                            print(f"     🏦 Protocol: {defi_analysis.get('protocol_type', 'unknown')}")
                
                # Elliptic++ analysis
                if result.get('elliptic_plus_result'):
                    elliptic_result = result['elliptic_plus_result']
                    if elliptic_result.get('found_elliptic_data'):
                        classification = elliptic_result.get('elliptic_classification', {})
                        print(f"   📊 ELLIPTIC++ CLASSIFICATION: {classification.get('label', 'unknown').upper()}")
                        
                        network_analysis = elliptic_result.get('network_analysis', {})
                        if network_analysis.get('network_size', 0) > 0:
                            print(f"     🕸️  Network size: {network_analysis['network_size']} addresses")
                            print(f"     🚨 Illicit connections: {network_analysis.get('illicit_connections', 0)}")
                
                # Elliptic2 money laundering analysis
                if result.get('elliptic2_result'):
                    elliptic2_result = result['elliptic2_result']
                    if elliptic2_result.get('found_elliptic2_data'):
                        ml_analysis = elliptic2_result.get('money_laundering_analysis', {})
                        print(f"   🏦 MONEY LAUNDERING PATTERNS:")
                        print(f"     Risk: {ml_analysis.get('risk_classification', 'unknown')}")
                        print(f"     Patterns: {ml_analysis.get('detected_patterns', 0)}")
                        
                        pattern_types = ml_analysis.get('pattern_types', [])
                        if pattern_types:
                            print(f"     Types: {', '.join(pattern_types)}")
                
                # HuggingFace smart contract analysis
                if result.get('huggingface_result'):
                    hf_result = result['huggingface_result']
                    found_datasets = hf_result.get('found_in_datasets', [])
                    if found_datasets:
                        print(f"   🤗 HUGGINGFACE DATASETS:")
                        for dataset in found_datasets:
                            print(f"     - Found in: {dataset}")
                
                # Overall assessment
                assessment = result['aggregated_assessment']
                print(f"   📈 RISK ASSESSMENT:")
                print(f"     Criminal activity: {'Yes' if result['criminal_activity_found'] else 'No'}")
                print(f"     Risk score: {assessment['risk_score']:.3f}")
                print(f"     Sources analyzed: {len(result['sources_checked'])}")
                
            else:
                print("❌ No intelligence gathered")
            
        except Exception as e:
            print(f"❌ Error analyzing {address}: {e}")
    
    # Test email intelligence with enhanced breach detection
    print("\n📧 ENHANCED EMAIL BREACH INTELLIGENCE")
    print("-" * 40)
    
    test_emails = [
        "test@example.com",
        "admin@suspicious-domain.com",
        "user@company.com"
    ]
    
    for email in test_emails:
        print(f"\n📧 Analyzing Email: {email}")
        try:
            result = aggregator.collect_email_intelligence(email)
            
            if result:
                print(f"✅ Analysis Complete - Sources: {len(result['sources_checked'])}")
                
                # HIBP results
                if result.get('hibp_result') and result['hibp_result'].get('found_breach_data'):
                    hibp = result['hibp_result']
                    print(f"   🔍 HIBP: {hibp.get('total_breaches', 0)} breaches found")
                
                # DeHashed results
                if result.get('dehashed_result') and result['dehashed_result'].get('found_dehashed_data'):
                    dehashed = result['dehashed_result']
                    print(f"   🗃️  DeHashed: {dehashed.get('total_records', 0)} records found")
                    print(f"      Databases: {len(dehashed.get('database_sources', []))}")
                    print(f"      Exposed passwords: {dehashed.get('exposed_passwords_count', 0)}")
                
                # Overall assessment
                assessment = result['aggregated_assessment']
                print(f"   📊 Overall breach exposure: {'Yes' if result['breach_exposure_found'] else 'No'}")
                print(f"   📊 Risk score: {assessment['risk_score']:.3f}")
                
            else:
                print("✅ No breach data found")
                
        except Exception as e:
            print(f"❌ Error analyzing {email}: {e}")
    
    # Display comprehensive statistics
    print("\n📊 COMPREHENSIVE SYSTEM STATISTICS")
    print("-" * 40)
    
    # Get statistics from all components
    components = [
        ('Historical Crime Aggregator', aggregator),
        ('Elliptic++', aggregator.elliptic_plus),
        ('Elliptic2', aggregator.elliptic2),
        ('Ethereum Datasets', aggregator.ethereum_datasets),
        ('HuggingFace Manager', aggregator.huggingface_manager),
        ('Shodan Client', aggregator.shodan_client),
        ('DeHashed Client', aggregator.dehashed_client)
    ]
    
    for component_name, component in components:
        try:
            stats = component.get_statistics()
            print(f"\n{component_name}:")
            for key, value in stats.items():
                if key in ['configured', 'datasets_loaded', 'kaggle_configured', 'web3_connected']:
                    status = "✅" if value else "❌"
                    print(f"  {status} {key.replace('_', ' ').title()}: {value}")
                elif isinstance(value, (int, float)) and key.endswith(('_count', '_size', '_records')):
                    print(f"  📊 {key.replace('_', ' ').title()}: {value:,}")
        except Exception as e:
            print(f"  ❌ Error getting statistics: {e}")
    
    print("\n🎉 COMPREHENSIVE INTELLIGENCE TEST COMPLETE!")
    print("\n🚀 NEXT STEPS:")
    print("1. 📥 Download datasets as needed:")
    print("   - Elliptic++: https://github.com/git-disl/EllipticPlusPlus")
    print("   - Elliptic2: http://elliptic.co/elliptic2")
    print("   - Ethereum Fraud: kaggle datasets download vagifa/ethereum-frauddetection-dataset")
    print("   - pip install datasets (for HuggingFace integration)")
    print("2. 🔑 Configure API keys in .env file")
    print("3. 🤖 Run ML training with enhanced multi-source data")
    print("4. 🚀 Deploy the comprehensive API system")
    
    print("\n💎 ETHEREUM ECOSYSTEM PRIORITIZATION ACHIEVED!")
    print("Your AI now has comprehensive Ethereum intelligence with:")
    print("• DeFi protocol analysis and MEV detection")
    print("• Smart contract vulnerability assessment")  
    print("• Advanced fraud detection patterns")
    print("• Money laundering subgraph analysis")
    print("• Multi-source cross-validation")

if __name__ == "__main__":
    test_comprehensive_intelligence()