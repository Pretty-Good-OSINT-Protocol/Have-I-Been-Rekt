#!/usr/bin/env python3
"""
Simple CLI tool to test sanctions integration with real addresses.

Usage:
    python test_sanctions.py 0x1234567890123456789012345678901234567890
    python test_sanctions.py --batch addresses.txt
    python test_sanctions.py --update-ofac
"""

import sys
import os
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import get_config
from src.utils.logging import setup_logging, get_logger
from src.collectors import SanctionsAggregator


def test_single_address(aggregator, address):
    """Test a single address"""
    logger = get_logger(__name__)
    
    print(f"\n🔍 Analyzing address: {address}")
    print("=" * 60)
    
    try:
        result = aggregator.collect_address_data(address)
        
        if not result:
            print("❌ No result returned")
            return
        
        # Basic info
        sources_checked = result.get('sources_checked', [])
        sanctions_found = result.get('sanctions_found', False)
        
        print(f"📊 Sources checked: {', '.join(sources_checked)}")
        print(f"⚠️  Sanctions found: {'YES' if sanctions_found else 'NO'}")
        
        # OFAC results
        ofac_result = result.get('ofac_result')
        if ofac_result:
            if ofac_result.get('sanctioned'):
                entity = ofac_result.get('entity', {})
                print(f"🚨 OFAC: SANCTIONED")
                print(f"   Entity: {entity.get('name', 'Unknown')}")
                print(f"   Program: {entity.get('primary_program', 'Unknown')}")
                print(f"   Type: {entity.get('type', 'Unknown')}")
            else:
                print(f"✅ OFAC: Clean")
        else:
            print(f"❓ OFAC: No data")
        
        # Chainalysis results
        chainalysis_result = result.get('chainalysis_result')
        if chainalysis_result:
            category = chainalysis_result.get('category', 'unknown')
            risk_score = chainalysis_result.get('risk_score', 0)
            cluster_name = chainalysis_result.get('cluster_name')
            
            if chainalysis_result.get('is_sanctioned'):
                print(f"🚨 Chainalysis: SANCTIONED ({category})")
            elif risk_score > 0.5:
                print(f"⚠️  Chainalysis: HIGH RISK ({category}, score: {risk_score:.2f})")
            elif risk_score > 0.1:
                print(f"🟡 Chainalysis: Medium risk ({category}, score: {risk_score:.2f})")
            else:
                print(f"✅ Chainalysis: Clean ({category})")
            
            if cluster_name:
                print(f"   Cluster: {cluster_name}")
        else:
            print(f"❓ Chainalysis: No data (API key needed)")
        
        # Aggregated risk
        aggregated = result.get('aggregated_risk', {})
        risk_score = aggregated.get('risk_score', 0)
        confidence = aggregated.get('confidence', 0)
        primary_concern = aggregated.get('primary_concern')
        
        print(f"\n📈 Overall Assessment:")
        print(f"   Risk Score: {risk_score:.3f}")
        print(f"   Confidence: {confidence:.3f}")
        if primary_concern:
            print(f"   Primary Concern: {primary_concern}")
        
        # Risk analysis
        if risk_score >= 0.8:
            print(f"🔴 CRITICAL RISK")
        elif risk_score >= 0.6:
            print(f"🟠 HIGH RISK")
        elif risk_score >= 0.4:
            print(f"🟡 MEDIUM RISK")
        elif risk_score >= 0.2:
            print(f"🟢 LOW RISK")
        else:
            print(f"⚪ CLEAN")
            
    except Exception as e:
        logger.error(f"Error analyzing address {address}: {e}")
        print(f"❌ Error: {e}")


def test_batch_addresses(aggregator, filepath):
    """Test multiple addresses from file"""
    logger = get_logger(__name__)
    
    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        return
    
    addresses = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                addresses.append(line)
    
    if not addresses:
        print(f"❌ No addresses found in {filepath}")
        return
    
    print(f"\n📋 Testing {len(addresses)} addresses from {filepath}")
    print("=" * 60)
    
    results = aggregator.batch_screen_addresses(addresses)
    
    # Summary
    sanctions_count = 0
    high_risk_count = 0
    errors_count = 0
    
    for address, result in results.items():
        if result is None:
            errors_count += 1
            print(f"❌ {address[:10]}... - Error")
            continue
        
        aggregated = result.get('aggregated_risk', {})
        risk_score = aggregated.get('risk_score', 0)
        is_sanctioned = aggregated.get('is_sanctioned', False)
        primary_concern = aggregated.get('primary_concern', '')
        
        if is_sanctioned:
            sanctions_count += 1
            print(f"🚨 {address[:10]}... - SANCTIONED ({primary_concern})")
        elif risk_score > 0.6:
            high_risk_count += 1
            print(f"⚠️  {address[:10]}... - HIGH RISK ({primary_concern})")
        else:
            print(f"✅ {address[:10]}... - Clean (score: {risk_score:.2f})")
    
    print(f"\n📊 Summary:")
    print(f"   Total addresses: {len(addresses)}")
    print(f"   Sanctioned: {sanctions_count}")
    print(f"   High risk: {high_risk_count}")
    print(f"   Errors: {errors_count}")


def update_ofac_data(aggregator):
    """Update OFAC data"""
    logger = get_logger(__name__)
    
    print("\n📥 Updating OFAC sanctions data...")
    print("=" * 60)
    
    try:
        success = aggregator.ofac_collector.update_data()
        
        if success:
            stats = aggregator.ofac_collector.get_statistics()
            print(f"✅ OFAC update successful!")
            print(f"   Total entities: {stats.get('total_entities', 0):,}")
            print(f"   Crypto addresses: {stats.get('crypto_addresses', 0):,}")
            print(f"   Last update: {stats.get('last_update', 'Unknown')}")
            
            # Show top programs
            top_programs = stats.get('top_programs', [])[:5]
            if top_programs:
                print(f"\n📋 Top 5 sanctions programs:")
                for program, count in top_programs:
                    print(f"   {program}: {count} entities")
        else:
            print(f"❌ OFAC update failed")
            
    except Exception as e:
        logger.error(f"Error updating OFAC data: {e}")
        print(f"❌ Error: {e}")


def show_coverage_stats(aggregator):
    """Show data source coverage statistics"""
    logger = get_logger(__name__)
    
    print("\n📊 Data Source Coverage")
    print("=" * 60)
    
    try:
        stats = aggregator.get_coverage_stats()
        
        available_sources = stats.get('available_sources', [])
        coverage_pct = stats.get('coverage_percentage', 0)
        
        print(f"Available sources: {', '.join(available_sources)}")
        print(f"Coverage: {coverage_pct:.0f}%")
        
        # Source details
        source_details = stats.get('source_details', {})
        
        for source, details in source_details.items():
            print(f"\n{source.upper()}:")
            
            if 'error' in details:
                print(f"   ❌ Error: {details['error']}")
            else:
                if source == 'ofac':
                    print(f"   Entities: {details.get('total_entities', 0):,}")
                    print(f"   Crypto addresses: {details.get('crypto_addresses', 0):,}")
                    print(f"   Last update: {details.get('last_update', 'Unknown')}")
                elif source == 'chainalysis':
                    print(f"   Cached screenings: {details.get('cached_screenings', 0)}")
                    print(f"   API key configured: {details.get('api_key_configured', False)}")
                    print(f"   API key valid: {details.get('api_key_valid', False)}")
    
    except Exception as e:
        logger.error(f"Error getting coverage stats: {e}")
        print(f"❌ Error: {e}")


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description='Test sanctions integration')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('address', nargs='?', help='Single address to test')
    group.add_argument('--batch', metavar='FILE', help='File containing addresses to test')
    group.add_argument('--update-ofac', action='store_true', help='Update OFAC data')
    group.add_argument('--stats', action='store_true', help='Show coverage statistics')
    
    parser.add_argument('--config', help='Config file path')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        if args.config:
            from src.utils.config import get_config_manager
            config = get_config_manager(args.config).load_config()
        else:
            config = get_config()
        
        # Set up logging
        if args.verbose:
            config.logging.level = "DEBUG"
        else:
            config.logging.level = "WARNING"  # Quiet for CLI use
        
        setup_logging(config.logging.dict())
        
        # Initialize aggregator
        print("🚀 Initializing sanctions aggregator...")
        aggregator = SanctionsAggregator(
            config.dict(),
            cache_dir=config.cache.directory
        )
        
        print(f"✅ Available sources: {', '.join(aggregator.available_sources)}")
        
        # Execute requested action
        if args.address:
            test_single_address(aggregator, args.address)
        elif args.batch:
            test_batch_addresses(aggregator, args.batch)
        elif args.update_ofac:
            update_ofac_data(aggregator)
        elif args.stats:
            show_coverage_stats(aggregator)
        
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()