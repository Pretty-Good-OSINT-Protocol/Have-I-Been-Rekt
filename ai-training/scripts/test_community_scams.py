#!/usr/bin/env python3
"""
Test script for community scam database integration.

Usage:
    python test_community_scams.py 0x1234... --test-all
    python test_community_scams.py --update-cryptoscamdb 
    python test_community_scams.py --stats
    python test_community_scams.py --cross-reference email@example.com
"""

import sys
import os
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import get_config
from src.utils.logging import setup_logging, get_logger
from src.collectors.community_scam_aggregator import CommunityScamAggregator
from src.collectors.cryptoscamdb_collector import CryptoScamDBCollector
from src.collectors.chainabuse_scraper import ChainabuseScraper
from src.collectors.scamsearch_client import ScamSearchClient
from src.collectors.whale_alert_client import WhaleAlertClient


def test_single_address(aggregator, address):
    """Test community scam lookup for a single address"""
    logger = get_logger(__name__)
    
    print(f"\n🔍 Analyzing address against community scam databases: {address}")
    print("=" * 70)
    
    try:
        result = aggregator.collect_address_data(address)
        
        if not result:
            print("❌ No result returned")
            return
        
        # Basic info
        sources_checked = result.get('sources_checked', [])
        scam_reports_found = result.get('scam_reports_found', False)
        
        print(f"📊 Community sources checked: {', '.join(sources_checked)}")
        print(f"⚠️  Scam reports found: {'YES' if scam_reports_found else 'NO'}")
        
        # CryptoScamDB results
        cryptoscamdb_result = result.get('cryptoscamdb_result')
        if cryptoscamdb_result:
            if cryptoscamdb_result.get('found_in_database'):
                report_count = cryptoscamdb_result.get('report_count', 0)
                print(f"🗃️  CryptoScamDB: {report_count} reports found")
                
                # Show sample reports
                reports = cryptoscamdb_result.get('reports', [])[:2]  # Show first 2
                for report in reports:
                    category = report.get('category', 'Unknown')
                    description = report.get('description', '')[:60]
                    print(f"   📝 {category}: {description}...")
            else:
                print(f"✅ CryptoScamDB: Clean")
        else:
            print(f"❓ CryptoScamDB: No data")
        
        # Chainabuse results
        chainabuse_result = result.get('chainabuse_result')
        if chainabuse_result:
            if chainabuse_result.get('found_in_chainabuse'):
                report_count = chainabuse_result.get('report_count', 0)
                abuse_types = chainabuse_result.get('abuse_types', [])
                print(f"🚨 Chainabuse: {report_count} abuse reports found")
                if abuse_types:
                    print(f"   Types: {', '.join(abuse_types[:3])}")
            else:
                print(f"✅ Chainabuse: Clean")
        else:
            print(f"❓ Chainabuse: No data (ethical scraping)")
        
        # ScamSearch results  
        scamsearch_result = result.get('scamsearch_result')
        if scamsearch_result:
            if scamsearch_result.get('found_in_scamsearch'):
                entry_count = scamsearch_result.get('entry_count', 0)
                total_reports = scamsearch_result.get('total_reports', 0)
                scam_types = scamsearch_result.get('scam_types', [])
                print(f"🔍 ScamSearch: {entry_count} entries, {total_reports} total reports")
                if scam_types:
                    print(f"   Types: {', '.join(scam_types[:3])}")
            else:
                print(f"✅ ScamSearch: Clean")
        else:
            print(f"❓ ScamSearch: No data (API key needed)")
        
        # Whale Alert results  
        whale_alert_result = result.get('whale_alert_result')
        if whale_alert_result:
            if whale_alert_result.get('found_in_whale_alert'):
                whale_tx_count = whale_alert_result.get('whale_transaction_count', 0)
                suspicious_detected = whale_alert_result.get('suspicious_activity_detected', False)
                total_volume = whale_alert_result.get('total_whale_volume_usd', 0)
                
                print(f"🐋 Whale Alert: {whale_tx_count} whale transactions (${total_volume:,.0f})")
                
                if suspicious_detected:
                    suspicious_activity = whale_alert_result.get('suspicious_activity', {})
                    risk_level = suspicious_activity.get('risk_level', 'unknown')
                    activity_type = suspicious_activity.get('activity_type', 'unknown')
                    print(f"   ⚠️  Suspicious activity: {activity_type} ({risk_level} risk)")
            else:
                print(f"✅ Whale Alert: No whale activity detected")
        else:
            print(f"❓ Whale Alert: No data (API key needed)")
        
        # Aggregated assessment
        assessment = result.get('aggregated_assessment', {})
        risk_score = assessment.get('risk_score', 0)
        confidence = assessment.get('confidence', 0)
        total_reports = assessment.get('total_reports', 0)
        primary_scam_types = assessment.get('primary_scam_types', [])
        
        print(f"\n📈 Community Assessment:")
        print(f"   Total Reports: {total_reports}")
        print(f"   Risk Score: {risk_score:.3f}")
        print(f"   Confidence: {confidence:.3f}")
        if primary_scam_types:
            print(f"   Primary Types: {', '.join(primary_scam_types[:3])}")
        
        # Risk level
        if risk_score >= 0.8:
            print(f"🔴 HIGH RISK - Multiple community reports")
        elif risk_score >= 0.6:
            print(f"🟠 MODERATE RISK - Community reports found")
        elif risk_score >= 0.3:
            print(f"🟡 LOW RISK - Limited reports")
        elif total_reports > 0:
            print(f"🟡 CAUTION - Some community reports")
        else:
            print(f"✅ CLEAN - No community scam reports")
            
    except Exception as e:
        logger.error(f"Error analyzing address {address}: {e}")
        print(f"❌ Error: {e}")


def update_cryptoscamdb(collector):
    """Update CryptoScamDB data"""
    logger = get_logger(__name__)
    
    print("\n📥 Updating CryptoScamDB data from GitHub...")
    print("=" * 50)
    
    try:
        success = collector.update_data()
        
        if success:
            stats = collector.get_statistics()
            print(f"✅ CryptoScamDB update successful!")
            print(f"   Unique addresses: {stats.get('unique_addresses', 0):,}")
            print(f"   Total reports: {stats.get('total_reports', 0):,}")
            print(f"   Scam domains: {stats.get('scam_domains', 0):,}")
            print(f"   Last update: {stats.get('last_update', 'Unknown')}")
            
            # Show top categories
            top_categories = stats.get('top_categories', [])[:5]
            if top_categories:
                print(f"\n📊 Top 5 scam categories:")
                for category, count in top_categories:
                    print(f"   {category}: {count} reports")
        else:
            print(f"❌ CryptoScamDB update failed")
            
    except Exception as e:
        logger.error(f"Error updating CryptoScamDB data: {e}")
        print(f"❌ Error: {e}")


def show_coverage_stats(aggregator):
    """Show community database coverage statistics"""
    logger = get_logger(__name__)
    
    print("\n📊 Community Scam Database Coverage")
    print("=" * 50)
    
    try:
        stats = aggregator.get_coverage_statistics()
        
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
                if source == 'cryptoscamdb':
                    print(f"   Unique addresses: {details.get('unique_addresses', 0):,}")
                    print(f"   Total reports: {details.get('total_reports', 0):,}")
                    print(f"   Scam domains: {details.get('scam_domains', 0):,}")
                    print(f"   Last update: {details.get('last_update', 'Unknown')}")
                elif source == 'chainabuse':
                    print(f"   Ethical scraping: {details.get('ethical_scraping_enabled', True)}")
                    print(f"   Base delay: {details.get('base_delay_seconds', 0)} seconds")
                    print(f"   Unique addresses: {details.get('unique_addresses', 0)}")
                    print(f"   Total reports: {details.get('total_reports', 0)}")
                elif source == 'scamsearch':
                    print(f"   API key configured: {details.get('api_key_configured', False)}")
                    print(f"   Subscription tier: {details.get('subscription_tier', 'free')}")
                    print(f"   Requests today: {details.get('requests_today', 0)}")
                    print(f"   Daily remaining: {details.get('daily_remaining', 0)}")
                elif source == 'whale_alert':
                    print(f"   API key configured: {details.get('api_key_configured', False)}")
                    print(f"   Subscription tier: {details.get('subscription_tier', 'free')}")
                    print(f"   Requests per hour: {details.get('requests_per_hour', 60)}")
                    print(f"   Min transaction USD: ${details.get('min_transaction_usd', 500000):,}")
    
    except Exception as e:
        logger.error(f"Error getting coverage stats: {e}")
        print(f"❌ Error: {e}")


def test_cross_reference(aggregator, email=None, username=None, crypto_address=None):
    """Test cross-referencing identities across community databases"""
    logger = get_logger(__name__)
    
    print(f"\n🔗 Cross-Referencing Identity Information")
    print("=" * 50)
    
    identifiers = {}
    if email:
        identifiers['email'] = email
    if username:
        identifiers['username'] = username  
    if crypto_address:
        identifiers['crypto_address'] = crypto_address
    
    if not identifiers:
        print("❌ No identifiers provided for cross-reference")
        return
    
    print(f"📋 Identifiers to cross-reference:")
    for id_type, id_value in identifiers.items():
        print(f"   {id_type}: {id_value}")
    
    try:
        result = aggregator.cross_reference_identity(**identifiers)
        
        cross_references_found = result.get('cross_references_found', False)
        print(f"\n🔍 Cross-references found: {'YES' if cross_references_found else 'NO'}")
        
        if cross_references_found:
            scamsearch_results = result.get('scamsearch_results', [])
            linked_addresses = result.get('linked_addresses', [])
            linked_scam_types = result.get('linked_scam_types', [])
            risk_assessment = result.get('risk_assessment', {})
            
            print(f"📊 ScamSearch entries: {len(scamsearch_results)}")
            print(f"🔗 Linked crypto addresses: {len(linked_addresses)}")
            print(f"⚠️  Linked scam types: {', '.join(list(linked_scam_types)[:3])}")
            
            print(f"\n📈 Risk Assessment:")
            print(f"   Overall risk score: {risk_assessment.get('overall_risk_score', 0):.3f}")
            print(f"   Confidence: {risk_assessment.get('confidence', 0):.3f}")
            print(f"   Total reports: {risk_assessment.get('total_reports', 0)}")
            
            # Show sample linked addresses
            if linked_addresses:
                print(f"\n🏛️  Sample linked addresses:")
                for addr in list(linked_addresses)[:3]:
                    print(f"   {addr}")
            
            # Show sample entries
            print(f"\n📝 Sample ScamSearch entries:")
            for entry in scamsearch_results[:2]:
                scam_type = entry.get('scam_type', 'unknown')
                description = entry.get('description', '')[:60]
                verified = entry.get('verified', False)
                print(f"   {scam_type} {'(verified)' if verified else ''}: {description}...")
        
    except Exception as e:
        logger.error(f"Cross-reference failed: {e}")
        print(f"❌ Error: {e}")


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description='Test community scam database integration')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('address', nargs='?', help='Address to test against community databases')
    group.add_argument('--update-cryptoscamdb', action='store_true', help='Update CryptoScamDB data')
    group.add_argument('--stats', action='store_true', help='Show coverage statistics')
    group.add_argument('--cross-reference', help='Cross-reference identity (email/username)')
    
    parser.add_argument('--test-all', action='store_true', help='Test all available sources')
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
        print("🚀 Initializing community scam database aggregator...")
        aggregator = CommunityScamAggregator(
            config.dict(),
            cache_dir=config.cache.directory
        )
        
        available_sources = list(aggregator.available_sources)
        print(f"✅ Available sources: {', '.join(available_sources)}")
        
        # Execute requested action
        if args.address:
            test_single_address(aggregator, args.address)
        elif args.update_cryptoscamdb:
            cryptoscamdb = CryptoScamDBCollector(config.dict(), config.cache.directory)
            update_cryptoscamdb(cryptoscamdb)
        elif args.stats:
            show_coverage_stats(aggregator)
        elif args.cross_reference:
            # Detect type of identifier
            identifier = args.cross_reference
            if '@' in identifier:
                test_cross_reference(aggregator, email=identifier)
            elif identifier.startswith('0x'):
                test_cross_reference(aggregator, crypto_address=identifier)
            else:
                test_cross_reference(aggregator, username=identifier)
        
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()