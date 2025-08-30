#!/usr/bin/env python3
"""
Automated script to update sanctions data from various sources.
Designed to run daily via cron job or AWS Lambda for fresh data.

Usage:
    python update_sanctions_data.py [--force] [--config /path/to/config.json]
"""

import sys
import os
import argparse
import json
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import get_config, get_config_manager
from src.utils.logging import setup_logging, get_logger
from src.collectors import OFACSanctionsCollector, ChainanalysisClient, SanctionsAggregator


def setup_environment():
    """Set up logging and configuration"""
    # Load configuration
    config = get_config()
    
    # Set up logging
    setup_logging(config.logging.dict())
    logger = get_logger(__name__)
    
    return config, logger


def update_ofac_data(config, logger, force_update=False):
    """Update OFAC sanctions data"""
    logger.info("Starting OFAC data update", force_update=force_update)
    
    try:
        # Initialize OFAC collector
        collector = OFACSanctionsCollector(
            config.dict(),
            cache_dir=config.cache.directory
        )
        
        # Check if update is needed
        if not force_update and not collector.should_update():
            logger.info("OFAC data is up to date, skipping update")
            return True
        
        # Perform update
        success = collector.update_data()
        
        if success:
            # Get statistics
            stats = collector.get_statistics()
            logger.info(
                "OFAC data update completed successfully",
                total_entities=stats.get('total_entities', 0),
                crypto_addresses=stats.get('crypto_addresses', 0),
                last_update=stats.get('last_update')
            )
            
            # Log top programs for monitoring
            top_programs = stats.get('top_programs', [])[:5]
            if top_programs:
                logger.info("Top 5 sanctions programs", programs=top_programs)
        else:
            logger.error("OFAC data update failed")
        
        return success
        
    except Exception as e:
        logger.error("Error updating OFAC data", error=str(e))
        return False


def validate_chainalysis_access(config, logger):
    """Validate Chainalysis API access"""
    logger.info("Validating Chainalysis API access")
    
    try:
        client = ChainanalysisClient(
            config.dict(),
            cache_dir=config.cache.directory
        )
        
        # Check if API key is configured
        if not config.api_keys.chainalysis:
            logger.warning("No Chainalysis API key configured")
            return False
        
        # Validate API key
        is_valid = client.validate_api_key()
        
        if is_valid:
            logger.info("Chainalysis API key validation successful")
            
            # Get usage stats
            stats = client.get_usage_stats()
            logger.info("Chainalysis usage stats", stats=stats)
        else:
            logger.error("Chainalysis API key validation failed")
        
        return is_valid
        
    except Exception as e:
        logger.error("Error validating Chainalysis access", error=str(e))
        return False


def run_health_checks(config, logger):
    """Run health checks on all sanctions data sources"""
    logger.info("Running sanctions data health checks")
    
    results = {
        'timestamp': datetime.utcnow().isoformat(),
        'ofac_status': 'unknown',
        'chainalysis_status': 'unknown',
        'overall_status': 'unknown'
    }
    
    try:
        # Initialize aggregator
        aggregator = SanctionsAggregator(
            config.dict(),
            cache_dir=config.cache.directory
        )
        
        # Ensure data is ready
        data_ready = aggregator.ensure_data_ready()
        
        # Get coverage stats
        coverage_stats = aggregator.get_coverage_stats()
        
        # Check OFAC status
        ofac_details = coverage_stats.get('source_details', {}).get('ofac', {})
        if 'error' in ofac_details:
            results['ofac_status'] = 'error'
            logger.error("OFAC health check failed", error=ofac_details['error'])
        else:
            results['ofac_status'] = 'healthy'
            results['ofac_entities'] = ofac_details.get('total_entities', 0)
            results['ofac_crypto_addresses'] = ofac_details.get('crypto_addresses', 0)
            results['ofac_last_update'] = ofac_details.get('last_update')
        
        # Check Chainalysis status
        chainalysis_details = coverage_stats.get('source_details', {}).get('chainalysis', {})
        if 'error' in chainalysis_details:
            results['chainalysis_status'] = 'error'
            logger.warning("Chainalysis health check failed", error=chainalysis_details['error'])
        elif chainalysis_details.get('api_key_valid'):
            results['chainalysis_status'] = 'healthy'
            results['chainalysis_cached_screenings'] = chainalysis_details.get('cached_screenings', 0)
        else:
            results['chainalysis_status'] = 'no_api_key'
            logger.warning("Chainalysis API key not configured or invalid")
        
        # Determine overall status
        if results['ofac_status'] == 'healthy':
            if results['chainalysis_status'] in ['healthy', 'no_api_key']:
                results['overall_status'] = 'healthy'
            else:
                results['overall_status'] = 'partial'  # OFAC works, Chainalysis doesn't
        else:
            results['overall_status'] = 'unhealthy'
        
        # Log coverage information
        available_sources = coverage_stats.get('available_sources', [])
        coverage_percentage = coverage_stats.get('coverage_percentage', 0)
        
        logger.info(
            "Health check completed",
            overall_status=results['overall_status'],
            available_sources=available_sources,
            coverage_percentage=coverage_percentage,
            data_ready=data_ready
        )
        
        return results
        
    except Exception as e:
        logger.error("Error running health checks", error=str(e))
        results['overall_status'] = 'error'
        results['error'] = str(e)
        return results


def test_address_screening(config, logger):
    """Test address screening with known addresses"""
    logger.info("Testing address screening functionality")
    
    # Test addresses (known clean addresses)
    test_addresses = [
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",  # Ethereum Foundation
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",          # Bitcoin Genesis Block
        "0x0000000000000000000000000000000000000000"   # Zero address
    ]
    
    try:
        # Initialize aggregator
        aggregator = SanctionsAggregator(
            config.dict(),
            cache_dir=config.cache.directory
        )
        
        test_results = []
        
        for address in test_addresses:
            try:
                logger.info("Testing address screening", address=address[:10] + "...")
                
                result = aggregator.collect_address_data(address)
                
                if result:
                    test_results.append({
                        'address': address[:10] + "...",
                        'sanctions_found': result.get('sanctions_found', False),
                        'sources_checked': result.get('sources_checked', []),
                        'risk_score': result.get('aggregated_risk', {}).get('risk_score', 0)
                    })
                else:
                    test_results.append({
                        'address': address[:10] + "...",
                        'error': 'No result returned'
                    })
                    
            except Exception as e:
                logger.error("Error testing address", address=address, error=str(e))
                test_results.append({
                    'address': address[:10] + "...",
                    'error': str(e)
                })
        
        logger.info("Address screening test completed", results=test_results)
        return test_results
        
    except Exception as e:
        logger.error("Error testing address screening", error=str(e))
        return []


def main():
    """Main update routine"""
    parser = argparse.ArgumentParser(description='Update sanctions data')
    parser.add_argument('--force', action='store_true', 
                       help='Force update even if data is recent')
    parser.add_argument('--config', type=str,
                       help='Path to configuration file')
    parser.add_argument('--test-only', action='store_true',
                       help='Only run health checks and tests, no updates')
    parser.add_argument('--quiet', action='store_true',
                       help='Reduce log output')
    
    args = parser.parse_args()
    
    try:
        # Set up environment
        if args.config:
            config_manager = get_config_manager(args.config)
            config = config_manager.load_config()
        else:
            config = get_config()
        
        # Adjust logging level if quiet
        if args.quiet:
            config.logging.level = "WARNING"
        
        setup_logging(config.logging.dict())
        logger = get_logger(__name__)
        
        logger.info("Starting sanctions data update routine", 
                   force_update=args.force, test_only=args.test_only)
        
        success = True
        
        if not args.test_only:
            # Update OFAC data
            ofac_success = update_ofac_data(config, logger, args.force)
            if not ofac_success:
                success = False
            
            # Validate Chainalysis access (doesn't update, just validates)
            chainalysis_success = validate_chainalysis_access(config, logger)
            # Chainalysis failure is not critical since it's optional
        
        # Run health checks
        health_results = run_health_checks(config, logger)
        
        # Test address screening
        screening_results = test_address_screening(config, logger)
        
        # Summary
        overall_status = health_results.get('overall_status', 'unknown')
        
        if overall_status == 'healthy':
            logger.info("✅ All sanctions data sources are healthy and operational")
        elif overall_status == 'partial':
            logger.warning("⚠️  Some sanctions data sources are unavailable")
        elif overall_status == 'unhealthy':
            logger.error("❌ Critical sanctions data sources are failing")
            success = False
        else:
            logger.error("❓ Unknown health status")
            success = False
        
        # Exit with appropriate code
        exit_code = 0 if success else 1
        
        logger.info("Sanctions data update routine completed", 
                   success=success, exit_code=exit_code)
        
        sys.exit(exit_code)
        
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()