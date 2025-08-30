#!/usr/bin/env python3
"""
Test script for smart contract threat analysis integration.

Usage:
    python test_smart_contracts.py 0x1234... --test-all
    python test_smart_contracts.py 0x1234... --honeypot-only
    python test_smart_contracts.py 0x1234... --contract-analysis
    python test_smart_contracts.py 0x1234... --rugpull-check
    python test_smart_contracts.py --stats
    python test_smart_contracts.py --cross-reference 0x1234...
"""

import sys
import os
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import get_config
from src.utils.logging import setup_logging, get_logger
from src.collectors.smart_contract_aggregator import SmartContractAggregator
from src.collectors.honeypot_detector import HoneypotDetector
from src.collectors.contract_analyzer import ContractAnalyzer
from src.collectors.rugpull_detector import RugPullDetector
from src.collectors.web3_provider import Web3Provider


def test_single_contract(aggregator, contract_address, chain=None):
    """Test smart contract analysis for a single contract"""
    logger = get_logger(__name__)
    
    print(f"\n🔒 Analyzing smart contract: {contract_address}")
    if chain:
        print(f"🌐 Network: {chain}")
    print("=" * 70)
    
    try:
        result = aggregator.collect_address_data(contract_address, chain)
        
        if not result:
            print("❌ No result returned")
            return
        
        # Basic info
        sources_checked = result.get('sources_checked', [])
        threats_found = result.get('smart_contract_threats_found', False)
        
        print(f"📊 Analysis sources: {', '.join(sources_checked)}")
        print(f"⚠️  Smart contract threats: {'YES' if threats_found else 'NO'}")
        
        # Honeypot analysis results
        honeypot_result = result.get('honeypot_result')
        if honeypot_result and honeypot_result.get('found_honeypot_data'):
            is_honeypot = honeypot_result.get('is_honeypot', False)
            confidence = honeypot_result.get('confidence_score', 0)
            
            if is_honeypot:
                honeypot_reason = honeypot_result.get('honeypot_reason', 'unknown')
                print(f"🍯 Honeypot Detection: CONFIRMED ({honeypot_reason})")
            else:
                print(f"✅ Honeypot Detection: Clean (confidence: {confidence:.2f})")
            
            # Tax analysis
            tax_analysis = honeypot_result.get('tax_analysis', {})
            buy_tax = tax_analysis.get('buy_tax', 0)
            sell_tax = tax_analysis.get('sell_tax', 0)
            
            if buy_tax > 0 or sell_tax > 0:
                print(f"📈 Token Taxes: {buy_tax}% buy, {sell_tax}% sell")
            
            # Trading analysis
            trading_analysis = honeypot_result.get('trading_analysis', {})
            can_sell = trading_analysis.get('can_be_sold', True)
            if not can_sell:
                print(f"🚫 Trading: Cannot sell tokens")
        else:
            print(f"❓ Honeypot Detection: No data available")
        
        # Contract analysis results
        contract_result = result.get('contract_analysis_result')
        if contract_result and contract_result.get('found_contract_data'):
            contract_info = contract_result.get('contract_info', {})
            security_analysis = contract_result.get('security_analysis', {})
            
            print(f"📄 Contract: {contract_info.get('name', 'Unknown')} (verified: {contract_info.get('is_verified', False)})")
            print(f"🔐 Security Risk: {security_analysis.get('risk_level', 'unknown').upper()}")
            
            # Security issues
            security_issues = security_analysis.get('security_issues', [])
            if security_issues:
                print(f"⚠️  Security Issues: {', '.join(security_issues[:3])}")
            
            # Admin functions
            if security_analysis.get('has_admin_functions'):
                print(f"👤 Admin Functions: Present")
            
            # Proxy contract
            proxy_analysis = contract_result.get('proxy_analysis', {})
            if proxy_analysis.get('can_be_upgraded'):
                print(f"🔄 Upgradeable Contract: YES")
        else:
            print(f"❓ Contract Analysis: No data available")
        
        # Rug pull analysis results
        rugpull_result = result.get('rugpull_result')
        if rugpull_result and rugpull_result.get('found_rugpull_data'):
            probability = rugpull_result.get('rug_pull_probability', 0)
            risk_level = rugpull_result.get('risk_level', 'low')
            confidence = rugpull_result.get('confidence_score', 0)
            
            print(f"🎯 Rug Pull Risk: {probability:.1%} ({risk_level.upper()})")
            
            # Red flags
            red_flags = rugpull_result.get('red_flags', [])
            if red_flags:
                print(f"🚩 Red Flags: {', '.join(red_flags[:3])}")
            
            # Liquidity analysis
            liquidity_analysis = rugpull_result.get('liquidity_analysis', {})
            removal_percentage = liquidity_analysis.get('removal_percentage', 0)
            if removal_percentage > 0:
                print(f"💧 Liquidity Removal: {removal_percentage:.1f}%")
        else:
            print(f"❓ Rug Pull Analysis: No data available")
        
        # Web3 blockchain data
        web3_result = result.get('web3_result')
        if web3_result and web3_result.get('found_web3_data'):
            is_contract = web3_result.get('is_contract', False)
            balance = web3_result.get('balance', {})
            
            print(f"⛓️  Blockchain: Contract={is_contract}")
            
            if balance:
                formatted_balance = balance.get('formatted', 'Unknown')
                print(f"💰 Balance: {formatted_balance}")
        else:
            print(f"❓ Web3 Data: No data available")
        
        # Aggregated assessment
        assessment = result.get('aggregated_assessment', {})
        overall_risk_score = assessment.get('overall_risk_score', 0)
        confidence = assessment.get('confidence', 0)
        threat_categories = assessment.get('threat_categories', [])
        primary_risks = assessment.get('primary_risks', [])
        
        print(f"\n🎯 Overall Assessment:")
        print(f"   Risk Score: {overall_risk_score:.3f}")
        print(f"   Confidence: {confidence:.3f}")
        
        if threat_categories:
            print(f"   Threat Categories: {', '.join(threat_categories)}")
        
        if primary_risks:
            print(f"   Primary Risks:")
            for risk in primary_risks[:3]:
                print(f"     • {risk}")
        
        # Risk level interpretation
        if overall_risk_score >= 0.8:
            print(f"🔴 CRITICAL RISK - Multiple severe threats detected")
        elif overall_risk_score >= 0.6:
            print(f"🟠 HIGH RISK - Significant threats present")
        elif overall_risk_score >= 0.3:
            print(f"🟡 MODERATE RISK - Some concerns identified")
        elif threat_categories:
            print(f"🟡 CAUTION - Minor threats detected")
        else:
            print(f"✅ LOW RISK - No major threats identified")
            
    except Exception as e:
        logger.error(f"Error analyzing contract {contract_address}: {e}")
        print(f"❌ Error: {e}")


def test_honeypot_only(detector, contract_address, chain=None):
    """Test honeypot detection only"""
    logger = get_logger(__name__)
    
    print(f"\n🍯 Honeypot Analysis: {contract_address}")
    print("=" * 50)
    
    try:
        result = detector.lookup_address(contract_address, chain)
        
        if not result or not result.get('found_honeypot_data'):
            print("❌ No honeypot data available")
            return
        
        is_honeypot = result.get('is_honeypot', False)
        confidence = result.get('confidence_score', 0)
        
        if is_honeypot:
            reason = result.get('honeypot_reason', 'unknown')
            print(f"🚨 HONEYPOT DETECTED: {reason}")
        else:
            print(f"✅ Not a honeypot (confidence: {confidence:.2f})")
        
        # Detailed analysis
        token_info = result.get('token_info', {})
        if token_info:
            print(f"🪙 Token: {token_info.get('name', 'Unknown')} ({token_info.get('symbol', 'UNK')})")
        
        tax_analysis = result.get('tax_analysis', {})
        print(f"📊 Taxes: Buy {tax_analysis.get('buy_tax', 0)}%, Sell {tax_analysis.get('sell_tax', 0)}%")
        
        trading_analysis = result.get('trading_analysis', {})
        can_buy = trading_analysis.get('can_be_bought', True)
        can_sell = trading_analysis.get('can_be_sold', True)
        
        print(f"💱 Trading: Buy {'✅' if can_buy else '❌'}, Sell {'✅' if can_sell else '❌'}")
        
        security_analysis = result.get('security_analysis', {})
        risk_factors = security_analysis.get('risk_factors', [])
        if risk_factors:
            print(f"⚠️  Risk Factors: {', '.join(risk_factors[:5])}")
        
    except Exception as e:
        logger.error(f"Error in honeypot analysis: {e}")
        print(f"❌ Error: {e}")


def show_coverage_stats(aggregator):
    """Show smart contract analysis coverage statistics"""
    logger = get_logger(__name__)
    
    print(f"\n📊 Smart Contract Analysis Coverage")
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
            print(f"\n{source.upper().replace('_', ' ')}:")
            
            if 'error' in details:
                print(f"   ❌ Error: {details['error']}")
            else:
                if source == 'honeypot_detector':
                    print(f"   Supported chains: {details.get('supported_chains', [])}")
                    print(f"   Default chain: {details.get('default_chain', 'ethereum')}")
                    print(f"   Max buy tax threshold: {details.get('max_buy_tax_threshold', 10)}%")
                    print(f"   Max sell tax threshold: {details.get('max_sell_tax_threshold', 10)}%")
                elif source == 'contract_analyzer':
                    print(f"   Supported chains: {details.get('supported_chains', [])}")
                    print(f"   Configured chains: {details.get('configured_chains', [])}")
                    print(f"   Default chain: {details.get('default_chain', 'ethereum')}")
                    print(f"   Analyze bytecode: {details.get('analyze_bytecode', True)}")
                elif source == 'rugpull_detector':
                    print(f"   Supported DEXes: {details.get('supported_dexes', [])}")
                    print(f"   Default DEX: {details.get('default_dex', 'uniswap_v2')}")
                    print(f"   Analysis period: {details.get('analysis_period_days', 7)} days")
                    print(f"   Min liquidity: ${details.get('min_liquidity_usd', 10000):,}")
                elif source == 'web3_provider':
                    print(f"   Supported chains: {details.get('supported_chains', [])}")
                    print(f"   Configured chains: {details.get('configured_chains', [])}")
                    print(f"   Default chain: {details.get('default_chain', 'ethereum')}")
                    connection_status = details.get('connection_status', {})
                    for chain, status in connection_status.items():
                        status_icon = "✅" if status.get('connected') else "❌"
                        print(f"     {chain}: {status_icon}")
    
    except Exception as e:
        logger.error(f"Error getting coverage stats: {e}")
        print(f"❌ Error: {e}")


def test_cross_reference(aggregator, contract_address, chain=None):
    """Test cross-referencing a contract across multiple analysis tools"""
    logger = get_logger(__name__)
    
    print(f"\n🔗 Cross-Reference Analysis: {contract_address}")
    print("=" * 50)
    
    try:
        result = aggregator.cross_reference_contract(contract_address)
        
        cross_references_found = result.get('cross_references_found', False)
        print(f"🔍 Threats found: {'YES' if cross_references_found else 'NO'}")
        
        analysis_results = result.get('analysis_results', {})
        sources_checked = analysis_results.get('sources_checked', [])
        print(f"📊 Sources analyzed: {', '.join(sources_checked)}")
        
        # Consensus assessment
        consensus = result.get('consensus_assessment', {})
        threat_consensus = consensus.get('threat_consensus', False)
        risk_agreement = consensus.get('risk_agreement_score', 0)
        
        print(f"\n🎯 Consensus Assessment:")
        print(f"   Threat consensus: {'YES' if threat_consensus else 'NO'}")
        print(f"   Agreement score: {risk_agreement:.3f}")
        
        # Show individual source assessments
        if analysis_results.get('aggregated_assessment'):
            assessment = analysis_results['aggregated_assessment']
            threat_categories = assessment.get('threat_categories', [])
            primary_risks = assessment.get('primary_risks', [])
            
            if threat_categories:
                print(f"   Threat categories: {', '.join(threat_categories)}")
            
            if primary_risks:
                print(f"   Key findings:")
                for risk in primary_risks[:3]:
                    print(f"     • {risk}")
    
    except Exception as e:
        logger.error(f"Cross-reference failed: {e}")
        print(f"❌ Error: {e}")


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description='Test smart contract threat analysis integration')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('contract_address', nargs='?', help='Contract address to analyze')
    group.add_argument('--stats', action='store_true', help='Show coverage statistics')
    group.add_argument('--cross-reference', help='Cross-reference contract across all tools')
    
    parser.add_argument('--chain', help='Blockchain network (ethereum, bsc, polygon, etc.)')
    parser.add_argument('--honeypot-only', action='store_true', help='Run honeypot analysis only')
    parser.add_argument('--contract-analysis', action='store_true', help='Run contract analysis only')
    parser.add_argument('--rugpull-check', action='store_true', help='Run rug pull check only')
    parser.add_argument('--test-all', action='store_true', help='Run all available analyses')
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
        
        # Initialize components
        print("🚀 Initializing smart contract threat analysis system...")
        aggregator = SmartContractAggregator(
            config.dict(),
            cache_dir=config.cache.directory
        )
        
        available_sources = list(aggregator.available_sources)
        print(f"✅ Available sources: {', '.join(available_sources)}")
        
        # Execute requested action
        if args.contract_address:
            if args.honeypot_only:
                honeypot_detector = HoneypotDetector(config.dict(), config.cache.directory)
                test_honeypot_only(honeypot_detector, args.contract_address, args.chain)
            else:
                test_single_contract(aggregator, args.contract_address, args.chain)
        elif args.stats:
            show_coverage_stats(aggregator)
        elif args.cross_reference:
            test_cross_reference(aggregator, args.cross_reference, args.chain)
        
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()