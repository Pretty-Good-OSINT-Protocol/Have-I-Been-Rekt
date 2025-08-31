#!/usr/bin/env python3
"""
Comprehensive Threat Intelligence Collection
Collects multi-modal threat data: blockchain + usernames + URLs + emails + infrastructure
"""

import asyncio
import aiohttp
import pandas as pd
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
import hashlib
import time
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

class ComprehensiveThreatCollector:
    """Collects threat intelligence from multiple sources for training"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = None
        
        # API credentials
        self.hibp_key = os.getenv('HIBP_API_KEY')
        self.shodan_key = os.getenv('SHODAN_API_KEY')
        self.vt_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.abuse_key = os.getenv('ABUSEIPDB_API_KEY')
        
        # Data storage
        self.threat_data = {
            'blockchain': [],
            'usernames': [],
            'domains': [],
            'emails': [],
            'infrastructure': []
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def collect_blockchain_intelligence(self, address: str) -> Dict[str, Any]:
        """Collect blockchain-specific intelligence"""
        print(f"🔗 Analyzing blockchain address: {address}")
        
        intelligence = {
            'address': address,
            'risk_indicators': [],
            'network_analysis': {},
            'transaction_patterns': {}
        }
        
        # Add logic for blockchain analysis here
        # This would integrate with your existing Ethereum dataset
        
        return intelligence
    
    async def collect_username_intelligence(self, username: str) -> Dict[str, Any]:
        """Collect intelligence on usernames/handles"""
        print(f"👤 Analyzing username: {username}")
        
        intelligence = {
            'username': username,
            'platform_presence': [],
            'scam_reports': [],
            'associated_addresses': []
        }
        
        # Check against known scammer databases
        scammer_patterns = [
            'crypto_king', 'moon_shot', 'quick_profit', 'guaranteed_returns',
            'official_support', 'admin_help', 'binance_official', 'metamask_help'
        ]
        
        username_lower = username.lower()
        for pattern in scammer_patterns:
            if pattern in username_lower:
                intelligence['scam_reports'].append({
                    'pattern': pattern,
                    'risk_level': 'high',
                    'reason': f'Username matches common scammer pattern: {pattern}'
                })
        
        return intelligence
    
    async def collect_domain_intelligence(self, domain: str) -> Dict[str, Any]:
        """Collect intelligence on domains/URLs"""
        print(f"🌐 Analyzing domain: {domain}")
        
        intelligence = {
            'domain': domain,
            'reputation_score': 0.0,
            'threat_categories': [],
            'infrastructure_details': {},
            'phishing_indicators': []
        }
        
        try:
            # VirusTotal domain analysis
            if self.vt_key:
                vt_data = await self.check_virustotal_domain(domain)
                if vt_data:
                    intelligence['threat_categories'] = vt_data.get('categories', [])
                    intelligence['reputation_score'] = vt_data.get('reputation_score', 0.0)
            
            # Shodan infrastructure analysis
            if self.shodan_key:
                shodan_data = await self.check_shodan_domain(domain)
                if shodan_data:
                    intelligence['infrastructure_details'] = shodan_data
            
            # Check for common phishing indicators
            phishing_indicators = [
                'binance' in domain and 'binance.com' not in domain,
                'metamask' in domain and 'metamask.io' not in domain,
                'uniswap' in domain and 'uniswap.org' not in domain,
                any(char in domain for char in ['0', '1', 'l', 'I']) and len(domain) > 10,
                domain.count('-') > 2,
                domain.endswith('.tk') or domain.endswith('.ml')
            ]
            
            for i, indicator in enumerate(phishing_indicators):
                if indicator:
                    intelligence['phishing_indicators'].append({
                        'type': f'pattern_{i+1}',
                        'description': 'Suspicious domain pattern detected'
                    })
        
        except Exception as e:
            print(f"⚠️ Error analyzing domain {domain}: {e}")
        
        return intelligence
    
    async def collect_email_intelligence(self, email: str) -> Dict[str, Any]:
        """Collect intelligence on email addresses"""
        print(f"📧 Analyzing email: {email}")
        
        intelligence = {
            'email': email,
            'breach_history': [],
            'domain_reputation': {},
            'risk_indicators': []
        }
        
        try:
            # HIBP breach check
            if self.hibp_key:
                breach_data = await self.check_hibp_breaches(email)
                if breach_data:
                    intelligence['breach_history'] = breach_data
            
            # Email domain analysis
            domain = email.split('@')[1] if '@' in email else None
            if domain:
                domain_intel = await self.collect_domain_intelligence(domain)
                intelligence['domain_reputation'] = domain_intel
            
            # Check for suspicious patterns
            suspicious_patterns = [
                'noreply' in email,
                'admin' in email,
                'support' in email and ('gmail.com' in email or 'yahoo.com' in email),
                any(char.isdigit() for char in email.split('@')[0]) and len(email.split('@')[0]) > 8
            ]
            
            for pattern in suspicious_patterns:
                if pattern:
                    intelligence['risk_indicators'].append('suspicious_pattern')
        
        except Exception as e:
            print(f"⚠️ Error analyzing email {email}: {e}")
        
        return intelligence
    
    async def check_virustotal_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain with VirusTotal API"""
        if not self.vt_key:
            return None
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': self.vt_key, 'domain': domain}
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'reputation_score': data.get('positives', 0) / max(data.get('total', 1), 1),
                        'categories': data.get('categories', []),
                        'detected_urls': len(data.get('detected_urls', []))
                    }
        except Exception as e:
            print(f"⚠️ VirusTotal API error for {domain}: {e}")
        
        return None
    
    async def check_shodan_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain infrastructure with Shodan API"""
        if not self.shodan_key:
            return None
        
        try:
            url = f"https://api.shodan.io/dns/resolve"
            params = {'hostnames': domain, 'key': self.shodan_key}
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'ip_addresses': list(data.values()),
                        'hosting_info': 'resolved' if data else 'not_found'
                    }
        except Exception as e:
            print(f"⚠️ Shodan API error for {domain}: {e}")
        
        return None
    
    async def check_hibp_breaches(self, email: str) -> Optional[List[Dict[str, Any]]]:
        """Check email breaches with HIBP API"""
        if not self.hibp_key:
            return None
        
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {'hibp-api-key': self.hibp_key, 'User-Agent': 'HIBR-AI-Training'}
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    breaches = await response.json()
                    return [{'name': breach['Name'], 'date': breach['BreachDate']} 
                            for breach in breaches]
                elif response.status == 404:
                    return []  # No breaches found
        except Exception as e:
            print(f"⚠️ HIBP API error for {email}: {e}")
        
        return None
    
    async def collect_sample_threat_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect sample threat intelligence for training"""
        print("🚀 Collecting comprehensive threat intelligence...")
        
        # Sample data for testing (replace with real collection)
        sample_data = {
            'addresses': [
                '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb6',  # Known scam
                '0x00009277775ac7d0d59eaad8fee3d10ac6c805e8'   # From dataset
            ],
            'usernames': [
                '@crypto_king_2024',
                '@binance_official_help', 
                '@metamask_support_team',
                'admin_quick_profits'
            ],
            'domains': [
                'fake-binance.org',
                'metamask-help.com', 
                'uniswap-defi.net',
                'crypto-moonshot.tk'
            ],
            'emails': [
                'support@fake-binance.org',
                'admin@crypto-profits.com',
                'help@metamask-support.com'
            ]
        }
        
        results = {
            'blockchain_intelligence': [],
            'username_intelligence': [],
            'domain_intelligence': [],
            'email_intelligence': []
        }
        
        # Collect blockchain intelligence
        for address in sample_data['addresses']:
            intel = await self.collect_blockchain_intelligence(address)
            results['blockchain_intelligence'].append(intel)
            await asyncio.sleep(0.1)  # Rate limiting
        
        # Collect username intelligence
        for username in sample_data['usernames']:
            intel = await self.collect_username_intelligence(username)
            results['username_intelligence'].append(intel)
            await asyncio.sleep(0.1)
        
        # Collect domain intelligence
        for domain in sample_data['domains']:
            intel = await self.collect_domain_intelligence(domain)
            results['domain_intelligence'].append(intel)
            await asyncio.sleep(1)  # Slower for API rate limits
        
        # Collect email intelligence
        for email in sample_data['emails']:
            intel = await self.collect_email_intelligence(email)
            results['email_intelligence'].append(intel)
            await asyncio.sleep(1)
        
        return results
    
    def save_training_data(self, data: Dict[str, Any], output_dir: str = "datasets"):
        """Save collected data for training"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Save each intelligence type
        for intel_type, intel_data in data.items():
            filename = output_path / f"{intel_type}.json"
            with open(filename, 'w') as f:
                json.dump(intel_data, f, indent=2)
            print(f"💾 Saved {len(intel_data)} records to {filename}")
        
        # Create unified training dataset
        unified_data = []
        
        for intel_type, intel_data in data.items():
            for record in intel_data:
                unified_record = {
                    'type': intel_type,
                    'data': record,
                    'timestamp': int(time.time())
                }
                unified_data.append(unified_record)
        
        unified_file = output_path / "comprehensive_threat_intelligence.json"
        with open(unified_file, 'w') as f:
            json.dump(unified_data, f, indent=2)
        
        print(f"📊 Created unified training dataset: {unified_file}")
        print(f"   Total records: {len(unified_data)}")
        
        return str(unified_file)


async def main():
    """Main collection function"""
    config = {
        'rate_limit_delay': 1.0,
        'max_concurrent': 3,
        'output_directory': 'datasets'
    }
    
    print("🚀 COMPREHENSIVE THREAT INTELLIGENCE COLLECTOR")
    print("=" * 60)
    print("Collecting multi-modal threat data for AI training")
    print("=" * 60)
    
    async with ComprehensiveThreatCollector(config) as collector:
        # Collect sample threat intelligence
        threat_data = await collector.collect_sample_threat_data()
        
        # Save for training
        output_file = collector.save_training_data(threat_data)
        
        print(f"\n✅ Collection complete!")
        print(f"📁 Data saved to: {output_file}")
        print(f"🎯 Ready for comprehensive AI training!")
        
        # Summary
        total_records = sum(len(data) for data in threat_data.values())
        print(f"\n📊 Collection Summary:")
        for intel_type, data in threat_data.items():
            print(f"   {intel_type}: {len(data)} records")
        print(f"   Total: {total_records} threat intelligence records")


if __name__ == "__main__":
    asyncio.run(main())