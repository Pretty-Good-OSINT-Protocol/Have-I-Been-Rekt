"""
Chainabuse Scraper - respectful web scraping of Chainabuse.com
for community-reported cryptocurrency abuse reports.

Data Source: https://www.chainabuse.com/
Contains ~220k community reports of crypto abuse across multiple chains.

Note: This implements ethical scraping practices:
- Respects robots.txt
- Uses reasonable delays between requests
- Includes proper User-Agent
- Implements exponential backoff on errors
- Caches results to minimize requests
"""

import re
import time
import random
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, parse_qs
import logging

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType
from ..utils.logging import LoggingMixin


@dataclass 
class ChainabuseReport:
    """Represents a Chainabuse community report"""
    report_id: Optional[str] = None
    address: Optional[str] = None
    blockchain: Optional[str] = None
    abuse_type: Optional[str] = None
    description: Optional[str] = None
    reporter: Optional[str] = None
    report_date: Optional[datetime] = None
    amount_lost: Optional[float] = None
    currency: Optional[str] = None
    confidence_score: float = 0.6  # Community reports have moderate confidence
    verification_status: str = "unverified"
    
    @property
    def risk_level(self) -> RiskLevel:
        """Determine risk level based on abuse type"""
        if self.abuse_type in ['ransomware', 'exit_scam', 'rug_pull']:
            return RiskLevel.CRITICAL
        elif self.abuse_type in ['phishing', 'fake_exchange', 'investment_scam']:
            return RiskLevel.HIGH
        elif self.abuse_type in ['suspicious_activity', 'mixer_abuse']:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.HIGH  # Default for abuse reports


class ChainabuseScraper(BaseDataCollector, LoggingMixin):
    """Ethical scraper for Chainabuse community reports"""
    
    BASE_URL = "https://www.chainabuse.com"
    
    # Search and browse endpoints
    SEARCH_URL = f"{BASE_URL}/search"
    BROWSE_URL = f"{BASE_URL}/reports"
    
    # Common abuse types on Chainabuse
    ABUSE_TYPES = [
        'ransomware', 'blackmail', 'darknet', 'exchange', 'gambling', 
        'mixer', 'phishing', 'ponzi', 'scam', 'theft', 'other'
    ]
    
    # Blockchain mappings
    BLOCKCHAIN_MAPPING = {
        'btc': 'bitcoin',
        'eth': 'ethereum', 
        'ltc': 'litecoin',
        'bch': 'bitcoin_cash',
        'xmr': 'monero',
        'sol': 'solana',
        'ada': 'cardano'
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # Ethical scraping configuration
        self.base_delay = 2.0  # Base delay between requests (seconds)
        self.max_delay = 30.0  # Maximum delay on errors
        self.respect_robots = config.get('data_sources', {}).get(self.source_name, {}).get('respect_robots', True)
        
        # Storage for scraped data
        self.abuse_reports: Dict[str, List[ChainabuseReport]] = {}
        self.last_update: Optional[datetime] = None
        self.robots_txt_checked = False
        self.allowed_paths = set()
        self.disallowed_paths = set()
        
        # Rate limiting
        self.last_request_time = 0
        self.consecutive_errors = 0
    
    @property
    def source_name(self) -> str:
        return "chainabuse"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.SCAM_DATABASE
    
    def _check_robots_txt(self) -> bool:
        """Check and parse robots.txt for ethical scraping"""
        if self.robots_txt_checked:
            return True
        
        if not self.respect_robots:
            self.logger.info("Robots.txt checking disabled")
            self.robots_txt_checked = True
            return True
        
        try:
            robots_url = f"{self.BASE_URL}/robots.txt"
            self.logger.info("Checking robots.txt for scraping permissions")
            
            response = self.make_request(robots_url, timeout=10)
            
            if not response or 'text' not in response:
                self.logger.warning("Could not fetch robots.txt, proceeding with caution")
                self.robots_txt_checked = True
                return True
            
            robots_content = response['text']
            current_user_agent = None
            
            for line in robots_content.split('\n'):
                line = line.strip()
                
                if line.startswith('User-agent:'):
                    current_user_agent = line.split(':', 1)[1].strip()
                elif line.startswith('Disallow:') and current_user_agent in ['*', 'HaveIBeenRekt-OSINT']:
                    path = line.split(':', 1)[1].strip()
                    if path:
                        self.disallowed_paths.add(path)
                elif line.startswith('Allow:') and current_user_agent in ['*', 'HaveIBeenRekt-OSINT']:
                    path = line.split(':', 1)[1].strip()
                    if path:
                        self.allowed_paths.add(path)
                elif line.startswith('Crawl-delay:') and current_user_agent in ['*', 'HaveIBeenRekt-OSINT']:
                    try:
                        delay = float(line.split(':', 1)[1].strip())
                        self.base_delay = max(self.base_delay, delay)
                    except ValueError:
                        pass
            
            self.logger.info(
                "Robots.txt processed",
                disallowed_paths=len(self.disallowed_paths),
                allowed_paths=len(self.allowed_paths),
                crawl_delay=self.base_delay
            )
            
            self.robots_txt_checked = True
            return True
            
        except Exception as e:
            self.logger.warning("Error checking robots.txt", error=str(e))
            self.robots_txt_checked = True
            return True  # Proceed with caution if robots.txt check fails
    
    def _is_path_allowed(self, path: str) -> bool:
        """Check if a path is allowed according to robots.txt"""
        if not self.respect_robots:
            return True
        
        # Check disallowed paths
        for disallowed in self.disallowed_paths:
            if path.startswith(disallowed):
                return False
        
        # If there are allowed paths specified, check them
        if self.allowed_paths:
            for allowed in self.allowed_paths:
                if path.startswith(allowed):
                    return True
            return False  # Path not explicitly allowed
        
        return True  # Default to allowed if no specific restrictions
    
    def _ethical_delay(self):
        """Implement ethical delay between requests"""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        # Calculate delay based on recent errors
        if self.consecutive_errors > 0:
            error_delay = min(self.max_delay, self.base_delay * (2 ** self.consecutive_errors))
            # Add jitter to avoid thundering herd
            error_delay += random.uniform(0, error_delay * 0.1)
        else:
            error_delay = self.base_delay
        
        if elapsed < error_delay:
            sleep_time = error_delay - elapsed
            self.logger.debug("Ethical delay", sleep_seconds=sleep_time)
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _make_ethical_request(self, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Make request with ethical scraping practices"""
        # Check robots.txt
        if not self._check_robots_txt():
            return None
        
        # Parse URL and check if path is allowed
        parsed_url = urlparse(url)
        if not self._is_path_allowed(parsed_url.path):
            self.logger.warning("Path disallowed by robots.txt", path=parsed_url.path)
            return None
        
        # Apply ethical delay
        self._ethical_delay()
        
        # Set proper headers
        headers = kwargs.get('headers', {})
        headers.update({
            'User-Agent': 'HaveIBeenRekt-OSINT/1.0 (+https://github.com/Pretty-Good-OSINT-Protocol/Have-I-Been-Rekt)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        kwargs['headers'] = headers
        
        # Make request with timeout
        kwargs['timeout'] = kwargs.get('timeout', 30)
        
        try:
            response = self.make_request(url, **kwargs)
            
            if response:
                self.consecutive_errors = 0  # Reset error count on success
                return response
            else:
                self.consecutive_errors += 1
                return None
                
        except Exception as e:
            self.consecutive_errors += 1
            self.logger.error("Ethical request failed", url=url, error=str(e))
            return None
    
    def _parse_report_page(self, html_content: str) -> List[ChainabuseReport]:
        """Parse Chainabuse report page HTML to extract report data"""
        reports = []
        
        # This is a simplified parser - in practice you'd use BeautifulSoup
        # For now, we'll use regex patterns to extract key information
        
        try:
            # Look for address patterns in the HTML
            address_patterns = [
                r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}',  # Bitcoin addresses
                r'0x[a-fA-F0-9]{40}',                # Ethereum addresses
                r'[LM][a-km-zA-HJ-NP-Z1-9]{26,33}', # Litecoin addresses
            ]
            
            found_addresses = set()
            for pattern in address_patterns:
                matches = re.findall(pattern, html_content)
                found_addresses.update(matches)
            
            # Extract other report details using regex
            abuse_type_match = re.search(r'Abuse Type[:\s]*([^<\n]+)', html_content, re.IGNORECASE)
            description_match = re.search(r'Description[:\s]*([^<]{50,200})', html_content, re.IGNORECASE)
            date_match = re.search(r'(\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4})', html_content)
            
            # Create reports for found addresses
            for address in found_addresses:
                report = ChainabuseReport(
                    address=address,
                    abuse_type=abuse_type_match.group(1).strip() if abuse_type_match else 'unknown',
                    description=description_match.group(1).strip() if description_match else None,
                    report_date=self._parse_date(date_match.group(1)) if date_match else None,
                    blockchain=self._detect_blockchain(address)
                )
                
                reports.append(report)
                
        except Exception as e:
            self.logger.warning("Error parsing report page", error=str(e))
        
        return reports
    
    def _detect_blockchain(self, address: str) -> str:
        """Detect blockchain type from address format"""
        if address.startswith('1') or address.startswith('3') or address.startswith('bc1'):
            return 'bitcoin'
        elif address.startswith('0x') and len(address) == 42:
            return 'ethereum'
        elif address.startswith('L') or address.startswith('M'):
            return 'litecoin'
        else:
            return 'unknown'
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse various date formats"""
        if not date_str:
            return None
        
        date_formats = [
            '%Y-%m-%d',
            '%m/%d/%Y', 
            '%d/%m/%Y',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S'
        ]
        
        for fmt in date_formats:
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue
        
        return None
    
    def search_address(self, address: str) -> List[ChainabuseReport]:
        """Search Chainabuse for reports about a specific address"""
        if not self._check_robots_txt():
            return []
        
        # Check cache first
        cache_key = f"search_{address}"
        cached_result = self.get_cached_result(cache_key)
        if cached_result:
            return [ChainabuseReport(**report_data) for report_data in cached_result]
        
        reports = []
        
        try:
            # Construct search URL
            search_params = {'q': address}
            search_url = f"{self.SEARCH_URL}?q={address}"
            
            self.logger.info("Searching Chainabuse for address", address=address[:10] + "...")
            
            response = self._make_ethical_request(search_url)
            
            if response and 'text' in response:
                parsed_reports = self._parse_report_page(response['text'])
                
                # Filter reports to only those matching our search address
                for report in parsed_reports:
                    if report.address and report.address.lower() == address.lower():
                        reports.append(report)
                
                # Cache the results
                cache_data = [
                    {
                        'address': r.address,
                        'blockchain': r.blockchain,
                        'abuse_type': r.abuse_type,
                        'description': r.description,
                        'report_date': r.report_date.isoformat() if r.report_date else None,
                        'confidence_score': r.confidence_score
                    } for r in reports
                ]
                self.cache_result(cache_key, cache_data)
                
                self.logger.info("Chainabuse search completed", 
                               address=address[:10] + "...", 
                               reports_found=len(reports))
        
        except Exception as e:
            self.logger.error("Error searching Chainabuse", address=address, error=str(e))
        
        return reports
    
    def collect_address_data(self, address: str) -> Optional[Dict[str, Any]]:
        """Collect Chainabuse data for a specific address"""
        reports = self.search_address(address)
        
        if not reports:
            return {
                'address': address,
                'found_in_chainabuse': False,
                'reports': [],
                'source': self.source_name
            }
        
        # Convert reports to dict format
        report_dicts = []
        for report in reports:
            report_dict = {
                'address': report.address,
                'blockchain': report.blockchain,
                'abuse_type': report.abuse_type,
                'description': report.description,
                'report_date': report.report_date.isoformat() if report.report_date else None,
                'confidence_score': report.confidence_score,
                'risk_level': report.risk_level.value
            }
            report_dicts.append(report_dict)
        
        return {
            'address': address,
            'found_in_chainabuse': True,
            'report_count': len(reports),
            'reports': report_dicts,
            'highest_risk_level': max(report.risk_level.value for report in reports),
            'average_confidence': sum(report.confidence_score for report in reports) / len(reports),
            'abuse_types': list(set(report.abuse_type for report in reports if report.abuse_type)),
            'source': self.source_name
        }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse Chainabuse data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_in_chainabuse'):
            return risk_factors
        
        reports = raw_data.get('reports', [])
        if not reports:
            return risk_factors
        
        # Group reports by abuse type
        abuse_types = {}
        for report in reports:
            abuse_type = report.get('abuse_type', 'unknown')
            if abuse_type not in abuse_types:
                abuse_types[abuse_type] = {
                    'count': 0,
                    'max_confidence': 0,
                    'descriptions': [],
                    'risk_level': report.get('risk_level', 'high')
                }
            
            abuse_types[abuse_type]['count'] += 1
            abuse_types[abuse_type]['max_confidence'] = max(
                abuse_types[abuse_type]['max_confidence'],
                report.get('confidence_score', 0.6)
            )
            
            if report.get('description'):
                abuse_types[abuse_type]['descriptions'].append(report['description'])
        
        # Create risk factors
        for abuse_type, info in abuse_types.items():
            # Map to risk levels
            if info['risk_level'] == 'critical':
                severity = RiskLevel.CRITICAL
                weight = 0.8
            elif info['risk_level'] == 'high':
                severity = RiskLevel.HIGH
                weight = 0.7
            elif info['risk_level'] == 'medium':
                severity = RiskLevel.MEDIUM
                weight = 0.5
            else:
                severity = RiskLevel.HIGH
                weight = 0.6
            
            # Build description
            if info['count'] == 1:
                description = f"Address reported on Chainabuse for {abuse_type}"
            else:
                description = f"Address reported {info['count']} times on Chainabuse for {abuse_type}"
            
            risk_factor = RiskFactor(
                source=self.source_name,
                factor_type="community_abuse_report",
                severity=severity,
                weight=weight,
                description=description,
                reference_url="https://www.chainabuse.com/",
                confidence=info['max_confidence'],
                report_count=info['count']
            )
            
            risk_factors.append(risk_factor)
        
        return risk_factors
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about scraped data"""
        total_addresses = len(self.abuse_reports)
        total_reports = sum(len(reports) for reports in self.abuse_reports.values())
        
        abuse_type_counts = {}
        blockchain_counts = {}
        
        for reports in self.abuse_reports.values():
            for report in reports:
                abuse_type = report.abuse_type or 'unknown'
                abuse_type_counts[abuse_type] = abuse_type_counts.get(abuse_type, 0) + 1
                
                blockchain = report.blockchain or 'unknown'
                blockchain_counts[blockchain] = blockchain_counts.get(blockchain, 0) + 1
        
        return {
            'unique_addresses': total_addresses,
            'total_reports': total_reports,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'abuse_type_breakdown': abuse_type_counts,
            'blockchain_breakdown': blockchain_counts,
            'top_abuse_types': sorted(abuse_type_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'ethical_scraping_enabled': self.respect_robots,
            'base_delay_seconds': self.base_delay
        }