"""
CryptoScamDB Collector - integrates with CryptoScamDB GitHub repository
to collect community-reported scam addresses and domains.

Data Sources:
- GitHub: https://github.com/CryptoScamDB/api
- Website: https://cryptoscamdb.org/
"""

import json
import re
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
import logging

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType
from ..utils.logging import LoggingMixin


@dataclass
class ScamReport:
    """Represents a scam report from community sources"""
    id: Optional[str] = None
    addresses: List[str] = None
    domain: Optional[str] = None
    scam_type: Optional[str] = None
    category: Optional[str] = None
    subcategory: Optional[str] = None
    description: Optional[str] = None
    reporter: Optional[str] = None
    report_date: Optional[datetime] = None
    amount_lost: Optional[float] = None
    currency: Optional[str] = None
    status: str = "active"
    confidence: float = 0.7  # Default community report confidence
    source: str = "community"
    
    def __post_init__(self):
        if self.addresses is None:
            self.addresses = []
    
    @property
    def risk_level(self) -> RiskLevel:
        """Determine risk level based on scam type and category"""
        if self.scam_type in ['ponzi', 'exit_scam', 'rugpull']:
            return RiskLevel.CRITICAL
        elif self.scam_type in ['phishing', 'fake_exchange', 'impersonation']:
            return RiskLevel.HIGH
        elif self.scam_type in ['suspicious', 'unconfirmed']:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.HIGH  # Default for community reports


class CryptoScamDBCollector(BaseDataCollector, LoggingMixin):
    """Collector for CryptoScamDB community scam reports"""
    
    # GitHub API endpoints
    GITHUB_API_BASE = "https://api.github.com"
    REPO_OWNER = "CryptoScamDB"
    REPO_NAME = "api"
    
    # Data file paths in the repository
    DATA_PATHS = {
        'addresses': 'data/addresses.json',
        'domains': 'data/domains.json', 
        'ips': 'data/ips.json',
        'urls': 'data/urls.json'
    }
    
    # Scam categories mapping
    SCAM_CATEGORIES = {
        'Scamming': {
            'risk_level': RiskLevel.HIGH,
            'weight': 0.8,
            'description': 'General scamming activity'
        },
        'Phishing': {
            'risk_level': RiskLevel.HIGH,
            'weight': 0.9,
            'description': 'Phishing attacks targeting users'
        },
        'Ransomware': {
            'risk_level': RiskLevel.CRITICAL,
            'weight': 1.0,
            'description': 'Ransomware payment addresses'
        },
        'Darknet': {
            'risk_level': RiskLevel.HIGH,
            'weight': 0.7,
            'description': 'Darknet marketplace activity'
        },
        'Exchange': {
            'risk_level': RiskLevel.MEDIUM,
            'weight': 0.5,
            'description': 'Suspicious exchange activity'
        },
        'Mixing': {
            'risk_level': RiskLevel.MEDIUM,
            'weight': 0.4,
            'description': 'Cryptocurrency mixing service'
        }
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # GitHub API token (optional, increases rate limits)
        self.github_token = config.get('api_keys', {}).get('github')
        
        # Storage for loaded data
        self.scam_addresses: Dict[str, List[ScamReport]] = {}
        self.scam_domains: Set[str] = set()
        self.last_update: Optional[datetime] = None
        
        # Rate limiting for GitHub API
        self.api_requests_made = 0
        self.api_reset_time = None
    
    @property
    def source_name(self) -> str:
        return "cryptoscamdb"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.SCAM_DATABASE
    
    def _get_github_headers(self) -> Dict[str, str]:
        """Get headers for GitHub API requests"""
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'HaveIBeenRekt-OSINT/1.0'
        }
        
        if self.github_token:
            headers['Authorization'] = f'token {self.github_token}'
        
        return headers
    
    def _check_rate_limit(self) -> bool:
        """Check GitHub API rate limit status"""
        headers = self._get_github_headers()
        
        try:
            response = self.make_request(
                f"{self.GITHUB_API_BASE}/rate_limit",
                headers=headers
            )
            
            if response:
                rate_limit = response.get('rate', {})
                remaining = rate_limit.get('remaining', 0)
                reset_time = rate_limit.get('reset', 0)
                
                self.logger.info(
                    "GitHub API rate limit status",
                    remaining=remaining,
                    reset_time=datetime.fromtimestamp(reset_time).isoformat() if reset_time else None
                )
                
                return remaining > 10  # Keep some buffer
            
        except Exception as e:
            self.logger.warning("Failed to check GitHub rate limit", error=str(e))
            return True  # Assume it's okay if we can't check
        
        return True
    
    def _fetch_github_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Fetch a file from GitHub repository"""
        if not self._check_rate_limit():
            self.logger.warning("GitHub rate limit exceeded, skipping file fetch")
            return None
        
        url = f"{self.GITHUB_API_BASE}/repos/{self.REPO_OWNER}/{self.REPO_NAME}/contents/{file_path}"
        headers = self._get_github_headers()
        
        try:
            self.logger.info("Fetching CryptoScamDB data", file_path=file_path)
            
            response = self.make_request(url, headers=headers)
            
            if not response:
                return None
            
            # GitHub API returns base64-encoded content
            import base64
            content_b64 = response.get('content', '')
            if content_b64:
                content_bytes = base64.b64decode(content_b64)
                content_str = content_bytes.decode('utf-8')
                return json.loads(content_str)
            
        except Exception as e:
            self.logger.error("Error fetching GitHub file", file_path=file_path, error=str(e))
        
        return None
    
    def _parse_address_data(self, data: Dict[str, Any]) -> List[ScamReport]:
        """Parse CryptoScamDB address data into ScamReport objects"""
        reports = []
        
        if not data or 'result' not in data:
            return reports
        
        entries = data.get('result', [])
        
        for entry in entries:
            try:
                # Extract basic information
                addresses = []
                
                # Handle different address formats
                if 'addresses' in entry:
                    addresses = entry['addresses'] if isinstance(entry['addresses'], list) else [entry['addresses']]
                elif 'address' in entry:
                    addresses = [entry['address']]
                
                # Create scam report
                report = ScamReport(
                    id=entry.get('id'),
                    addresses=addresses,
                    scam_type=entry.get('type', 'unknown').lower(),
                    category=entry.get('category', 'Scamming'),
                    subcategory=entry.get('subcategory'),
                    description=entry.get('description'),
                    domain=entry.get('url') or entry.get('domain'),
                    report_date=self._parse_date(entry.get('date')),
                    status=entry.get('status', 'active').lower(),
                    source='cryptoscamdb'
                )
                
                # Adjust confidence based on available information
                if report.description and len(report.description) > 50:
                    report.confidence += 0.1
                if report.domain:
                    report.confidence += 0.1
                if len(report.addresses) > 1:
                    report.confidence += 0.1
                
                report.confidence = min(1.0, report.confidence)
                
                reports.append(report)
                
            except Exception as e:
                self.logger.warning("Error parsing CryptoScamDB entry", entry_id=entry.get('id'), error=str(e))
        
        return reports
    
    def _parse_domain_data(self, data: Dict[str, Any]) -> Set[str]:
        """Parse CryptoScamDB domain data"""
        domains = set()
        
        if not data or 'result' not in data:
            return domains
        
        entries = data.get('result', [])
        
        for entry in entries:
            try:
                domain = entry.get('url') or entry.get('domain')
                if domain:
                    # Clean domain (remove protocol, paths, etc.)
                    domain = re.sub(r'^https?://', '', domain)
                    domain = re.sub(r'/.*$', '', domain)
                    domains.add(domain.lower())
                    
            except Exception as e:
                self.logger.warning("Error parsing domain entry", error=str(e))
        
        return domains
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string into datetime object"""
        if not date_str:
            return None
        
        # Try common date formats
        date_formats = [
            '%Y-%m-%d',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%d %H:%M:%S'
        ]
        
        for fmt in date_formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        self.logger.warning("Could not parse date", date_str=date_str)
        return None
    
    def update_data(self) -> bool:
        """Update CryptoScamDB data from GitHub"""
        try:
            self.logger.info("Updating CryptoScamDB data from GitHub")
            
            # Clear existing data
            self.scam_addresses.clear()
            self.scam_domains.clear()
            
            success_count = 0
            total_reports = 0
            
            # Fetch address data
            address_data = self._fetch_github_file(self.DATA_PATHS['addresses'])
            if address_data:
                address_reports = self._parse_address_data(address_data)
                
                # Index by address
                for report in address_reports:
                    for address in report.addresses:
                        address_lower = address.lower()
                        if address_lower not in self.scam_addresses:
                            self.scam_addresses[address_lower] = []
                        self.scam_addresses[address_lower].append(report)
                
                total_reports += len(address_reports)
                success_count += 1
                
                self.logger.info("Loaded address reports", count=len(address_reports))
            
            # Fetch domain data
            domain_data = self._fetch_github_file(self.DATA_PATHS['domains'])
            if domain_data:
                domains = self._parse_domain_data(domain_data)
                self.scam_domains.update(domains)
                success_count += 1
                
                self.logger.info("Loaded scam domains", count=len(domains))
            
            # Update timestamp
            self.last_update = datetime.utcnow()
            
            # Cache the results
            cache_data = {
                'scam_addresses': {
                    addr: [
                        {
                            'id': r.id,
                            'addresses': r.addresses,
                            'scam_type': r.scam_type,
                            'category': r.category,
                            'description': r.description,
                            'domain': r.domain,
                            'confidence': r.confidence,
                            'source': r.source
                        } for r in reports
                    ] for addr, reports in self.scam_addresses.items()
                },
                'scam_domains': list(self.scam_domains),
                'last_update': self.last_update.isoformat(),
                'total_reports': total_reports
            }
            
            self.cache_result('cryptoscamdb_data', cache_data)
            
            self.logger.info(
                "CryptoScamDB data update completed",
                success_count=success_count,
                total_files=len(self.DATA_PATHS),
                total_reports=total_reports,
                unique_addresses=len(self.scam_addresses),
                unique_domains=len(self.scam_domains)
            )
            
            return success_count > 0
            
        except Exception as e:
            self.logger.error("Error updating CryptoScamDB data", error=str(e))
            return False
    
    def load_cached_data(self) -> bool:
        """Load cached CryptoScamDB data"""
        cached_data = self.get_cached_result('cryptoscamdb_data')
        if not cached_data:
            return False
        
        try:
            # Reconstruct scam addresses
            self.scam_addresses.clear()
            addresses_data = cached_data.get('scam_addresses', {})
            
            for address, reports_data in addresses_data.items():
                reports = []
                for report_data in reports_data:
                    report = ScamReport(
                        id=report_data.get('id'),
                        addresses=report_data.get('addresses', []),
                        scam_type=report_data.get('scam_type'),
                        category=report_data.get('category'),
                        description=report_data.get('description'),
                        domain=report_data.get('domain'),
                        confidence=report_data.get('confidence', 0.7),
                        source=report_data.get('source', 'cryptoscamdb')
                    )
                    reports.append(report)
                
                self.scam_addresses[address] = reports
            
            # Reconstruct scam domains
            self.scam_domains = set(cached_data.get('scam_domains', []))
            
            # Parse last update time
            last_update_str = cached_data.get('last_update')
            if last_update_str:
                self.last_update = datetime.fromisoformat(last_update_str)
            
            self.logger.info(
                "Loaded cached CryptoScamDB data",
                addresses=len(self.scam_addresses),
                domains=len(self.scam_domains),
                cache_age_hours=(datetime.utcnow() - self.last_update).total_seconds() / 3600 if self.last_update else None
            )
            
            return True
            
        except Exception as e:
            self.logger.error("Error loading cached CryptoScamDB data", error=str(e))
            return False
    
    def should_update(self) -> bool:
        """Check if data should be updated"""
        if not self.last_update:
            return True
        
        source_config = self.config.get('data_sources', {}).get(self.source_name, {})
        update_interval = source_config.get('update_interval_hours', 6)  # Default 6 hours for community data
        
        return datetime.utcnow() - self.last_update > timedelta(hours=update_interval)
    
    def ensure_data_loaded(self) -> bool:
        """Ensure CryptoScamDB data is loaded and up to date"""
        # Try loading cached data first
        if self.load_cached_data() and not self.should_update():
            return True
        
        # Update data if needed
        return self.update_data()
    
    def collect_address_data(self, address: str) -> Optional[Dict[str, Any]]:
        """Check if address appears in CryptoScamDB reports"""
        # Ensure data is loaded
        if not self.ensure_data_loaded():
            self.logger.error("Failed to load CryptoScamDB data")
            return None
        
        # Normalize address
        address_lower = address.lower().strip()
        
        # Look up in scam database
        reports = self.scam_addresses.get(address_lower, [])
        
        if not reports:
            return {
                'address': address,
                'found_in_database': False,
                'reports': [],
                'source': self.source_name,
                'last_updated': self.last_update.isoformat() if self.last_update else None
            }
        
        # Convert reports to dict format
        report_dicts = []
        for report in reports:
            report_dict = {
                'id': report.id,
                'scam_type': report.scam_type,
                'category': report.category,
                'description': report.description,
                'domain': report.domain,
                'confidence': report.confidence,
                'risk_level': report.risk_level.value,
                'report_date': report.report_date.isoformat() if report.report_date else None
            }
            report_dicts.append(report_dict)
        
        return {
            'address': address,
            'found_in_database': True,
            'report_count': len(reports),
            'reports': report_dicts,
            'highest_risk_level': max(report.risk_level.value for report in reports),
            'average_confidence': sum(report.confidence for report in reports) / len(reports),
            'source': self.source_name,
            'last_updated': self.last_update.isoformat() if self.last_update else None
        }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse CryptoScamDB data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_in_database'):
            return risk_factors
        
        reports = raw_data.get('reports', [])
        if not reports:
            return risk_factors
        
        # Create risk factors for each unique report type
        report_types = {}
        for report in reports:
            report_type = report.get('category', 'Unknown')
            if report_type not in report_types:
                report_types[report_type] = {
                    'count': 0,
                    'max_confidence': 0,
                    'descriptions': [],
                    'risk_level': report.get('risk_level', 'high')
                }
            
            report_types[report_type]['count'] += 1
            report_types[report_type]['max_confidence'] = max(
                report_types[report_type]['max_confidence'],
                report.get('confidence', 0.7)
            )
            
            if report.get('description'):
                report_types[report_type]['descriptions'].append(report['description'])
        
        # Create risk factor for each report type
        for report_type, info in report_types.items():
            # Map to our risk levels
            if info['risk_level'] == 'critical':
                severity = RiskLevel.CRITICAL
                weight = 0.9
            elif info['risk_level'] == 'high':
                severity = RiskLevel.HIGH
                weight = 0.8
            elif info['risk_level'] == 'medium':
                severity = RiskLevel.MEDIUM
                weight = 0.6
            else:
                severity = RiskLevel.HIGH  # Default for community reports
                weight = 0.7
            
            # Build description
            if info['count'] == 1:
                description = f"Address reported for {report_type.lower()}"
            else:
                description = f"Address reported {info['count']} times for {report_type.lower()}"
            
            # Add sample description if available
            if info['descriptions']:
                sample_desc = info['descriptions'][0][:100]
                description += f": {sample_desc}..."
            
            risk_factor = RiskFactor(
                source=self.source_name,
                factor_type="community_report",
                severity=severity,
                weight=weight,
                description=description,
                reference_url="https://cryptoscamdb.org/",
                confidence=info['max_confidence'],
                report_count=info['count']
            )
            
            risk_factors.append(risk_factor)
        
        return risk_factors
    
    def search_by_domain(self, domain: str) -> bool:
        """Check if domain is in scam database"""
        if not self.ensure_data_loaded():
            return False
        
        domain_lower = domain.lower().strip()
        return domain_lower in self.scam_domains
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about CryptoScamDB data"""
        if not self.ensure_data_loaded():
            return {'error': 'Failed to load data'}
        
        # Analyze data
        total_reports = sum(len(reports) for reports in self.scam_addresses.values())
        
        category_counts = {}
        scam_type_counts = {}
        
        for reports in self.scam_addresses.values():
            for report in reports:
                category = report.category or 'Unknown'
                category_counts[category] = category_counts.get(category, 0) + 1
                
                scam_type = report.scam_type or 'unknown'
                scam_type_counts[scam_type] = scam_type_counts.get(scam_type, 0) + 1
        
        return {
            'unique_addresses': len(self.scam_addresses),
            'total_reports': total_reports,
            'scam_domains': len(self.scam_domains),
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'category_breakdown': category_counts,
            'scam_type_breakdown': scam_type_counts,
            'top_categories': sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_scam_types': sorted(scam_type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        }