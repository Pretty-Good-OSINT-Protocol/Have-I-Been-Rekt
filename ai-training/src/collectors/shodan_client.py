"""
Shodan API Client - Integration with Shodan for infrastructure and device intelligence
related to cryptocurrency addresses and associated infrastructure.
"""

import requests
import ipaddress
import socket
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timezone
from dataclasses import dataclass
import logging
import re

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin


@dataclass
class ShodanService:
    """Represents a service found on Shodan"""
    ip: str
    port: int
    protocol: str
    service: str
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    vulnerabilities: List[str] = None
    location: Dict[str, Any] = None
    organization: Optional[str] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.location is None:
            self.location = {}


@dataclass
class ShodanIntelligence:
    """Comprehensive infrastructure intelligence from Shodan"""
    target: str
    target_type: str  # 'ip', 'domain', 'crypto_infrastructure'
    found_services: List[ShodanService]
    total_services: int
    open_ports: List[int]
    vulnerabilities: List[str]
    crypto_related_services: List[ShodanService]
    suspicious_indicators: List[str]
    threat_score: float
    countries: Set[str]
    organizations: Set[str]
    last_seen: Optional[datetime] = None
    
    def __post_init__(self):
        if isinstance(self.countries, list):
            self.countries = set(self.countries)
        if isinstance(self.organizations, list):
            self.organizations = set(self.organizations)


class ShodanClient(BaseDataCollector, LoggingMixin):
    """
    Client for Shodan infrastructure intelligence API.
    Provides device and service information related to cryptocurrency infrastructure.
    """
    
    BASE_URL = "https://api.shodan.io"
    
    # Cryptocurrency-related services and ports
    CRYPTO_INDICATORS = {
        'bitcoin': {
            'ports': [8333, 8332, 18333, 18332],
            'services': ['bitcoin', 'bitcoin-rpc'],
            'products': ['bitcoin-core', 'bitcoind'],
            'banners': ['bitcoin', 'satoshi', 'btc']
        },
        'ethereum': {
            'ports': [30303, 8545, 8546, 8547],
            'services': ['ethereum', 'geth', 'parity'],
            'products': ['geth', 'parity-ethereum', 'ethereum'],
            'banners': ['ethereum', 'geth', 'parity', 'eth']
        },
        'monero': {
            'ports': [18080, 18081],
            'services': ['monero', 'monerod'],
            'products': ['monero'],
            'banners': ['monero', 'xmr']
        },
        'mining': {
            'ports': [4444, 3333, 9999, 14444],
            'services': ['stratum', 'mining'],
            'products': ['stratum-mining', 'mining-pool'],
            'banners': ['stratum', 'mining', 'pool', 'hashrate']
        }
    }
    
    # Suspicious service indicators
    SUSPICIOUS_INDICATORS = {
        'tor': ['tor', 'onion', 'hidden service'],
        'proxy': ['proxy', 'socks', 'http-proxy'],
        'vpn': ['openvpn', 'wireguard', 'vpn'],
        'anonymizer': ['anonymizer', 'privacy'],
        'malware': ['botnet', 'c2', 'command-and-control', 'backdoor'],
        'suspicious_crypto': ['cryptojacking', 'miner', 'coinhive']
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # API Configuration
        self.api_key = config.get('shodan_api_key')
        self.timeout = config.get('shodan_timeout', 30)
        self.max_results = config.get('shodan_max_results', 100)
        
        # Rate limiting (Shodan allows various limits based on plan)
        self.requests_per_second = config.get('shodan_rate_limit', 1)
        
        if not self.api_key:
            self.logger.warning("Shodan API key not configured")
            return
        
        self.logger.info("Shodan client initialized")
    
    @property
    def source_name(self) -> str:
        return "shodan"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.COMMERCIAL
    
    def is_configured(self) -> bool:
        """Check if Shodan is properly configured"""
        return bool(self.api_key)
    
    def search_host(self, ip: str) -> Optional[ShodanIntelligence]:
        """
        Get detailed information about a specific host.
        
        Args:
            ip: IP address to investigate
            
        Returns:
            ShodanIntelligence with host information
        """
        if not self.is_configured():
            return None
        
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            
            # Check cache
            cache_key = f"shodan_host_{ip}"
            cached_result = self.get_cached_result(cache_key, max_age_hours=6)
            
            if cached_result:
                return self._deserialize_intelligence(cached_result)
            
            # Rate limiting
            if not self.check_rate_limit():
                return None
            
            # API request
            url = f"{self.BASE_URL}/shodan/host/{ip}"
            params = {'key': self.api_key}
            
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            intelligence = self._process_host_data(ip, data)
            
            # Cache result
            if intelligence:
                self.cache_result(cache_key, self._serialize_intelligence(intelligence))
            
            self.logger.info(f"Shodan host lookup completed for {ip}: {len(intelligence.found_services) if intelligence else 0} services")
            
            return intelligence
            
        except ipaddress.AddressValueError:
            self.logger.warning(f"Invalid IP address: {ip}")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Shodan API request failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Shodan host search error: {e}")
            return None
    
    def search_cryptocurrency_infrastructure(self, query: str) -> Optional[List[ShodanIntelligence]]:
        """
        Search for cryptocurrency-related infrastructure.
        
        Args:
            query: Search query (e.g., 'bitcoin', 'ethereum mining')
            
        Returns:
            List of ShodanIntelligence results
        """
        if not self.is_configured():
            return None
        
        try:
            cache_key = f"shodan_crypto_search_{hash(query)}"
            cached_result = self.get_cached_result(cache_key, max_age_hours=12)
            
            if cached_result:
                return [self._deserialize_intelligence(intel) for intel in cached_result]
            
            if not self.check_rate_limit():
                return None
            
            # API request
            url = f"{self.BASE_URL}/shodan/host/search"
            params = {
                'key': self.api_key,
                'query': query,
                'limit': min(self.max_results, 100)
            }
            
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            results = []
            
            for match in data.get('matches', []):
                ip = match.get('ip_str')
                if ip:
                    intelligence = self._process_host_data(ip, match, is_search_result=True)
                    if intelligence:
                        results.append(intelligence)
            
            # Cache results
            if results:
                serialized = [self._serialize_intelligence(intel) for intel in results]
                self.cache_result(cache_key, serialized)
            
            self.logger.info(f"Shodan crypto search completed: {len(results)} results")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Shodan crypto search error: {e}")
            return None
    
    def resolve_domain_and_search(self, domain: str) -> Optional[ShodanIntelligence]:
        """
        Resolve domain to IP and search Shodan.
        
        Args:
            domain: Domain name to resolve and search
            
        Returns:
            ShodanIntelligence for the resolved IP
        """
        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(domain)
            self.logger.debug(f"Resolved {domain} to {ip}")
            
            # Search the IP
            intelligence = self.search_host(ip)
            
            if intelligence:
                # Add domain context
                intelligence.target = f"{domain} ({ip})"
                intelligence.target_type = 'domain'
            
            return intelligence
            
        except socket.gaierror:
            self.logger.warning(f"Could not resolve domain: {domain}")
            return None
        except Exception as e:
            self.logger.error(f"Domain resolution error: {e}")
            return None
    
    def _process_host_data(self, ip: str, data: Dict, is_search_result: bool = False) -> Optional[ShodanIntelligence]:
        """Process Shodan host data into structured intelligence"""
        
        try:
            services = []
            crypto_services = []
            open_ports = []
            vulnerabilities = set()
            suspicious_indicators = []
            countries = set()
            organizations = set()
            
            # Process services data
            service_data = data.get('data', []) if is_search_result else [data]
            
            for service_info in service_data:
                port = service_info.get('port')
                if port:
                    open_ports.append(port)
                
                service = ShodanService(
                    ip=ip,
                    port=port or 0,
                    protocol=service_info.get('transport', 'tcp'),
                    service=service_info.get('product', 'unknown'),
                    product=service_info.get('product'),
                    version=service_info.get('version'),
                    banner=service_info.get('data', '')[:500],  # Limit banner size
                    vulnerabilities=service_info.get('vulns', []),
                    location=service_info.get('location', {}),
                    organization=service_info.get('org')
                )
                
                services.append(service)
                
                # Check for crypto-related services
                if self._is_crypto_related_service(service):
                    crypto_services.append(service)
                
                # Collect vulnerabilities
                if service.vulnerabilities:
                    vulnerabilities.update(service.vulnerabilities)
                
                # Collect location data
                if service.location:
                    country = service.location.get('country_name')
                    if country:
                        countries.add(country)
                
                # Collect organizations
                if service.organization:
                    organizations.add(service.organization)
                
                # Check for suspicious indicators
                suspicious = self._check_suspicious_indicators(service)
                suspicious_indicators.extend(suspicious)
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(services, vulnerabilities, suspicious_indicators)
            
            intelligence = ShodanIntelligence(
                target=ip,
                target_type='ip',
                found_services=services,
                total_services=len(services),
                open_ports=sorted(list(set(open_ports))),
                vulnerabilities=list(vulnerabilities),
                crypto_related_services=crypto_services,
                suspicious_indicators=list(set(suspicious_indicators)),
                threat_score=threat_score,
                countries=countries,
                organizations=organizations,
                last_seen=datetime.now(timezone.utc)
            )
            
            return intelligence
            
        except Exception as e:
            self.logger.error(f"Error processing Shodan host data: {e}")
            return None
    
    def _is_crypto_related_service(self, service: ShodanService) -> bool:
        """Check if service is cryptocurrency-related"""
        
        for crypto_type, indicators in self.CRYPTO_INDICATORS.items():
            # Check ports
            if service.port in indicators['ports']:
                return True
            
            # Check service names
            if service.service.lower() in [s.lower() for s in indicators['services']]:
                return True
            
            # Check products
            if service.product and service.product.lower() in [p.lower() for p in indicators['products']]:
                return True
            
            # Check banner content
            if service.banner:
                banner_lower = service.banner.lower()
                for keyword in indicators['banners']:
                    if keyword in banner_lower:
                        return True
        
        return False
    
    def _check_suspicious_indicators(self, service: ShodanService) -> List[str]:
        """Check for suspicious service indicators"""
        
        indicators = []
        
        for indicator_type, keywords in self.SUSPICIOUS_INDICATORS.items():
            # Check service name
            if service.service.lower() in [k.lower() for k in keywords]:
                indicators.append(indicator_type)
                continue
            
            # Check product
            if service.product and any(k.lower() in service.product.lower() for k in keywords):
                indicators.append(indicator_type)
                continue
            
            # Check banner
            if service.banner:
                banner_lower = service.banner.lower()
                if any(k in banner_lower for k in keywords):
                    indicators.append(indicator_type)
        
        return indicators
    
    def _calculate_threat_score(self, services: List[ShodanService], vulnerabilities: Set[str], 
                               suspicious_indicators: List[str]) -> float:
        """Calculate overall threat score"""
        
        score = 0.0
        
        # Base score from number of services
        score += min(0.2, len(services) * 0.01)
        
        # Vulnerability score
        score += min(0.4, len(vulnerabilities) * 0.05)
        
        # Suspicious indicators score
        score += min(0.3, len(suspicious_indicators) * 0.1)
        
        # High-risk port bonus
        high_risk_ports = [22, 23, 3389, 1433, 3306]  # SSH, Telnet, RDP, SQL Server, MySQL
        exposed_high_risk = sum(1 for service in services if service.port in high_risk_ports)
        score += min(0.1, exposed_high_risk * 0.05)
        
        return min(1.0, score)
    
    def _serialize_intelligence(self, intelligence: ShodanIntelligence) -> Dict:
        """Serialize intelligence for caching"""
        return {
            'target': intelligence.target,
            'target_type': intelligence.target_type,
            'total_services': intelligence.total_services,
            'open_ports': intelligence.open_ports,
            'vulnerability_count': len(intelligence.vulnerabilities),
            'crypto_services_count': len(intelligence.crypto_related_services),
            'suspicious_indicators': intelligence.suspicious_indicators,
            'threat_score': intelligence.threat_score,
            'countries': list(intelligence.countries),
            'organizations': list(intelligence.organizations),
            'last_seen': intelligence.last_seen.isoformat() if intelligence.last_seen else None
        }
    
    def _deserialize_intelligence(self, cached_data: Dict) -> ShodanIntelligence:
        """Deserialize cached intelligence (simplified version)"""
        return ShodanIntelligence(
            target=cached_data['target'],
            target_type=cached_data['target_type'],
            found_services=[],  # Not cached for performance
            total_services=cached_data['total_services'],
            open_ports=cached_data['open_ports'],
            vulnerabilities=[],  # Count only in cache
            crypto_related_services=[],  # Count only in cache
            suspicious_indicators=cached_data['suspicious_indicators'],
            threat_score=cached_data['threat_score'],
            countries=set(cached_data['countries']),
            organizations=set(cached_data['organizations']),
            last_seen=datetime.fromisoformat(cached_data['last_seen']) if cached_data['last_seen'] else None
        )
    
    def lookup_address(self, target: str) -> Optional[Dict[str, Any]]:
        """
        Standard lookup interface for IP addresses or domains.
        
        Args:
            target: IP address or domain to investigate
            
        Returns:
            Dictionary with Shodan infrastructure data
        """
        # Determine if target is IP or domain
        try:
            ipaddress.ip_address(target)
            intelligence = self.search_host(target)
        except ipaddress.AddressValueError:
            # Assume it's a domain
            intelligence = self.resolve_domain_and_search(target)
        
        if not intelligence:
            return None
        
        return {
            'target': target,
            'found_shodan_data': True,
            'timestamp': datetime.utcnow().isoformat(),
            'infrastructure_intelligence': {
                'total_services': intelligence.total_services,
                'open_ports': intelligence.open_ports,
                'crypto_related_services': len(intelligence.crypto_related_services),
                'vulnerability_count': len(intelligence.vulnerabilities),
                'suspicious_indicators': intelligence.suspicious_indicators,
                'threat_score': intelligence.threat_score,
                'countries': list(intelligence.countries),
                'organizations': list(intelligence.organizations)
            },
            'risk_assessment': self._assess_infrastructure_risk(intelligence)
        }
    
    def _assess_infrastructure_risk(self, intelligence: ShodanIntelligence) -> Dict[str, Any]:
        """Assess risk based on infrastructure intelligence"""
        
        risk_score = intelligence.threat_score
        risk_indicators = []
        
        # High-risk indicators
        if len(intelligence.vulnerabilities) > 5:
            risk_indicators.append('multiple_vulnerabilities')
        
        if len(intelligence.crypto_related_services) > 0:
            risk_indicators.append('crypto_infrastructure')
        
        if 'tor' in intelligence.suspicious_indicators:
            risk_indicators.append('tor_infrastructure')
        
        if 'malware' in intelligence.suspicious_indicators:
            risk_indicators.append('malware_infrastructure')
            risk_score += 0.3
        
        # Geographic risk factors
        high_risk_countries = ['CN', 'RU', 'IR', 'KP']  # Example list
        if any(country in intelligence.countries for country in high_risk_countries):
            risk_indicators.append('high_risk_geography')
            risk_score += 0.1
        
        risk_score = min(1.0, risk_score)
        
        # Determine risk level
        if risk_score >= 0.8:
            risk_level = 'critical'
        elif risk_score >= 0.6:
            risk_level = 'high'
        elif risk_score >= 0.3:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'confidence': 0.85,  # Shodan is reliable but infrastructure can change
            'primary_concerns': risk_indicators,
            'infrastructure_type': 'crypto_related' if intelligence.crypto_related_services else 'general'
        }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], target: str) -> List[RiskFactor]:
        """Parse Shodan data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_shodan_data'):
            return risk_factors
        
        infra_intel = raw_data.get('infrastructure_intelligence', {})
        risk_assessment = raw_data.get('risk_assessment', {})
        
        # Main infrastructure risk factor
        risk_level = self._get_risk_level_enum(risk_assessment.get('risk_level', 'low'))
        
        open_ports = infra_intel.get('open_ports', [])
        vuln_count = infra_intel.get('vulnerability_count', 0)
        suspicious = infra_intel.get('suspicious_indicators', [])
        
        description = f"Infrastructure analysis: {len(open_ports)} open ports"
        if vuln_count > 0:
            description += f", {vuln_count} vulnerabilities"
        if suspicious:
            description += f", suspicious indicators: {', '.join(suspicious)}"
        
        risk_factors.append(RiskFactor(
            type="infrastructure_analysis",
            description=description,
            risk_level=risk_level,
            confidence=risk_assessment.get('confidence', 0.85),
            source=DataSourceType.COMMERCIAL,
            raw_data={
                'open_ports': open_ports[:10],  # Limit for size
                'vulnerability_count': vuln_count,
                'suspicious_indicators': suspicious,
                'threat_score': infra_intel.get('threat_score', 0)
            }
        ))
        
        # Crypto infrastructure factor
        crypto_services = infra_intel.get('crypto_related_services', 0)
        if crypto_services > 0:
            risk_factors.append(RiskFactor(
                type="cryptocurrency_infrastructure",
                description=f"Cryptocurrency infrastructure detected: {crypto_services} related services",
                risk_level=RiskLevel.MEDIUM,
                confidence=0.9,
                source=DataSourceType.COMMERCIAL,
                raw_data={'crypto_services_count': crypto_services}
            ))
        
        # High vulnerability count
        if vuln_count > 5:
            risk_factors.append(RiskFactor(
                type="high_vulnerability_exposure",
                description=f"High vulnerability exposure: {vuln_count} known vulnerabilities",
                risk_level=RiskLevel.HIGH,
                confidence=0.95,
                source=DataSourceType.COMMERCIAL,
                raw_data={'vulnerability_count': vuln_count}
            ))
        
        return risk_factors
    
    def _get_risk_level_enum(self, risk_level_str: str) -> RiskLevel:
        """Convert string risk level to enum"""
        mapping = {
            'critical': RiskLevel.CRITICAL,
            'high': RiskLevel.HIGH,
            'medium': RiskLevel.MEDIUM,
            'low': RiskLevel.LOW
        }
        return mapping.get(risk_level_str, RiskLevel.LOW)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get Shodan client statistics"""
        return {
            'configured': self.is_configured(),
            'rate_limit_per_second': self.requests_per_second,
            'max_results_per_query': self.max_results,
            'crypto_indicators_tracked': len(self.CRYPTO_INDICATORS),
            'suspicious_indicators_tracked': len(self.SUSPICIOUS_INDICATORS),
            'api_endpoint': self.BASE_URL
        }