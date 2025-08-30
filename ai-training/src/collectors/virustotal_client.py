"""
VirusTotal OSINT Client - integrates with VirusTotal for malware intelligence.

Provides:
- Address/URL search in malware configurations
- Phishing URL detection containing crypto addresses
- Malware family attribution
- Cryptostealer configuration analysis
- IoC (Indicators of Compromise) extraction
"""

from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timezone
from dataclasses import dataclass
import requests
import time
import json
import re
import base64
from urllib.parse import quote

from ..data_collector import BaseDataCollector
from ..utils.logging import get_logger


@dataclass
class MalwareDetection:
    """Malware detection from VirusTotal"""
    
    file_hash: str
    detection_names: List[str]
    malware_families: List[str]
    first_seen: datetime
    last_seen: datetime
    detection_ratio: str  # e.g., "45/70"
    contained_addresses: List[str]
    contained_urls: List[str]
    file_type: str
    file_size: int
    confidence: float


@dataclass
class PhishingURL:
    """Phishing URL containing crypto addresses"""
    
    url: str
    detected_addresses: List[str]
    malware_families: List[str]
    detection_engines: List[str]
    first_seen: datetime
    last_seen: datetime
    threat_categories: List[str]
    confidence: float


@dataclass
class CryptostealerConfig:
    """Cryptostealer malware configuration"""
    
    malware_family: str
    config_hash: str
    target_wallets: List[str]
    c2_servers: List[str]
    targeted_currencies: List[str]
    clipboard_monitoring: bool
    keylogger_enabled: bool
    screenshot_capture: bool
    extraction_timestamp: datetime


@dataclass
class VirusTotalIntelligence:
    """Comprehensive VirusTotal intelligence report"""
    
    address_or_url: str
    found_in_malware: bool
    malware_detections: List[MalwareDetection]
    phishing_urls: List[PhishingURL]
    cryptostealer_configs: List[CryptostealerConfig]
    threat_assessment: Dict[str, Any]
    related_indicators: Set[str]
    analysis_timestamp: datetime


class VirusTotalClient(BaseDataCollector):
    """
    VirusTotal API client for malware and threat intelligence.
    
    Searches VirusTotal database for:
    - Cryptocurrency addresses in malware configurations
    - Phishing URLs containing target addresses
    - Malware family attribution and IoCs
    - Cryptostealer and clipper malware analysis
    """
    
    VT_API_BASE = "https://www.virustotal.com/api/v3"
    
    # Common cryptostealer families
    CRYPTOSTEALER_FAMILIES = {
        'clipper', 'cryptostealer', 'redline', 'azorult', 'raccoon',
        'vidar', 'mars', 'lokibot', 'formbook', 'agentTesla',
        'predator', 'worldwind', 'blacknet', 'phoenix', 'atomic'
    }
    
    # Cryptocurrency patterns for extraction
    CRYPTO_PATTERNS = {
        'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        'ethereum': r'\b0x[a-fA-F0-9]{40}\b',
        'litecoin': r'\bL[a-km-zA-HJ-NP-Z1-9]{26,33}\b',
        'monero': r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
        'dash': r'\bX[1-9A-HJ-NP-Za-km-z]{33}\b',
        'zcash': r'\bt1[a-zA-Z0-9]{33}\b'
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: str):
        super().__init__(config, cache_dir, "virustotal_client")
        
        self.logger = get_logger(f"{__name__}.VirusTotalClient")
        
        # Load configuration
        crime_config = config.get('historical_crime_data', {})
        vt_config = crime_config.get('virustotal', {})
        
        self.api_key = vt_config.get('api_key')
        self.subscription_type = vt_config.get('subscription', 'public')  # public, private, premium
        self.enable_file_search = vt_config.get('enable_file_search', True)
        self.enable_url_search = vt_config.get('enable_url_search', True)
        self.max_results_per_query = vt_config.get('max_results', 100)
        
        # Rate limiting based on subscription
        rate_limits = {
            'public': 4,      # 4 requests per minute
            'private': 1000,  # 1000 requests per minute
            'premium': 10000  # 10000 requests per minute
        }
        
        requests_per_minute = rate_limits.get(self.subscription_type, 4)
        self.request_delay = 60.0 / requests_per_minute
        
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                'x-apikey': self.api_key,
                'Content-Type': 'application/json'
            })
        
        self.logger.info(f"Initialized VirusTotal Client (subscription: {self.subscription_type})")
    
    def _make_vt_request(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Make rate-limited request to VirusTotal API"""
        
        if not self.api_key:
            self.logger.error("VirusTotal API key required")
            return None
        
        # Rate limiting
        time.sleep(self.request_delay)
        
        url = f"{self.VT_API_BASE}/{endpoint}"
        
        try:
            self.logger.debug(f"Making VirusTotal API request: {endpoint}")
            
            response = self.session.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 204:
                # No content - valid response
                return {'data': []}
            elif response.status_code == 400:
                self.logger.error(f"VirusTotal API: Bad request")
                return None
            elif response.status_code == 401:
                self.logger.error(f"VirusTotal API: Unauthorized - check API key")
                return None
            elif response.status_code == 403:
                self.logger.error(f"VirusTotal API: Forbidden - insufficient privileges")
                return None
            elif response.status_code == 404:
                # Not found - return empty result
                return {'data': []}
            elif response.status_code == 429:
                self.logger.warning(f"VirusTotal API: Rate limited")
                time.sleep(60)  # Back off for rate limiting
                return None
            else:
                self.logger.error(f"VirusTotal API error: HTTP {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"VirusTotal API request failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error in VirusTotal request: {e}")
            return None
    
    def search_files_by_content(self, search_query: str) -> List[MalwareDetection]:
        """
        Search for files containing specific content.
        
        Args:
            search_query: Search query (e.g., crypto address)
            
        Returns:
            List of malware detections containing the query
        """
        
        if not self.enable_file_search:
            return []
        
        detections = []
        
        try:
            # Use VirusTotal Intelligence search
            params = {
                'query': f'content:"{search_query}"',
                'limit': min(self.max_results_per_query, 300)
            }
            
            response = self._make_vt_request('intelligence/search', params)
            
            if not response or 'data' not in response:
                return detections
            
            for item in response['data']:
                detection = self._parse_file_detection(item, search_query)
                if detection:
                    detections.append(detection)
            
            self.logger.info(f"Found {len(detections)} file detections for query: {search_query[:20]}...")
            
        except Exception as e:
            self.logger.error(f"Error searching files by content: {e}")
        
        return detections
    
    def search_urls_containing_address(self, address: str) -> List[PhishingURL]:
        """
        Search for URLs containing cryptocurrency address.
        
        Args:
            address: Cryptocurrency address to search for
            
        Returns:
            List of phishing URLs containing the address
        """
        
        if not self.enable_url_search:
            return []
        
        phishing_urls = []
        
        try:
            # Search for URLs containing the address
            params = {
                'query': f'url:"{address}"',
                'limit': min(self.max_results_per_query, 100)
            }
            
            response = self._make_vt_request('intelligence/search', params)
            
            if not response or 'data' not in response:
                return phishing_urls
            
            for item in response['data']:
                if item.get('type') == 'url':
                    phishing_url = self._parse_url_detection(item, address)
                    if phishing_url:
                        phishing_urls.append(phishing_url)
            
            self.logger.info(f"Found {len(phishing_urls)} URLs containing address: {address[:10]}...")
            
        except Exception as e:
            self.logger.error(f"Error searching URLs: {e}")
        
        return phishing_urls
    
    def analyze_cryptostealer_configs(self, address: str) -> List[CryptostealerConfig]:
        """
        Analyze cryptostealer malware configurations for target addresses.
        
        Args:
            address: Target cryptocurrency address
            
        Returns:
            List of cryptostealer configurations targeting the address
        """
        
        configs = []
        
        try:
            # Search for cryptostealer malware containing the address
            for family in self.CRYPTOSTEALER_FAMILIES:
                params = {
                    'query': f'tag:{family} content:"{address}"',
                    'limit': 50
                }
                
                response = self._make_vt_request('intelligence/search', params)
                
                if response and 'data' in response:
                    for item in response['data']:
                        config = self._extract_cryptostealer_config(item, family, address)
                        if config:
                            configs.append(config)
            
            self.logger.info(f"Found {len(configs)} cryptostealer configs for address: {address[:10]}...")
            
        except Exception as e:
            self.logger.error(f"Error analyzing cryptostealer configs: {e}")
        
        return configs
    
    def _parse_file_detection(self, vt_item: Dict[str, Any], search_query: str) -> Optional[MalwareDetection]:
        """Parse VirusTotal file detection item"""
        
        try:
            attributes = vt_item.get('attributes', {})
            
            # Extract detection information
            last_analysis = attributes.get('last_analysis_stats', {})
            detection_ratio = f"{last_analysis.get('malicious', 0)}/{last_analysis.get('malicious', 0) + last_analysis.get('undetected', 0)}"
            
            # Extract malware families from detection names
            detections = attributes.get('last_analysis_results', {})
            detection_names = []
            malware_families = set()
            
            for engine, result in detections.items():
                if result.get('category') == 'malicious':
                    detection_name = result.get('result', '')
                    detection_names.append(f"{engine}: {detection_name}")
                    
                    # Extract malware family
                    family = self._extract_malware_family(detection_name)
                    if family:
                        malware_families.add(family)
            
            # Extract embedded addresses/URLs
            contained_addresses = self._extract_crypto_addresses(str(vt_item))
            contained_urls = self._extract_urls(str(vt_item))
            
            detection = MalwareDetection(
                file_hash=vt_item.get('id', ''),
                detection_names=detection_names[:10],  # Top 10 detections
                malware_families=list(malware_families),
                first_seen=self._parse_timestamp(attributes.get('first_submission_date')),
                last_seen=self._parse_timestamp(attributes.get('last_submission_date')),
                detection_ratio=detection_ratio,
                contained_addresses=contained_addresses,
                contained_urls=contained_urls,
                file_type=attributes.get('type_description', ''),
                file_size=attributes.get('size', 0),
                confidence=0.8 if last_analysis.get('malicious', 0) > 5 else 0.6
            )
            
            return detection
            
        except Exception as e:
            self.logger.error(f"Error parsing file detection: {e}")
            return None
    
    def _parse_url_detection(self, vt_item: Dict[str, Any], address: str) -> Optional[PhishingURL]:
        """Parse VirusTotal URL detection item"""
        
        try:
            attributes = vt_item.get('attributes', {})
            
            url = attributes.get('url', '')
            
            # Extract detection engines that flagged this URL
            detections = attributes.get('last_analysis_results', {})
            detection_engines = []
            threat_categories = set()
            
            for engine, result in detections.items():
                if result.get('category') in ['malicious', 'suspicious']:
                    detection_engines.append(engine)
                    
                    # Categorize threat
                    result_text = result.get('result', '').lower()
                    if 'phishing' in result_text:
                        threat_categories.add('phishing')
                    elif 'malware' in result_text:
                        threat_categories.add('malware')
                    elif 'scam' in result_text:
                        threat_categories.add('scam')
            
            # Extract all crypto addresses from URL
            detected_addresses = self._extract_crypto_addresses(url)
            if address not in detected_addresses:
                detected_addresses.append(address)
            
            # Extract potential malware families
            malware_families = []
            for detection in detection_engines:
                family = self._extract_malware_family(str(detections.get(detection, {})))
                if family:
                    malware_families.append(family)
            
            phishing_url = PhishingURL(
                url=url,
                detected_addresses=detected_addresses,
                malware_families=list(set(malware_families)),
                detection_engines=detection_engines,
                first_seen=self._parse_timestamp(attributes.get('first_submission_date')),
                last_seen=self._parse_timestamp(attributes.get('last_submission_date')),
                threat_categories=list(threat_categories),
                confidence=0.9 if len(detection_engines) > 3 else 0.7
            )
            
            return phishing_url
            
        except Exception as e:
            self.logger.error(f"Error parsing URL detection: {e}")
            return None
    
    def _extract_cryptostealer_config(self, vt_item: Dict[str, Any], family: str, target_address: str) -> Optional[CryptostealerConfig]:
        """Extract cryptostealer configuration from malware sample"""
        
        try:
            attributes = vt_item.get('attributes', {})
            
            # Extract configuration data (this would require actual malware analysis)
            # For now, we'll use heuristics based on available data
            
            # Extract wallet addresses from content
            content_str = str(vt_item)
            target_wallets = self._extract_crypto_addresses(content_str)
            
            # Extract C2 servers (simplified)
            c2_servers = self._extract_urls(content_str)
            
            # Determine targeted currencies
            targeted_currencies = []
            for currency, pattern in self.CRYPTO_PATTERNS.items():
                if re.search(pattern, content_str):
                    targeted_currencies.append(currency)
            
            config = CryptostealerConfig(
                malware_family=family,
                config_hash=vt_item.get('id', ''),
                target_wallets=target_wallets,
                c2_servers=c2_servers,
                targeted_currencies=targeted_currencies,
                clipboard_monitoring=True,  # Most cryptostealers have this
                keylogger_enabled='keylog' in content_str.lower(),
                screenshot_capture='screenshot' in content_str.lower(),
                extraction_timestamp=datetime.now(timezone.utc)
            )
            
            return config
            
        except Exception as e:
            self.logger.error(f"Error extracting cryptostealer config: {e}")
            return None
    
    def _extract_malware_family(self, detection_text: str) -> Optional[str]:
        """Extract malware family from detection text"""
        
        detection_lower = detection_text.lower()
        
        # Check for known cryptostealer families
        for family in self.CRYPTOSTEALER_FAMILIES:
            if family in detection_lower:
                return family
        
        # Extract generic family patterns
        family_patterns = [
            r'trojan[./](\w+)',
            r'banker[./](\w+)',
            r'stealer[./](\w+)',
            r'clipper[./](\w+)',
            r'(\w+)stealer',
            r'(\w+)clipper'
        ]
        
        for pattern in family_patterns:
            match = re.search(pattern, detection_lower)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_crypto_addresses(self, text: str) -> List[str]:
        """Extract cryptocurrency addresses from text"""
        
        addresses = []
        
        for currency, pattern in self.CRYPTO_PATTERNS.items():
            matches = re.findall(pattern, text)
            addresses.extend(matches)
        
        return list(set(addresses))  # Remove duplicates
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        
        url_pattern = r'https?://[^\s<>"\']+|ftp://[^\s<>"\']+|www\.[^\s<>"\']+\.[a-z]{2,}'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        
        return list(set(urls))  # Remove duplicates
    
    def _parse_timestamp(self, timestamp: Optional[int]) -> datetime:
        """Parse Unix timestamp to datetime"""
        
        if timestamp:
            try:
                return datetime.fromtimestamp(timestamp, tz=timezone.utc)
            except (ValueError, TypeError):
                pass
        
        return datetime.now(timezone.utc)
    
    def analyze_address_threats(self, address: str) -> Optional[VirusTotalIntelligence]:
        """
        Perform comprehensive threat analysis for an address.
        
        Args:
            address: Cryptocurrency address to analyze
            
        Returns:
            VirusTotalIntelligence with comprehensive threat assessment
        """
        
        cache_key = f"vt_analysis_{address}"
        cached_result = self.get_cached_result(cache_key, max_age_hours=24)
        
        if cached_result:
            # Reconstruct objects from cache
            cached_result['analysis_timestamp'] = datetime.fromisoformat(cached_result['analysis_timestamp'])
            # Would need to reconstruct nested objects for full implementation
            return cached_result  # Simplified for now
        
        self.logger.info(f"Analyzing address threats with VirusTotal: {address}")
        
        try:
            # Search for malware containing the address
            malware_detections = self.search_files_by_content(address)
            
            # Search for phishing URLs containing the address
            phishing_urls = self.search_urls_containing_address(address)
            
            # Analyze cryptostealer configurations
            cryptostealer_configs = self.analyze_cryptostealer_configs(address)
            
            # Assess overall threat level
            threat_assessment = self._assess_threat_level(malware_detections, phishing_urls, cryptostealer_configs)
            
            # Collect related indicators
            related_indicators = set()
            for detection in malware_detections:
                related_indicators.update(detection.contained_addresses)
                related_indicators.update(detection.contained_urls)
            
            for url in phishing_urls:
                related_indicators.update(url.detected_addresses)
                related_indicators.add(url.url)
            
            # Remove the target address from related indicators
            related_indicators.discard(address)
            
            intelligence = VirusTotalIntelligence(
                address_or_url=address,
                found_in_malware=len(malware_detections) > 0 or len(cryptostealer_configs) > 0,
                malware_detections=malware_detections,
                phishing_urls=phishing_urls,
                cryptostealer_configs=cryptostealer_configs,
                threat_assessment=threat_assessment,
                related_indicators=related_indicators,
                analysis_timestamp=datetime.now(timezone.utc)
            )
            
            # Cache results (simplified)
            cache_data = {
                'address_or_url': intelligence.address_or_url,
                'found_in_malware': intelligence.found_in_malware,
                'malware_detection_count': len(intelligence.malware_detections),
                'phishing_url_count': len(intelligence.phishing_urls),
                'cryptostealer_config_count': len(intelligence.cryptostealer_configs),
                'threat_assessment': intelligence.threat_assessment,
                'related_indicators_count': len(intelligence.related_indicators),
                'analysis_timestamp': intelligence.analysis_timestamp.isoformat()
            }
            
            self.cache_result(cache_key, cache_data)
            
            return intelligence
            
        except Exception as e:
            self.logger.error(f"Error analyzing address threats: {e}")
            return None
    
    def _assess_threat_level(self, malware_detections: List[MalwareDetection], 
                           phishing_urls: List[PhishingURL], 
                           cryptostealer_configs: List[CryptostealerConfig]) -> Dict[str, Any]:
        """Assess overall threat level based on detections"""
        
        threat_score = 0.0
        threat_indicators = []
        
        # Malware detections contribute to threat score
        if malware_detections:
            threat_score += min(len(malware_detections) * 0.3, 0.6)
            threat_indicators.append(f"{len(malware_detections)} malware detection(s)")
            
            # Higher score for cryptostealer families
            for detection in malware_detections:
                if any(family in self.CRYPTOSTEALER_FAMILIES for family in detection.malware_families):
                    threat_score += 0.2
                    threat_indicators.append("Cryptostealer malware detected")
                    break
        
        # Phishing URLs increase threat score
        if phishing_urls:
            threat_score += min(len(phishing_urls) * 0.2, 0.4)
            threat_indicators.append(f"{len(phishing_urls)} phishing URL(s)")
        
        # Cryptostealer configs are high threat
        if cryptostealer_configs:
            threat_score += min(len(cryptostealer_configs) * 0.4, 0.8)
            threat_indicators.append(f"{len(cryptostealer_configs)} cryptostealer config(s)")
        
        # Determine threat level
        if threat_score >= 0.8:
            threat_level = 'critical'
        elif threat_score >= 0.6:
            threat_level = 'high'
        elif threat_score >= 0.3:
            threat_level = 'medium'
        else:
            threat_level = 'low'
        
        return {
            'threat_level': threat_level,
            'threat_score': min(threat_score, 1.0),
            'threat_indicators': threat_indicators,
            'confidence': 0.8 if len(malware_detections) > 0 else 0.6,
            'primary_threats': [
                'malware' if malware_detections else None,
                'phishing' if phishing_urls else None,
                'cryptostealer' if cryptostealer_configs else None
            ]
        }
    
    def lookup_address(self, address: str) -> Dict[str, Any]:
        """
        Main interface for VirusTotal threat analysis.
        
        Args:
            address: Cryptocurrency address to analyze
            
        Returns:
            Dictionary containing VirusTotal analysis results
        """
        
        try:
            self.logger.info(f"Starting VirusTotal analysis: {address[:10]}...")
            
            intelligence = self.analyze_address_threats(address)
            
            if not intelligence:
                return {
                    'found_virustotal_data': False,
                    'error': 'Failed to analyze address threats'
                }
            
            # Build result dictionary
            result = {
                'found_virustotal_data': True,
                'found_in_malware': intelligence.found_in_malware,
                'malware_detection_count': len(intelligence.malware_detections),
                'phishing_url_count': len(intelligence.phishing_urls),
                'cryptostealer_config_count': len(intelligence.cryptostealer_configs),
                'threat_assessment': intelligence.threat_assessment,
                'related_indicators_count': len(intelligence.related_indicators),
                'malware_families': list(set([
                    family for detection in intelligence.malware_detections 
                    for family in detection.malware_families
                ])),
                'analysis_timestamp': intelligence.analysis_timestamp.isoformat()
            }
            
            self.logger.info(f"VirusTotal analysis completed: {address[:10]}... (threats: {intelligence.found_in_malware})")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in VirusTotal analysis for {address}: {e}")
            return {
                'found_virustotal_data': False,
                'error': str(e)
            }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List:
        """Parse VirusTotal data into risk factors for ML training"""
        
        # Import here to avoid circular imports
        from ..data_collector import RiskFactor, RiskLevel, DataSourceType
        
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_virustotal_data'):
            return risk_factors
        
        if raw_data.get('found_in_malware'):
            threat_assessment = raw_data.get('threat_assessment', {})
            threat_level_str = threat_assessment.get('threat_level', 'medium')
            threat_score = threat_assessment.get('threat_score', 0.5)
            
            # Map threat level to RiskLevel enum
            threat_level_map = {
                'low': RiskLevel.LOW,
                'medium': RiskLevel.MEDIUM,
                'high': RiskLevel.HIGH,
                'critical': RiskLevel.CRITICAL
            }
            
            risk_level = threat_level_map.get(threat_level_str, RiskLevel.MEDIUM)
            
            # Main malware association risk
            risk_factors.append(RiskFactor(
                type="malware_association",
                description=f"Address found in malware/phishing content",
                risk_level=risk_level,
                confidence=threat_assessment.get('confidence', 0.8),
                source=DataSourceType.THREAT_INTELLIGENCE,
                raw_data={'threat_score': threat_score, 'threat_indicators': threat_assessment.get('threat_indicators', [])}
            ))
            
            # Cryptostealer specific risk
            cryptostealer_count = raw_data.get('cryptostealer_config_count', 0)
            if cryptostealer_count > 0:
                risk_factors.append(RiskFactor(
                    type="cryptostealer_target",
                    description=f"Address targeted by {cryptostealer_count} cryptostealer(s)",
                    risk_level=RiskLevel.CRITICAL,
                    confidence=0.9,
                    source=DataSourceType.THREAT_INTELLIGENCE,
                    raw_data={'cryptostealer_configs': cryptostealer_count}
                ))
            
            # Phishing URL risk
            phishing_count = raw_data.get('phishing_url_count', 0)
            if phishing_count > 0:
                risk_factors.append(RiskFactor(
                    type="phishing_url_association",
                    description=f"Address found in {phishing_count} phishing URL(s)",
                    risk_level=RiskLevel.HIGH,
                    confidence=0.85,
                    source=DataSourceType.THREAT_INTELLIGENCE,
                    raw_data={'phishing_urls': phishing_count}
                ))
        
        return risk_factors
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get VirusTotal client statistics"""
        
        return {
            'api_key_configured': bool(self.api_key),
            'subscription_type': self.subscription_type,
            'requests_per_minute': int(60.0 / self.request_delay),
            'file_search_enabled': self.enable_file_search,
            'url_search_enabled': self.enable_url_search,
            'max_results_per_query': self.max_results_per_query,
            'supported_cryptostealer_families': len(self.CRYPTOSTEALER_FAMILIES),
            'cache_entries': len(self.cache) if hasattr(self.cache, '__len__') else 'unknown'
        }