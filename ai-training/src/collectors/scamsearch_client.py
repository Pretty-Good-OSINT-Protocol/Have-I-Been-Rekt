"""
ScamSearch.io API Client - integrates with ScamSearch.io global scammer database.

Data Source: https://scamsearch.io/
Contains 4M+ scammer entries including emails, usernames, phone numbers,
websites, and crypto addresses aggregated from public reports and dark web sources.

Note: ScamSearch.io has both free and paid tiers with different rate limits.
"""

from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
import logging

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType
from ..utils.logging import LoggingMixin


@dataclass
class ScamSearchEntry:
    """Represents a scammer entry from ScamSearch.io"""
    entry_id: Optional[str] = None
    scammer_name: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    crypto_address: Optional[str] = None
    scam_type: Optional[str] = None
    description: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    report_count: int = 1
    confidence_score: float = 0.7
    verified: bool = False
    
    @property
    def risk_level(self) -> RiskLevel:
        """Determine risk level based on verification and scam type"""
        if self.verified and self.report_count > 5:
            return RiskLevel.HIGH
        elif self.scam_type in ['cryptocurrency', 'investment', 'ransomware']:
            return RiskLevel.HIGH
        elif self.scam_type in ['phishing', 'romance', 'tech_support']:
            return RiskLevel.MEDIUM
        elif self.report_count > 10:
            return RiskLevel.HIGH
        else:
            return RiskLevel.MEDIUM
    
    @property
    def age_days(self) -> Optional[int]:
        """Calculate age of entry in days"""
        if self.first_seen:
            return (datetime.utcnow() - self.first_seen).days
        return None


class ScamSearchClient(BaseDataCollector, LoggingMixin):
    """Client for ScamSearch.io global scammer database"""
    
    BASE_URL = "https://scamsearch.io/api"
    
    # API endpoints
    SEARCH_ENDPOINT = f"{BASE_URL}/search"
    LOOKUP_ENDPOINT = f"{BASE_URL}/lookup"
    STATS_ENDPOINT = f"{BASE_URL}/stats"
    
    # Search types supported
    SEARCH_TYPES = {
        'email': 'email',
        'username': 'username', 
        'phone': 'phone',
        'website': 'website',
        'crypto': 'crypto_address',
        'all': 'all'
    }
    
    # Scam categories
    SCAM_CATEGORIES = {
        'cryptocurrency': {
            'risk_level': RiskLevel.HIGH,
            'weight': 0.8,
            'description': 'Cryptocurrency-related scams'
        },
        'investment': {
            'risk_level': RiskLevel.HIGH,
            'weight': 0.8,
            'description': 'Investment and financial scams'
        },
        'phishing': {
            'risk_level': RiskLevel.HIGH,
            'weight': 0.7,
            'description': 'Phishing and credential theft'
        },
        'romance': {
            'risk_level': RiskLevel.MEDIUM,
            'weight': 0.6,
            'description': 'Romance and dating scams'
        },
        'tech_support': {
            'risk_level': RiskLevel.MEDIUM,
            'weight': 0.6,
            'description': 'Tech support scams'
        },
        'ransomware': {
            'risk_level': RiskLevel.CRITICAL,
            'weight': 0.9,
            'description': 'Ransomware and extortion'
        }
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # API configuration
        self.api_key = config.get('api_keys', {}).get('scamsearch')
        self.subscription_tier = 'free'  # free, basic, premium
        
        # Rate limiting based on subscription tier
        self.rate_limits = {
            'free': {'requests_per_day': 100, 'requests_per_hour': 10},
            'basic': {'requests_per_day': 1000, 'requests_per_hour': 100},
            'premium': {'requests_per_day': 10000, 'requests_per_hour': 1000}
        }
        
        # Track API usage
        self.requests_today = 0
        self.requests_this_hour = 0
        self.usage_reset_time = datetime.utcnow()
        
        if not self.api_key:
            self.logger.warning("No ScamSearch.io API key configured - limited functionality")
    
    @property
    def source_name(self) -> str:
        return "scamsearch"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.SCAM_DATABASE
    
    def _get_headers(self) -> Dict[str, str]:
        """Get API request headers"""
        headers = {
            'User-Agent': 'HaveIBeenRekt-OSINT/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        
        return headers
    
    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits"""
        now = datetime.utcnow()
        
        # Reset counters if needed
        if (now - self.usage_reset_time).total_seconds() >= 3600:  # 1 hour
            self.requests_this_hour = 0
            self.usage_reset_time = now
        
        if now.date() != self.usage_reset_time.date():  # New day
            self.requests_today = 0
        
        # Check limits
        current_limits = self.rate_limits.get(self.subscription_tier, self.rate_limits['free'])
        
        if self.requests_today >= current_limits['requests_per_day']:
            self.logger.warning("Daily rate limit exceeded", 
                              requests_today=self.requests_today,
                              daily_limit=current_limits['requests_per_day'])
            return False
        
        if self.requests_this_hour >= current_limits['requests_per_hour']:
            self.logger.warning("Hourly rate limit exceeded",
                              requests_this_hour=self.requests_this_hour,
                              hourly_limit=current_limits['requests_per_hour'])
            return False
        
        return True
    
    def _make_api_request(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Make API request with rate limiting and error handling"""
        if not self._check_rate_limit():
            return None
        
        headers = self._get_headers()
        
        try:
            response = self.make_request(
                url=endpoint,
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response:
                # Update usage counters
                self.requests_today += 1
                self.requests_this_hour += 1
                
                # Check for API errors
                if 'error' in response:
                    self.logger.error("ScamSearch API error", error=response['error'])
                    return None
                
                return response
            
        except Exception as e:
            self.logger.error("ScamSearch API request failed", endpoint=endpoint, error=str(e))
        
        return None
    
    def search_crypto_address(self, address: str) -> List[ScamSearchEntry]:
        """Search for crypto address in ScamSearch database"""
        if not self.api_key:
            self.logger.warning("Cannot search - no API key configured")
            return []
        
        # Check cache first
        cache_key = f"crypto_search_{address}"
        cached_result = self.get_cached_result(cache_key)
        if cached_result:
            return [ScamSearchEntry(**entry_data) for entry_data in cached_result]
        
        params = {
            'q': address,
            'type': 'crypto_address',
            'limit': 100  # Maximum results
        }
        
        try:
            self.logger.info("Searching ScamSearch for crypto address", address=address[:10] + "...")
            
            response = self._make_api_request(self.SEARCH_ENDPOINT, params)
            
            if not response:
                return []
            
            entries = self._parse_search_results(response)
            
            # Cache the results
            cache_data = [
                {
                    'entry_id': entry.entry_id,
                    'scammer_name': entry.scammer_name,
                    'email': entry.email,
                    'crypto_address': entry.crypto_address,
                    'scam_type': entry.scam_type,
                    'description': entry.description,
                    'report_count': entry.report_count,
                    'confidence_score': entry.confidence_score,
                    'verified': entry.verified,
                    'first_seen': entry.first_seen.isoformat() if entry.first_seen else None,
                    'last_seen': entry.last_seen.isoformat() if entry.last_seen else None
                } for entry in entries
            ]
            self.cache_result(cache_key, cache_data)
            
            self.logger.info("ScamSearch crypto search completed",
                           address=address[:10] + "...",
                           entries_found=len(entries))
            
            return entries
            
        except Exception as e:
            self.logger.error("Error searching ScamSearch for crypto address", 
                            address=address, error=str(e))
            return []
    
    def search_email(self, email: str) -> List[ScamSearchEntry]:
        """Search for email address in ScamSearch database"""
        if not self.api_key:
            return []
        
        cache_key = f"email_search_{email}"
        cached_result = self.get_cached_result(cache_key)
        if cached_result:
            return [ScamSearchEntry(**entry_data) for entry_data in cached_result]
        
        params = {
            'q': email,
            'type': 'email',
            'limit': 100
        }
        
        try:
            response = self._make_api_request(self.SEARCH_ENDPOINT, params)
            if not response:
                return []
            
            entries = self._parse_search_results(response)
            
            # Cache results
            cache_data = [self._entry_to_dict(entry) for entry in entries]
            self.cache_result(cache_key, cache_data)
            
            return entries
            
        except Exception as e:
            self.logger.error("Error searching ScamSearch for email", email=email, error=str(e))
            return []
    
    def cross_reference_search(self, identifiers: Dict[str, str]) -> List[ScamSearchEntry]:
        """Cross-reference multiple identifiers (email, username, crypto address, etc.)"""
        all_entries = []
        seen_entry_ids = set()
        
        for id_type, id_value in identifiers.items():
            if id_type == 'email':
                entries = self.search_email(id_value)
            elif id_type == 'crypto_address':
                entries = self.search_crypto_address(id_value)
            else:
                # Generic search for other types
                entries = self._generic_search(id_type, id_value)
            
            # Deduplicate entries
            for entry in entries:
                if entry.entry_id and entry.entry_id not in seen_entry_ids:
                    all_entries.append(entry)
                    seen_entry_ids.add(entry.entry_id)
        
        return all_entries
    
    def _generic_search(self, search_type: str, query: str) -> List[ScamSearchEntry]:
        """Generic search for various identifier types"""
        if not self.api_key or search_type not in self.SEARCH_TYPES:
            return []
        
        params = {
            'q': query,
            'type': self.SEARCH_TYPES.get(search_type, 'all'),
            'limit': 50
        }
        
        try:
            response = self._make_api_request(self.SEARCH_ENDPOINT, params)
            if response:
                return self._parse_search_results(response)
        except Exception as e:
            self.logger.error("Generic search failed", search_type=search_type, error=str(e))
        
        return []
    
    def _parse_search_results(self, response: Dict[str, Any]) -> List[ScamSearchEntry]:
        """Parse ScamSearch API response into ScamSearchEntry objects"""
        entries = []
        
        results = response.get('results', [])
        if not results:
            return entries
        
        for result in results:
            try:
                entry = ScamSearchEntry(
                    entry_id=result.get('id'),
                    scammer_name=result.get('name'),
                    email=result.get('email'),
                    username=result.get('username'),
                    phone=result.get('phone'),
                    website=result.get('website'),
                    crypto_address=result.get('crypto_address'),
                    scam_type=result.get('scam_type', 'unknown'),
                    description=result.get('description'),
                    first_seen=self._parse_date(result.get('first_seen')),
                    last_seen=self._parse_date(result.get('last_seen')),
                    report_count=result.get('report_count', 1),
                    confidence_score=result.get('confidence', 0.7),
                    verified=result.get('verified', False)
                )
                
                entries.append(entry)
                
            except Exception as e:
                self.logger.warning("Error parsing ScamSearch entry", 
                                  entry_id=result.get('id'), error=str(e))
        
        return entries
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string into datetime object"""
        if not date_str:
            return None
        
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
        
        return None
    
    def _entry_to_dict(self, entry: ScamSearchEntry) -> Dict[str, Any]:
        """Convert ScamSearchEntry to dictionary for caching"""
        return {
            'entry_id': entry.entry_id,
            'scammer_name': entry.scammer_name,
            'email': entry.email,
            'username': entry.username,
            'phone': entry.phone,
            'website': entry.website,
            'crypto_address': entry.crypto_address,
            'scam_type': entry.scam_type,
            'description': entry.description,
            'report_count': entry.report_count,
            'confidence_score': entry.confidence_score,
            'verified': entry.verified,
            'first_seen': entry.first_seen.isoformat() if entry.first_seen else None,
            'last_seen': entry.last_seen.isoformat() if entry.last_seen else None
        }
    
    def collect_address_data(self, address: str) -> Optional[Dict[str, Any]]:
        """Collect ScamSearch data for a crypto address"""
        entries = self.search_crypto_address(address)
        
        if not entries:
            return {
                'address': address,
                'found_in_scamsearch': False,
                'entries': [],
                'source': self.source_name
            }
        
        # Convert entries to dict format
        entry_dicts = [self._entry_to_dict(entry) for entry in entries]
        
        # Calculate summary statistics
        total_reports = sum(entry.report_count for entry in entries)
        verified_entries = len([entry for entry in entries if entry.verified])
        scam_types = list(set(entry.scam_type for entry in entries if entry.scam_type))
        
        return {
            'address': address,
            'found_in_scamsearch': True,
            'entry_count': len(entries),
            'entries': entry_dicts,
            'total_reports': total_reports,
            'verified_entries': verified_entries,
            'scam_types': scam_types,
            'highest_risk_level': max(entry.risk_level.value for entry in entries),
            'average_confidence': sum(entry.confidence_score for entry in entries) / len(entries),
            'source': self.source_name
        }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse ScamSearch data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_in_scamsearch'):
            return risk_factors
        
        entries = raw_data.get('entries', [])
        if not entries:
            return risk_factors
        
        # Group by scam type
        scam_type_groups = {}
        for entry in entries:
            scam_type = entry.get('scam_type', 'unknown')
            if scam_type not in scam_type_groups:
                scam_type_groups[scam_type] = {
                    'count': 0,
                    'total_reports': 0,
                    'max_confidence': 0,
                    'verified_count': 0
                }
            
            group = scam_type_groups[scam_type]
            group['count'] += 1
            group['total_reports'] += entry.get('report_count', 1)
            group['max_confidence'] = max(group['max_confidence'], entry.get('confidence_score', 0.7))
            if entry.get('verified', False):
                group['verified_count'] += 1
        
        # Create risk factors
        for scam_type, group_info in scam_type_groups.items():
            # Determine severity based on scam type and verification
            category_info = self.SCAM_CATEGORIES.get(scam_type, {
                'risk_level': RiskLevel.MEDIUM,
                'weight': 0.6,
                'description': f'{scam_type} scam activity'
            })
            
            severity = category_info['risk_level']
            base_weight = category_info['weight']
            
            # Increase weight based on verification and report count
            weight_multiplier = 1.0
            if group_info['verified_count'] > 0:
                weight_multiplier += 0.2
            if group_info['total_reports'] > 10:
                weight_multiplier += 0.1
            
            final_weight = min(1.0, base_weight * weight_multiplier)
            
            # Build description
            if group_info['count'] == 1:
                description = f"Address found in ScamSearch database for {scam_type}"
            else:
                description = f"Address found {group_info['count']} times in ScamSearch for {scam_type}"
            
            if group_info['verified_count'] > 0:
                description += f" ({group_info['verified_count']} verified reports)"
            
            risk_factor = RiskFactor(
                source=self.source_name,
                factor_type="global_scammer_database",
                severity=severity,
                weight=final_weight,
                description=description,
                reference_url="https://scamsearch.io/",
                confidence=group_info['max_confidence'],
                report_count=group_info['total_reports']
            )
            
            risk_factors.append(risk_factor)
        
        return risk_factors
    
    def get_usage_statistics(self) -> Dict[str, Any]:
        """Get API usage statistics"""
        current_limits = self.rate_limits.get(self.subscription_tier, self.rate_limits['free'])
        
        return {
            'api_key_configured': bool(self.api_key),
            'subscription_tier': self.subscription_tier,
            'requests_today': self.requests_today,
            'requests_this_hour': self.requests_this_hour,
            'daily_limit': current_limits['requests_per_day'],
            'hourly_limit': current_limits['requests_per_hour'],
            'daily_remaining': max(0, current_limits['requests_per_day'] - self.requests_today),
            'hourly_remaining': max(0, current_limits['requests_per_hour'] - self.requests_this_hour)
        }
    
    def validate_api_key(self) -> bool:
        """Validate API key by making a test request"""
        if not self.api_key:
            return False
        
        try:
            # Make a simple search request
            response = self._make_api_request(self.STATS_ENDPOINT)
            return response is not None and 'error' not in response
            
        except Exception as e:
            self.logger.error("API key validation failed", error=str(e))
            return False