"""
DeHashed API Client - Integration with DeHashed breach intelligence service
for comprehensive breach data beyond HIBP coverage.
"""

import requests
import base64
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
import logging

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin


@dataclass
class DeHashedBreach:
    """Represents a breach record from DeHashed"""
    id: str
    email: str
    username: Optional[str] = None
    password: Optional[str] = None
    hashed_password: Optional[str] = None
    name: Optional[str] = None
    vin: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    database_name: Optional[str] = None
    obtained_from: Optional[str] = None


@dataclass
class DeHashedIntelligence:
    """Comprehensive intelligence from DeHashed"""
    email: str
    found_breaches: List[DeHashedBreach]
    total_records: int
    exposed_passwords: List[str]
    exposed_personal_info: Dict[str, Any]
    database_sources: List[str]
    first_breach_date: Optional[datetime] = None
    latest_breach_date: Optional[datetime] = None


class DeHashedClient(BaseDataCollector, LoggingMixin):
    """
    Client for DeHashed breach intelligence API.
    Provides comprehensive breach data beyond HIBP coverage.
    """
    
    BASE_URL = "https://api.dehashed.com/search"
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # API Configuration
        self.email = config.get('dehashed_email')
        self.api_key = config.get('dehashed_api_key')
        self.timeout = config.get('dehashed_timeout', 30)
        self.max_results = config.get('dehashed_max_results', 1000)
        
        # Rate limiting (DeHashed allows up to 50 requests per minute)
        self.requests_per_minute = 45  # Conservative limit
        self.rate_limit_window = 60  # seconds
        
        if not self.email or not self.api_key:
            self.logger.warning("DeHashed email/API key not configured")
            return
        
        # Setup authentication
        self.auth_header = base64.b64encode(f"{self.email}:{self.api_key}".encode()).decode()
        
        self.logger.info("DeHashed client initialized")
    
    @property
    def source_name(self) -> str:
        return "dehashed"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.COMMERCIAL
    
    def is_configured(self) -> bool:
        """Check if DeHashed is properly configured"""
        return bool(self.email and self.api_key)
    
    def search_email(self, email: str) -> Optional[DeHashedIntelligence]:
        """
        Search for email address breaches in DeHashed.
        
        Args:
            email: Email address to search
            
        Returns:
            DeHashedIntelligence with breach data
        """
        if not self.is_configured():
            self.logger.warning("DeHashed not configured, skipping search")
            return None
        
        try:
            # Check cache first
            cache_key = f"dehashed_email_{hashlib.md5(email.lower().encode()).hexdigest()}"
            cached_result = self.get_cached_result(cache_key, max_age_hours=24)
            
            if cached_result:
                self.logger.debug(f"Using cached DeHashed result for {email}")
                return self._deserialize_intelligence(cached_result)
            
            # Rate limiting
            if not self.check_rate_limit():
                self.logger.warning("DeHashed rate limit exceeded")
                return None
            
            # API Request
            headers = {
                'Authorization': f'Basic {self.auth_header}',
                'Accept': 'application/json'
            }
            
            params = {
                'query': f'email:{email}',
                'size': self.max_results
            }
            
            self.logger.debug(f"Searching DeHashed for email: {email}")
            
            response = requests.get(
                self.BASE_URL,
                headers=headers,
                params=params,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            # Process results
            intelligence = self._process_search_results(email, data)
            
            # Cache results
            if intelligence:
                self.cache_result(cache_key, self._serialize_intelligence(intelligence))
            
            self.logger.info(f"DeHashed search completed for {email}: {intelligence.total_records if intelligence else 0} records")
            
            return intelligence
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"DeHashed API request failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"DeHashed search error: {e}")
            return None
    
    def search_username(self, username: str) -> Optional[DeHashedIntelligence]:
        """Search for username breaches"""
        if not self.is_configured():
            return None
        
        try:
            cache_key = f"dehashed_user_{hashlib.md5(username.lower().encode()).hexdigest()}"
            cached_result = self.get_cached_result(cache_key, max_age_hours=24)
            
            if cached_result:
                return self._deserialize_intelligence(cached_result)
            
            if not self.check_rate_limit():
                return None
            
            headers = {
                'Authorization': f'Basic {self.auth_header}',
                'Accept': 'application/json'
            }
            
            params = {
                'query': f'username:{username}',
                'size': self.max_results
            }
            
            response = requests.get(
                self.BASE_URL,
                headers=headers,
                params=params,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            intelligence = self._process_search_results(username, data)
            
            if intelligence:
                self.cache_result(cache_key, self._serialize_intelligence(intelligence))
            
            return intelligence
            
        except Exception as e:
            self.logger.error(f"DeHashed username search error: {e}")
            return None
    
    def _process_search_results(self, search_term: str, api_data: Dict) -> Optional[DeHashedIntelligence]:
        """Process API response into structured intelligence"""
        
        try:
            entries = api_data.get('entries', [])
            total = api_data.get('total', 0)
            
            if total == 0:
                return None
            
            breaches = []
            exposed_passwords = set()
            exposed_info = {
                'names': set(),
                'addresses': set(),
                'phones': set(),
                'usernames': set()
            }
            database_sources = set()
            breach_dates = []
            
            for entry in entries:
                # Create breach record
                breach = DeHashedBreach(
                    id=entry.get('id', ''),
                    email=entry.get('email', ''),
                    username=entry.get('username'),
                    password=entry.get('password'),
                    hashed_password=entry.get('hashed_password'),
                    name=entry.get('name'),
                    vin=entry.get('vin'),
                    address=entry.get('address'),
                    phone=entry.get('phone'),
                    database_name=entry.get('database_name'),
                    obtained_from=entry.get('obtained_from')
                )
                
                breaches.append(breach)
                
                # Collect exposed data
                if breach.password:
                    exposed_passwords.add(breach.password)
                
                if breach.name:
                    exposed_info['names'].add(breach.name)
                
                if breach.address:
                    exposed_info['addresses'].add(breach.address)
                
                if breach.phone:
                    exposed_info['phones'].add(breach.phone)
                
                if breach.username:
                    exposed_info['usernames'].add(breach.username)
                
                if breach.database_name:
                    database_sources.add(breach.database_name)
                
                # Try to parse date from obtained_from or database_name
                # This is heuristic as DeHashed doesn't always provide structured dates
            
            # Convert sets to lists
            for key in exposed_info:
                exposed_info[key] = list(exposed_info[key])
            
            intelligence = DeHashedIntelligence(
                email=search_term,
                found_breaches=breaches,
                total_records=total,
                exposed_passwords=list(exposed_passwords),
                exposed_personal_info=exposed_info,
                database_sources=list(database_sources),
                first_breach_date=None,  # Would need additional parsing
                latest_breach_date=None
            )
            
            return intelligence
            
        except Exception as e:
            self.logger.error(f"Error processing DeHashed results: {e}")
            return None
    
    def _serialize_intelligence(self, intelligence: DeHashedIntelligence) -> Dict:
        """Serialize intelligence for caching"""
        return {
            'email': intelligence.email,
            'total_records': intelligence.total_records,
            'exposed_passwords_count': len(intelligence.exposed_passwords),
            'exposed_info_summary': {k: len(v) for k, v in intelligence.exposed_personal_info.items()},
            'database_sources': intelligence.database_sources,
            'breach_count': len(intelligence.found_breaches)
        }
    
    def _deserialize_intelligence(self, cached_data: Dict) -> DeHashedIntelligence:
        """Deserialize cached intelligence (simplified version)"""
        return DeHashedIntelligence(
            email=cached_data['email'],
            found_breaches=[],  # Not cached for performance
            total_records=cached_data['total_records'],
            exposed_passwords=[],  # Not cached for security
            exposed_personal_info={},  # Not cached for privacy
            database_sources=cached_data['database_sources']
        )
    
    def lookup_address(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Standard lookup interface for email addresses.
        
        Args:
            email: Email address to look up
            
        Returns:
            Dictionary with DeHashed breach data
        """
        intelligence = self.search_email(email)
        
        if not intelligence:
            return None
        
        return {
            'email': email,
            'found_dehashed_data': True,
            'timestamp': datetime.utcnow().isoformat(),
            'total_records': intelligence.total_records,
            'database_count': len(intelligence.database_sources),
            'exposed_passwords_count': len(intelligence.exposed_passwords),
            'exposed_personal_info': intelligence.exposed_personal_info,
            'database_sources': intelligence.database_sources,
            'risk_assessment': self._assess_breach_risk(intelligence)
        }
    
    def _assess_breach_risk(self, intelligence: DeHashedIntelligence) -> Dict[str, Any]:
        """Assess risk based on breach intelligence"""
        
        risk_score = 0.0
        risk_indicators = []
        
        # Base risk from number of records
        if intelligence.total_records > 0:
            risk_score = min(0.9, 0.3 + (intelligence.total_records / 100) * 0.1)
        
        # Password exposure increases risk
        if len(intelligence.exposed_passwords) > 0:
            risk_score += 0.3
            risk_indicators.append('exposed_passwords')
        
        # Personal information exposure
        personal_info_types = sum(1 for info_list in intelligence.exposed_personal_info.values() if info_list)
        if personal_info_types > 2:
            risk_score += 0.2
            risk_indicators.append('extensive_personal_data')
        
        # Multiple database sources indicate broader exposure
        if len(intelligence.database_sources) > 3:
            risk_score += 0.1
            risk_indicators.append('multiple_breach_sources')
        
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
            'confidence': 0.9,  # DeHashed is highly reliable
            'primary_concerns': risk_indicators,
            'breach_severity': 'high' if len(intelligence.exposed_passwords) > 0 else 'medium'
        }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse DeHashed data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_dehashed_data'):
            return risk_factors
        
        total_records = raw_data.get('total_records', 0)
        risk_assessment = raw_data.get('risk_assessment', {})
        exposed_passwords = raw_data.get('exposed_passwords_count', 0)
        database_sources = raw_data.get('database_sources', [])
        
        # Main breach exposure factor
        risk_level = self._get_risk_level_enum(risk_assessment.get('risk_level', 'low'))
        
        description = f"Found in {total_records} breach records across {len(database_sources)} databases"
        if exposed_passwords > 0:
            description += f" with {exposed_passwords} exposed passwords"
        
        risk_factors.append(RiskFactor(
            type="dehashed_breach_exposure",
            description=description,
            risk_level=risk_level,
            confidence=risk_assessment.get('confidence', 0.9),
            source=DataSourceType.COMMERCIAL,
            raw_data={
                'total_records': total_records,
                'exposed_passwords_count': exposed_passwords,
                'database_sources': database_sources[:5],  # Limit for size
                'breach_severity': risk_assessment.get('breach_severity')
            }
        ))
        
        # High exposure factor
        if total_records > 10:
            risk_factors.append(RiskFactor(
                type="extensive_breach_exposure",
                description=f"Extensive breach exposure: {total_records} records found",
                risk_level=RiskLevel.HIGH if total_records > 50 else RiskLevel.MEDIUM,
                confidence=0.95,
                source=DataSourceType.COMMERCIAL,
                raw_data={'record_count': total_records}
            ))
        
        # Password exposure factor
        if exposed_passwords > 0:
            risk_factors.append(RiskFactor(
                type="password_exposure",
                description=f"Passwords exposed in breaches: {exposed_passwords} instances",
                risk_level=RiskLevel.HIGH,
                confidence=0.95,
                source=DataSourceType.COMMERCIAL,
                raw_data={'exposed_password_count': exposed_passwords}
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
        """Get DeHashed client statistics"""
        return {
            'configured': self.is_configured(),
            'rate_limit_window': self.rate_limit_window,
            'max_results_per_query': self.max_results,
            'cache_enabled': hasattr(self, 'cache'),
            'api_endpoint': self.BASE_URL
        }