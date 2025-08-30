"""
Have I Been Pwned API Client - integrates with HIBP for breach detection.

Provides:
- Email breach lookup
- Password hash checking
- Domain breach monitoring
- Breach metadata and context
- Rate limiting and API key management
"""

from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timezone
from dataclasses import dataclass
import requests
import time
import hashlib
from urllib.parse import quote

from ..data_collector import BaseDataCollector
from ..utils.logging import get_logger


@dataclass
class BreachInfo:
    """Information about a data breach"""
    
    name: str
    title: str
    domain: str
    breach_date: datetime
    added_date: datetime
    modified_date: datetime
    pwn_count: int
    description: str
    data_classes: List[str]  # Types of data compromised
    is_verified: bool
    is_fabricated: bool
    is_sensitive: bool
    is_retired: bool
    is_spam_list: bool
    logo_path: Optional[str] = None


@dataclass
class PasteInfo:
    """Information about a paste containing email"""
    
    source: str
    id: str
    title: Optional[str]
    date: Optional[datetime]
    email_count: int


@dataclass
class BreachAnalysis:
    """Results from HIBP breach analysis"""
    
    email_address: str
    total_breaches: int
    total_pwn_count: int
    breaches: List[BreachInfo]
    pastes: List[PasteInfo]
    risk_assessment: Dict[str, Any]
    analysis_timestamp: datetime


class HIBPClient(BaseDataCollector):
    """
    Have I Been Pwned API client for breach detection.
    
    Integrates with HIBP v3 API to:
    - Check email addresses for known breaches
    - Provide breach context and timeline
    - Assess exposure risk levels
    - Respect API rate limits and terms
    """
    
    BASE_URL = "https://haveibeenpwned.com/api/v3"
    PWNED_PASSWORDS_URL = "https://api.pwnedpasswords.com"
    
    # High-impact breach types
    HIGH_IMPACT_BREACHES = {
        'financial', 'banking', 'cryptocurrency', 'payment', 'credit',
        'identity', 'government', 'healthcare', 'insurance'
    }
    
    # Sensitive data classes
    SENSITIVE_DATA_CLASSES = {
        'passwords', 'password hints', 'security questions and answers',
        'credit cards', 'bank account numbers', 'social security numbers',
        'government issued ids', 'private messages', 'phone numbers'
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: str):
        super().__init__(config, cache_dir, "hibp_client")
        
        self.logger = get_logger(f"{__name__}.HIBPClient")
        
        # Load configuration
        breach_config = config.get('breach_detection', {})
        hibp_config = breach_config.get('hibp', {})
        
        self.api_key = hibp_config.get('api_key')
        self.user_agent = hibp_config.get('user_agent', 'Have-I-Been-Rekt-Security-Scanner')
        self.include_unverified = hibp_config.get('include_unverified', False)
        self.check_pastes = hibp_config.get('check_pastes', True)
        
        # Rate limiting (HIBP requires 1.5 second delays between requests)
        rate_config = config.get('rate_limiting', {})
        self.request_delay = max(rate_config.get('hibp_delay_seconds', 1.5), 1.5)
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'hibp-api-key': self.api_key if self.api_key else ''
        })
        
        # Track last request time for rate limiting
        self.last_request_time = 0
        
        self.logger.info(f"Initialized HIBP Client (API key: {'configured' if self.api_key else 'not configured'})")
    
    def _make_api_request(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[Any]:
        """Make rate-limited request to HIBP API"""
        
        if not self.api_key:
            self.logger.error("HIBP API key required for API access")
            return None
        
        # Rate limiting - ensure 1.5+ seconds between requests
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.request_delay:
            sleep_time = self.request_delay - time_since_last
            time.sleep(sleep_time)
        
        url = f"{self.BASE_URL}/{endpoint}"
        
        try:
            self.logger.debug(f"Making HIBP API request: {endpoint}")
            
            response = self.session.get(url, params=params, timeout=30)
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                # No breaches found - this is a valid response
                return []
            elif response.status_code == 400:
                self.logger.error("HIBP API: Bad request - invalid email format")
                return None
            elif response.status_code == 401:
                self.logger.error("HIBP API: Unauthorized - invalid API key")
                return None
            elif response.status_code == 403:
                self.logger.error("HIBP API: Forbidden - no user agent or rate limited")
                return None
            elif response.status_code == 429:
                self.logger.warning("HIBP API: Rate limited - backing off")
                time.sleep(5)  # Back off for rate limiting
                return None
            else:
                self.logger.error(f"HIBP API error: HTTP {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"HIBP API request failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error in HIBP request: {e}")
            return None
    
    def check_email_breaches(self, email: str) -> Optional[List[BreachInfo]]:
        """
        Check if email address appears in known data breaches.
        
        Args:
            email: Email address to check
            
        Returns:
            List of BreachInfo objects for breaches containing the email
        """
        
        cache_key = f"hibp_breaches_{email.lower()}"
        cached_result = self.get_cached_result(cache_key, max_age_hours=24)  # Cache for 24 hours
        
        if cached_result:
            breaches = []
            for breach_data in cached_result:
                breach_data['breach_date'] = datetime.fromisoformat(breach_data['breach_date'])
                breach_data['added_date'] = datetime.fromisoformat(breach_data['added_date'])
                breach_data['modified_date'] = datetime.fromisoformat(breach_data['modified_date'])
                breaches.append(BreachInfo(**breach_data))
            return breaches
        
        # Prepare request parameters
        params = {}
        if not self.include_unverified:
            params['truncateResponse'] = 'false'
        
        # Make API request
        encoded_email = quote(email, safe='')
        endpoint = f"breachedaccount/{encoded_email}"
        
        response = self._make_api_request(endpoint, params)
        
        if response is None:
            return None
        
        if not response:  # Empty list means no breaches
            self.cache_result(cache_key, [])
            return []
        
        # Parse breach information
        breaches = []
        
        for breach_data in response:
            breach = BreachInfo(
                name=breach_data.get('Name', ''),
                title=breach_data.get('Title', ''),
                domain=breach_data.get('Domain', ''),
                breach_date=datetime.fromisoformat(breach_data.get('BreachDate', '2000-01-01')),
                added_date=datetime.fromisoformat(breach_data.get('AddedDate', '2000-01-01T00:00:00Z')),
                modified_date=datetime.fromisoformat(breach_data.get('ModifiedDate', '2000-01-01T00:00:00Z')),
                pwn_count=breach_data.get('PwnCount', 0),
                description=breach_data.get('Description', ''),
                data_classes=breach_data.get('DataClasses', []),
                is_verified=breach_data.get('IsVerified', False),
                is_fabricated=breach_data.get('IsFabricated', False),
                is_sensitive=breach_data.get('IsSensitive', False),
                is_retired=breach_data.get('IsRetired', False),
                is_spam_list=breach_data.get('IsSpamList', False),
                logo_path=breach_data.get('LogoPath')
            )
            breaches.append(breach)
        
        # Cache results
        cache_data = []
        for breach in breaches:
            breach_dict = breach.__dict__.copy()
            breach_dict['breach_date'] = breach_dict['breach_date'].isoformat()
            breach_dict['added_date'] = breach_dict['added_date'].isoformat()
            breach_dict['modified_date'] = breach_dict['modified_date'].isoformat()
            cache_data.append(breach_dict)
        
        self.cache_result(cache_key, cache_data)
        
        return breaches
    
    def check_email_pastes(self, email: str) -> Optional[List[PasteInfo]]:
        """
        Check if email appears in pastes.
        
        Args:
            email: Email address to check
            
        Returns:
            List of PasteInfo objects for pastes containing the email
        """
        
        if not self.check_pastes:
            return []
        
        cache_key = f"hibp_pastes_{email.lower()}"
        cached_result = self.get_cached_result(cache_key, max_age_hours=24)
        
        if cached_result:
            pastes = []
            for paste_data in cached_result:
                if paste_data.get('date'):
                    paste_data['date'] = datetime.fromisoformat(paste_data['date'])
                pastes.append(PasteInfo(**paste_data))
            return pastes
        
        # Make API request
        encoded_email = quote(email, safe='')
        endpoint = f"pasteaccount/{encoded_email}"
        
        response = self._make_api_request(endpoint)
        
        if response is None:
            return None
        
        if not response:  # Empty list means no pastes
            self.cache_result(cache_key, [])
            return []
        
        # Parse paste information
        pastes = []
        
        for paste_data in response:
            paste_date = None
            if paste_data.get('Date'):
                try:
                    paste_date = datetime.fromisoformat(paste_data['Date'])
                except (ValueError, TypeError):
                    paste_date = None
            
            paste = PasteInfo(
                source=paste_data.get('Source', ''),
                id=paste_data.get('Id', ''),
                title=paste_data.get('Title'),
                date=paste_date,
                email_count=paste_data.get('EmailCount', 0)
            )
            pastes.append(paste)
        
        # Cache results
        cache_data = []
        for paste in pastes:
            paste_dict = paste.__dict__.copy()
            if paste_dict['date']:
                paste_dict['date'] = paste_dict['date'].isoformat()
            cache_data.append(paste_dict)
        
        self.cache_result(cache_key, cache_data)
        
        return pastes
    
    def check_password_pwned(self, password: str) -> Optional[int]:
        """
        Check if password has been pwned using k-anonymity.
        
        Args:
            password: Password to check (will be hashed)
            
        Returns:
            Number of times password has been seen in breaches (0 if not found)
        """
        
        # Generate SHA-1 hash of password
        password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Use k-anonymity - send first 5 characters, get back suffixes
        hash_prefix = password_hash[:5]
        hash_suffix = password_hash[5:]
        
        try:
            # No rate limiting needed for password API
            url = f"{self.PWNED_PASSWORDS_URL}/range/{hash_prefix}"
            response = requests.get(url, timeout=10)
            
            if response.status_code != 200:
                self.logger.error(f"Pwned Passwords API error: HTTP {response.status_code}")
                return None
            
            # Parse response - each line is suffix:count
            for line in response.text.splitlines():
                suffix, count = line.split(':')
                if suffix == hash_suffix:
                    return int(count)
            
            # Password not found in breaches
            return 0
            
        except Exception as e:
            self.logger.error(f"Error checking pwned password: {e}")
            return None
    
    def analyze_breach_exposure(self, email: str) -> Optional[BreachAnalysis]:
        """
        Perform comprehensive breach analysis for an email address.
        
        Args:
            email: Email address to analyze
            
        Returns:
            BreachAnalysis with complete exposure assessment
        """
        
        self.logger.info(f"Analyzing breach exposure: {email}")
        
        try:
            # Get breach data
            breaches = self.check_email_breaches(email)
            if breaches is None:
                return None
            
            # Get paste data
            pastes = self.check_email_pastes(email) if self.check_pastes else []
            if pastes is None:
                pastes = []
            
            # Calculate risk assessment
            risk_assessment = self._calculate_risk_assessment(breaches, pastes)
            
            # Calculate total pwn count
            total_pwn_count = sum(breach.pwn_count for breach in breaches)
            
            analysis = BreachAnalysis(
                email_address=email,
                total_breaches=len(breaches),
                total_pwn_count=total_pwn_count,
                breaches=breaches,
                pastes=pastes,
                risk_assessment=risk_assessment,
                analysis_timestamp=datetime.now(timezone.utc)
            )
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing breach exposure for {email}: {e}")
            return None
    
    def _calculate_risk_assessment(self, breaches: List[BreachInfo], pastes: List[PasteInfo]) -> Dict[str, Any]:
        """Calculate risk assessment based on breach and paste data"""
        
        if not breaches and not pastes:
            return {
                'risk_level': 'low',
                'risk_score': 0.0,
                'primary_concerns': [],
                'recommendations': ['Email not found in known breaches']
            }
        
        risk_score = 0.0
        primary_concerns = []
        recommendations = []
        
        # Assess breach risks
        if breaches:
            # Base risk for having any breaches
            risk_score += min(len(breaches) * 0.1, 0.5)
            
            # High-impact breaches
            high_impact_breaches = []
            sensitive_data_exposed = set()
            recent_breaches = []
            unverified_breaches = []
            
            for breach in breaches:
                # Check for high-impact breach domains/types
                domain_lower = breach.domain.lower()
                name_lower = breach.name.lower()
                
                if any(keyword in domain_lower or keyword in name_lower 
                       for keyword in self.HIGH_IMPACT_BREACHES):
                    high_impact_breaches.append(breach)
                    risk_score += 0.15
                
                # Check for sensitive data classes
                for data_class in breach.data_classes:
                    data_class_lower = data_class.lower()
                    if any(sensitive in data_class_lower for sensitive in self.SENSITIVE_DATA_CLASSES):
                        sensitive_data_exposed.add(data_class)
                        risk_score += 0.1
                
                # Check breach recency (within last 2 years)
                if breach.breach_date > datetime.now(timezone.utc).replace(year=datetime.now().year - 2):
                    recent_breaches.append(breach)
                    risk_score += 0.05
                
                # Unverified breaches are lower confidence
                if not breach.is_verified:
                    unverified_breaches.append(breach)
                    risk_score += 0.02
                else:
                    risk_score += 0.05
            
            # Add concerns based on findings
            if high_impact_breaches:
                primary_concerns.append(f"Exposed in {len(high_impact_breaches)} high-impact breach(es)")
            
            if sensitive_data_exposed:
                primary_concerns.append(f"Sensitive data exposed: {', '.join(list(sensitive_data_exposed)[:3])}")
            
            if recent_breaches:
                primary_concerns.append(f"{len(recent_breaches)} recent breach(es)")
        
        # Assess paste risks
        if pastes:
            risk_score += min(len(pastes) * 0.05, 0.2)
            primary_concerns.append(f"Found in {len(pastes)} paste(s)")
        
        # Generate recommendations
        if breaches:
            recommendations.append("Change passwords for all affected accounts")
            recommendations.append("Enable two-factor authentication where possible")
            
            if any('passwords' in breach.data_classes for breach in breaches):
                recommendations.append("Update passwords immediately - credentials may be compromised")
            
            if any('credit cards' in breach.data_classes for breach in breaches):
                recommendations.append("Monitor credit reports and bank statements")
        
        if pastes:
            recommendations.append("Monitor for additional paste appearances")
        
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
            'risk_level': risk_level,
            'risk_score': min(risk_score, 1.0),
            'primary_concerns': primary_concerns,
            'recommendations': recommendations[:5]  # Top 5 recommendations
        }
    
    def lookup_address(self, address: str) -> Dict[str, Any]:
        """
        Main interface for email breach analysis.
        
        Args:
            address: Email address to analyze
            
        Returns:
            Dictionary containing breach analysis results
        """
        
        try:
            # Validate email format (basic check)
            if '@' not in address or '.' not in address.split('@')[1]:
                return {
                    'found_breach_data': False,
                    'error': 'Invalid email address format'
                }
            
            self.logger.info(f"Starting breach analysis: {address}")
            
            analysis = self.analyze_breach_exposure(address)
            
            if not analysis:
                return {
                    'found_breach_data': False,
                    'error': 'Failed to analyze breach exposure'
                }
            
            # Build result dictionary
            result = {
                'found_breach_data': True,
                'email_address': analysis.email_address,
                'total_breaches': analysis.total_breaches,
                'total_pwn_count': analysis.total_pwn_count,
                'risk_assessment': analysis.risk_assessment,
                'breach_summary': {
                    'most_recent_breach': max((b.breach_date for b in analysis.breaches), default=None),
                    'largest_breach': max((b.pwn_count for b in analysis.breaches), default=0),
                    'verified_breaches': sum(1 for b in analysis.breaches if b.is_verified),
                    'sensitive_breaches': sum(1 for b in analysis.breaches 
                                            if any(sens in ' '.join(b.data_classes).lower() 
                                                  for sens in self.SENSITIVE_DATA_CLASSES))
                },
                'breach_details': [
                    {
                        'name': breach.name,
                        'title': breach.title,
                        'domain': breach.domain,
                        'breach_date': breach.breach_date.isoformat(),
                        'pwn_count': breach.pwn_count,
                        'data_classes': breach.data_classes,
                        'is_verified': breach.is_verified,
                        'is_sensitive': breach.is_sensitive
                    } for breach in analysis.breaches[:10]  # Top 10 breaches
                ],
                'paste_count': len(analysis.pastes),
                'analysis_timestamp': analysis.analysis_timestamp.isoformat()
            }
            
            # Convert datetime objects to strings for JSON serialization
            if result['breach_summary']['most_recent_breach']:
                result['breach_summary']['most_recent_breach'] = result['breach_summary']['most_recent_breach'].isoformat()
            
            self.logger.info(f"Breach analysis completed: {address} ({analysis.total_breaches} breaches)")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in breach analysis for {address}: {e}")
            return {
                'found_breach_data': False,
                'error': str(e)
            }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List:
        """Parse HIBP breach data into risk factors for ML training"""
        
        # Import here to avoid circular imports
        from ..data_collector import RiskFactor, RiskLevel, DataSourceType
        
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_breach_data'):
            return risk_factors
        
        breach_count = raw_data.get('total_breaches', 0)
        risk_assessment = raw_data.get('risk_assessment', {})
        risk_level_str = risk_assessment.get('risk_level', 'low')
        risk_score = risk_assessment.get('risk_score', 0)
        
        # Map risk level string to enum
        risk_level_map = {
            'low': RiskLevel.LOW,
            'medium': RiskLevel.MEDIUM,
            'high': RiskLevel.HIGH,
            'critical': RiskLevel.CRITICAL
        }
        
        risk_level = risk_level_map.get(risk_level_str, RiskLevel.LOW)
        
        # Overall breach exposure
        if breach_count > 0:
            risk_factors.append(RiskFactor(
                type="data_breach_exposure",
                description=f"Email found in {breach_count} data breach(es)",
                risk_level=risk_level,
                confidence=0.9,  # HIBP is highly reliable
                source=DataSourceType.BREACH_DATABASE,
                raw_data={'breach_count': breach_count, 'risk_score': risk_score}
            ))
        
        # Sensitive data exposure
        breach_summary = raw_data.get('breach_summary', {})
        sensitive_breaches = breach_summary.get('sensitive_breaches', 0)
        
        if sensitive_breaches > 0:
            risk_factors.append(RiskFactor(
                type="sensitive_data_breach",
                description=f"Sensitive data exposed in {sensitive_breaches} breach(es)",
                risk_level=RiskLevel.HIGH if sensitive_breaches > 2 else RiskLevel.MEDIUM,
                confidence=0.95,
                source=DataSourceType.BREACH_DATABASE,
                raw_data={'sensitive_breaches': sensitive_breaches}
            ))
        
        # Recent breach exposure
        most_recent_breach = breach_summary.get('most_recent_breach')
        if most_recent_breach:
            try:
                recent_date = datetime.fromisoformat(most_recent_breach)
                days_ago = (datetime.now(timezone.utc) - recent_date).days
                
                if days_ago < 730:  # Within 2 years
                    risk_factors.append(RiskFactor(
                        type="recent_data_breach",
                        description=f"Recent breach exposure ({days_ago} days ago)",
                        risk_level=RiskLevel.MEDIUM,
                        confidence=0.8,
                        source=DataSourceType.BREACH_DATABASE,
                        raw_data={'days_since_breach': days_ago, 'breach_date': most_recent_breach}
                    ))
            except (ValueError, TypeError):
                pass
        
        # Paste exposure
        paste_count = raw_data.get('paste_count', 0)
        if paste_count > 0:
            risk_factors.append(RiskFactor(
                type="paste_exposure",
                description=f"Email found in {paste_count} paste(s)",
                risk_level=RiskLevel.LOW if paste_count <= 2 else RiskLevel.MEDIUM,
                confidence=0.7,
                source=DataSourceType.BREACH_DATABASE,
                raw_data={'paste_count': paste_count}
            ))
        
        return risk_factors
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get HIBP client statistics"""
        
        return {
            'api_key_configured': bool(self.api_key),
            'include_unverified_breaches': self.include_unverified,
            'check_pastes_enabled': self.check_pastes,
            'request_delay_seconds': self.request_delay,
            'user_agent': self.user_agent,
            'cache_entries': len(self.cache) if hasattr(self.cache, '__len__') else 'unknown'
        }