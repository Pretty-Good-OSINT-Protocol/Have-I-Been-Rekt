"""
Whale Alert API client for suspicious transaction monitoring.

Whale Alert tracks large cryptocurrency transactions and provides
alerts for suspicious activity, exchange movements, and scam detection.
"""

from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timezone
from dataclasses import dataclass
import requests
import time
import re
from urllib.parse import quote

from ..data_collector import BaseDataCollector
from ..utils.logging import get_logger


@dataclass
class WhaleTransaction:
    """Represents a whale transaction from Whale Alert"""
    
    transaction_hash: str
    blockchain: str
    amount: float
    amount_usd: float
    from_address: Optional[str]
    to_address: Optional[str] 
    from_owner: Optional[str]
    to_owner: Optional[str]
    timestamp: datetime
    transaction_type: str
    symbol: str


@dataclass
class SuspiciousActivity:
    """Represents suspicious activity detected by Whale Alert"""
    
    address: str
    activity_type: str  # 'whale_movement', 'exchange_suspicious', 'mixer_usage', 'sanctioned_interaction'
    description: str
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    confidence: float
    first_seen: datetime
    last_seen: datetime
    transaction_count: int
    total_volume_usd: float
    related_addresses: Set[str]
    tags: List[str]


class WhaleAlertClient(BaseDataCollector):
    """
    Client for Whale Alert API integration.
    
    Provides large transaction monitoring, suspicious activity detection,
    and scam wallet identification through transaction pattern analysis.
    """
    
    BASE_URL = "https://api.whale-alert.io/v1"
    
    def __init__(self, config: Dict[str, Any], cache_dir: str):
        super().__init__(config, cache_dir, "whale_alert")
        
        self.logger = get_logger(f"{__name__}.WhaleAlertClient")
        
        # Load configuration
        whale_config = config.get('community_scam_sources', {}).get('whale_alert', {})
        self.api_key = whale_config.get('api_key')
        self.subscription_tier = whale_config.get('subscription_tier', 'free')  # free, basic, pro
        self.min_usd_value = whale_config.get('min_transaction_usd', 500000)  # Minimum transaction value to track
        
        # Rate limiting based on subscription
        rate_limits = {
            'free': 60,      # 60 requests per hour
            'basic': 3600,   # 3600 requests per hour  
            'pro': 36000     # 36000 requests per hour
        }
        
        rate_config = config.get('rate_limiting', {})
        self.requests_per_hour = rate_limits.get(self.subscription_tier, 60)
        self.request_delay = 3600 / self.requests_per_hour  # Seconds between requests
        
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                'X-WA-API-KEY': self.api_key
            })
        
        self.logger.info(f"Initialized Whale Alert client (tier: {self.subscription_tier})")
    
    def _make_api_request(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Make rate-limited request to Whale Alert API"""
        
        if not self.api_key:
            self.logger.warning("No Whale Alert API key configured")
            return None
            
        url = f"{self.BASE_URL}/{endpoint}"
        
        try:
            # Rate limiting
            time.sleep(self.request_delay)
            
            self.logger.debug(f"Making Whale Alert API request: {endpoint}")
            
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('result') == 'success':
                return data
            else:
                self.logger.warning(f"Whale Alert API error: {data.get('message', 'Unknown error')}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Whale Alert API request failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error in Whale Alert request: {e}")
            return None
    
    def get_address_transactions(self, address: str, limit: int = 100) -> List[WhaleTransaction]:
        """
        Get whale transactions for a specific address.
        
        Args:
            address: Cryptocurrency address to analyze
            limit: Maximum number of transactions to return
            
        Returns:
            List of whale transactions involving the address
        """
        
        cache_key = f"whale_address_{address}_{limit}"
        cached_result = self.get_cached_result(cache_key, max_age_hours=1)  # Short cache for fresh data
        
        if cached_result:
            return [WhaleTransaction(**tx) for tx in cached_result]
        
        # Get transactions from last 24 hours (API limitation)
        params = {
            'start': int(time.time() - 86400),  # 24 hours ago
            'end': int(time.time()),
            'min_value': self.min_usd_value,
            'limit': limit
        }
        
        data = self._make_api_request('transactions', params)
        
        if not data or 'transactions' not in data:
            return []
        
        transactions = []
        
        for tx_data in data['transactions']:
            # Check if address is involved in this transaction
            from_addr = tx_data.get('from', {}).get('address')
            to_addr = tx_data.get('to', {}).get('address')
            
            if address.lower() not in [from_addr.lower() if from_addr else '', 
                                     to_addr.lower() if to_addr else '']:
                continue
            
            transaction = WhaleTransaction(
                transaction_hash=tx_data.get('hash', ''),
                blockchain=tx_data.get('blockchain', ''),
                amount=float(tx_data.get('amount', 0)),
                amount_usd=float(tx_data.get('amount_usd', 0)),
                from_address=from_addr,
                to_address=to_addr,
                from_owner=tx_data.get('from', {}).get('owner', ''),
                to_owner=tx_data.get('to', {}).get('owner', ''),
                timestamp=datetime.fromtimestamp(tx_data.get('timestamp', 0), tz=timezone.utc),
                transaction_type=tx_data.get('transaction_type', 'transfer'),
                symbol=tx_data.get('symbol', '')
            )
            
            transactions.append(transaction)
        
        # Cache results
        cache_data = [tx.__dict__ for tx in transactions]
        for tx_dict in cache_data:
            tx_dict['timestamp'] = tx_dict['timestamp'].isoformat()
        self.cache_result(cache_key, cache_data)
        
        self.logger.info(f"Found {len(transactions)} whale transactions for address {address[:10]}...")
        
        return transactions
    
    def analyze_suspicious_activity(self, address: str) -> Optional[SuspiciousActivity]:
        """
        Analyze address for suspicious activity patterns.
        
        Args:
            address: Cryptocurrency address to analyze
            
        Returns:
            SuspiciousActivity object if suspicious patterns detected, None otherwise
        """
        
        cache_key = f"suspicious_{address}"
        cached_result = self.get_cached_result(cache_key, max_age_hours=6)
        
        if cached_result:
            cached_result['first_seen'] = datetime.fromisoformat(cached_result['first_seen'])
            cached_result['last_seen'] = datetime.fromisoformat(cached_result['last_seen'])
            cached_result['related_addresses'] = set(cached_result['related_addresses'])
            return SuspiciousActivity(**cached_result)
        
        # Get recent transactions for analysis
        transactions = self.get_address_transactions(address, limit=50)
        
        if not transactions:
            return None
        
        # Analyze transaction patterns
        analysis = self._analyze_transaction_patterns(address, transactions)
        
        if analysis['risk_level'] in ['medium', 'high', 'critical']:
            
            suspicious_activity = SuspiciousActivity(
                address=address,
                activity_type=analysis['activity_type'],
                description=analysis['description'],
                risk_level=analysis['risk_level'],
                confidence=analysis['confidence'],
                first_seen=analysis['first_seen'],
                last_seen=analysis['last_seen'], 
                transaction_count=analysis['transaction_count'],
                total_volume_usd=analysis['total_volume_usd'],
                related_addresses=analysis['related_addresses'],
                tags=analysis['tags']
            )
            
            # Cache results
            cache_data = suspicious_activity.__dict__.copy()
            cache_data['first_seen'] = cache_data['first_seen'].isoformat()
            cache_data['last_seen'] = cache_data['last_seen'].isoformat()
            cache_data['related_addresses'] = list(cache_data['related_addresses'])
            self.cache_result(cache_key, cache_data)
            
            return suspicious_activity
        
        return None
    
    def _analyze_transaction_patterns(self, address: str, transactions: List[WhaleTransaction]) -> Dict[str, Any]:
        """Analyze transaction patterns for suspicious activity"""
        
        if not transactions:
            return {
                'activity_type': 'no_activity',
                'description': 'No recent whale transactions found',
                'risk_level': 'low',
                'confidence': 0.1,
                'first_seen': datetime.now(timezone.utc),
                'last_seen': datetime.now(timezone.utc),
                'transaction_count': 0,
                'total_volume_usd': 0.0,
                'related_addresses': set(),
                'tags': []
            }
        
        # Extract analysis data
        total_volume = sum(tx.amount_usd for tx in transactions)
        related_addresses = set()
        
        exchange_interactions = 0
        mixer_interactions = 0
        suspicious_patterns = []
        tags = []
        
        # Analyze each transaction
        for tx in transactions:
            # Collect related addresses
            if tx.from_address and tx.from_address.lower() != address.lower():
                related_addresses.add(tx.from_address)
            if tx.to_address and tx.to_address.lower() != address.lower():
                related_addresses.add(tx.to_address)
            
            # Check for exchange interactions
            if self._is_exchange_address(tx.from_address) or self._is_exchange_address(tx.to_address):
                exchange_interactions += 1
            
            # Check for mixer/privacy coin usage
            if self._is_mixer_address(tx.from_address) or self._is_mixer_address(tx.to_address):
                mixer_interactions += 1
                tags.append('mixer_usage')
            
            # Check for rapid succession (possible automated activity)
            if len(transactions) > 1:
                time_diffs = []
                for i in range(1, len(transactions)):
                    diff = abs((transactions[i].timestamp - transactions[i-1].timestamp).total_seconds())
                    time_diffs.append(diff)
                
                avg_time_diff = sum(time_diffs) / len(time_diffs) if time_diffs else 0
                if avg_time_diff < 300:  # Less than 5 minutes between transactions
                    suspicious_patterns.append('rapid_succession')
                    tags.append('automated_activity')
        
        # Determine activity type and risk level
        activity_type = 'whale_movement'
        risk_level = 'low'
        confidence = 0.3
        
        # High volume indicator
        if total_volume > 10_000_000:  # $10M+
            risk_level = 'medium'
            confidence = 0.6
            tags.append('high_volume')
        
        # Mixer usage significantly increases risk
        if mixer_interactions > 0:
            activity_type = 'mixer_usage'
            risk_level = 'high'
            confidence = 0.8
            suspicious_patterns.append('privacy_tools')
        
        # Multiple rapid transactions increase risk
        if 'rapid_succession' in suspicious_patterns and len(transactions) > 10:
            activity_type = 'automated_suspicious'
            risk_level = 'high'
            confidence = 0.9
        
        # Very high volume with patterns is critical
        if total_volume > 50_000_000 and len(suspicious_patterns) > 1:
            risk_level = 'critical'
            confidence = 0.95
        
        # Generate description
        description = f"Large transaction activity: {len(transactions)} transactions totaling ${total_volume:,.0f}"
        if suspicious_patterns:
            description += f". Patterns: {', '.join(suspicious_patterns)}"
        
        return {
            'activity_type': activity_type,
            'description': description,
            'risk_level': risk_level,
            'confidence': confidence,
            'first_seen': min(tx.timestamp for tx in transactions),
            'last_seen': max(tx.timestamp for tx in transactions),
            'transaction_count': len(transactions),
            'total_volume_usd': total_volume,
            'related_addresses': related_addresses,
            'tags': list(set(tags))  # Remove duplicates
        }
    
    def _is_exchange_address(self, address: Optional[str]) -> bool:
        """Check if address belongs to a known exchange"""
        if not address:
            return False
            
        # This would typically query a database of known exchange addresses
        # For now, we'll use basic heuristics and known patterns
        
        # Common exchange address patterns (this is simplified)
        exchange_patterns = [
            r'^1[13][a-km-zA-HJ-NP-Z1-9]{25,34}$',  # Bitcoin exchange patterns
            r'^0x[a-fA-F0-9]{40}$'  # Ethereum exchange patterns (would need actual exchange addresses)
        ]
        
        # This is a placeholder - in production you'd have a proper exchange address database
        return False
    
    def _is_mixer_address(self, address: Optional[str]) -> bool:
        """Check if address belongs to a known mixer/tumbler"""
        if not address:
            return False
            
        # Known mixer address patterns (simplified)
        # In production, this would check against known mixer addresses
        mixer_indicators = [
            'tornado',  # Tornado Cash patterns
            'mixer',
            'tumbler'
        ]
        
        # This is a placeholder - in production you'd have a proper mixer database  
        return any(indicator in address.lower() for indicator in mixer_indicators)
    
    def lookup_address(self, address: str) -> Dict[str, Any]:
        """
        Main interface for address lookup against Whale Alert data.
        
        Args:
            address: Cryptocurrency address to analyze
            
        Returns:
            Dictionary containing whale alert analysis results
        """
        
        try:
            self.logger.info(f"Analyzing address with Whale Alert: {address[:10]}...")
            
            # Get whale transactions
            transactions = self.get_address_transactions(address)
            
            # Analyze for suspicious activity
            suspicious_activity = self.analyze_suspicious_activity(address)
            
            # Build result
            result = {
                'found_in_whale_alert': len(transactions) > 0 or suspicious_activity is not None,
                'whale_transaction_count': len(transactions),
                'suspicious_activity_detected': suspicious_activity is not None,
                'total_whale_volume_usd': sum(tx.amount_usd for tx in transactions),
                'recent_transactions': [
                    {
                        'hash': tx.transaction_hash,
                        'amount_usd': tx.amount_usd,
                        'timestamp': tx.timestamp.isoformat(),
                        'type': tx.transaction_type,
                        'blockchain': tx.blockchain
                    } for tx in transactions[:5]  # Show only 5 most recent
                ]
            }
            
            if suspicious_activity:
                result['suspicious_activity'] = {
                    'activity_type': suspicious_activity.activity_type,
                    'risk_level': suspicious_activity.risk_level,
                    'confidence': suspicious_activity.confidence,
                    'description': suspicious_activity.description,
                    'transaction_count': suspicious_activity.transaction_count,
                    'tags': suspicious_activity.tags
                }
            
            self.logger.info(f"Whale Alert analysis completed for {address[:10]}...")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in Whale Alert lookup for {address}: {e}")
            return {
                'found_in_whale_alert': False,
                'error': str(e)
            }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List:
        """Parse Whale Alert data into risk factors for ML training"""
        
        # Import here to avoid circular imports
        from ..data_collector import RiskFactor, RiskLevel, DataSourceType
        
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_in_whale_alert'):
            return risk_factors
        
        # Whale transaction volume risk
        whale_tx_count = raw_data.get('whale_transaction_count', 0)
        total_volume = raw_data.get('total_whale_volume_usd', 0)
        
        if whale_tx_count > 0:
            risk_factors.append(RiskFactor(
                type="whale_activity",
                description=f"Address involved in {whale_tx_count} large transactions (${total_volume:,.0f} total)",
                risk_level=RiskLevel.LOW if total_volume < 1_000_000 else RiskLevel.MEDIUM,
                confidence=0.7,
                source=DataSourceType.COMMUNITY,
                raw_data={'whale_transactions': whale_tx_count, 'total_volume_usd': total_volume}
            ))
        
        # Suspicious activity risk
        suspicious_activity = raw_data.get('suspicious_activity')
        if suspicious_activity:
            activity_type = suspicious_activity.get('activity_type', 'unknown')
            risk_level_str = suspicious_activity.get('risk_level', 'medium')
            confidence = suspicious_activity.get('confidence', 0.7)
            description = suspicious_activity.get('description', 'Suspicious activity detected')
            
            # Map risk level string to enum
            risk_level_map = {
                'low': RiskLevel.LOW,
                'medium': RiskLevel.MEDIUM, 
                'high': RiskLevel.HIGH,
                'critical': RiskLevel.CRITICAL
            }
            
            risk_level = risk_level_map.get(risk_level_str.lower(), RiskLevel.MEDIUM)
            
            risk_factors.append(RiskFactor(
                type=f"whale_suspicious_{activity_type}",
                description=description,
                risk_level=risk_level,
                confidence=confidence,
                source=DataSourceType.COMMUNITY,
                raw_data=suspicious_activity
            ))
        
        return risk_factors
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get Whale Alert client statistics"""
        
        return {
            'api_key_configured': bool(self.api_key),
            'subscription_tier': self.subscription_tier,
            'requests_per_hour': self.requests_per_hour,
            'min_transaction_usd': self.min_usd_value,
            'cache_entries': len(self.cache) if hasattr(self.cache, '__len__') else 'unknown'
        }