"""
Chainalysis API client for real-time address screening and entity attribution.
Provides sanctions screening and risk assessment using Chainalysis data.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass
import logging

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType
from ..utils.logging import LoggingMixin


@dataclass
class ChainanalysisScreeningResult:
    """Result from Chainalysis address screening"""
    address: str
    is_sanctioned: bool
    category: Optional[str] = None
    category_id: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    cluster_name: Optional[str] = None
    risk_score: Optional[float] = None
    confidence: float = 1.0
    
    @property
    def is_high_risk(self) -> bool:
        """Check if this is a high-risk category"""
        high_risk_categories = {
            'sanctions', 'darknet', 'gambling', 'mixer', 'exchange.dex',
            'scam', 'ransomware', 'theft', 'child_abuse_csem'
        }
        return self.category_id in high_risk_categories if self.category_id else False


class ChainanalysisClient(BaseDataCollector, LoggingMixin):
    """Chainalysis API client for address screening and entity data"""
    
    # API endpoints
    BASE_URL = "https://api.chainalysis.com"
    SCREENING_ENDPOINT = "/api/kyt/v1/addresses"
    
    # Risk level mapping from Chainalysis categories
    CATEGORY_RISK_MAPPING = {
        'sanctions': RiskLevel.CRITICAL,
        'darknet': RiskLevel.HIGH,
        'ransomware': RiskLevel.CRITICAL,
        'scam': RiskLevel.HIGH,
        'theft': RiskLevel.HIGH,
        'child_abuse_csem': RiskLevel.CRITICAL,
        'mixer': RiskLevel.MEDIUM,
        'gambling': RiskLevel.LOW,
        'exchange': RiskLevel.CLEAN,
        'exchange.dex': RiskLevel.MEDIUM,
        'defi': RiskLevel.CLEAN,
        'mining_pool': RiskLevel.CLEAN,
        'unknown': RiskLevel.CLEAN
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        self.api_key = config.get('api_keys', {}).get('chainalysis')
        
        if not self.api_key:
            self.logger.warning("No Chainalysis API key configured")
    
    @property
    def source_name(self) -> str:
        return "chainalysis"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.SANCTIONS
    
    def _get_headers(self) -> Dict[str, str]:
        """Get API request headers"""
        if not self.api_key:
            return {}
        
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'HaveIBeenRekt/1.0 (OSINT Research Tool)'
        }
    
    def screen_address(self, address: str) -> Optional[ChainanalysisScreeningResult]:
        """Screen a single address using Chainalysis API"""
        if not self.api_key:
            self.logger.warning("Cannot screen address - no API key configured")
            return None
        
        # Check cache first
        cache_key = f"screen_{address}"
        cached_result = self.get_cached_result(cache_key)
        if cached_result:
            return ChainanalysisScreeningResult(**cached_result)
        
        url = f"{self.BASE_URL}{self.SCREENING_ENDPOINT}/{address}"
        headers = self._get_headers()
        
        try:
            self.logger.info("Screening address with Chainalysis", address=address[:10] + "...")
            
            response = self.make_request(url=url, headers=headers)
            
            if not response:
                self.logger.error("Failed to get response from Chainalysis API")
                return None
            
            # Parse response
            result = self._parse_screening_response(address, response)
            
            # Cache the result
            if result:
                self.cache_result(cache_key, {
                    'address': result.address,
                    'is_sanctioned': result.is_sanctioned,
                    'category': result.category,
                    'category_id': result.category_id,
                    'description': result.description,
                    'url': result.url,
                    'cluster_name': result.cluster_name,
                    'risk_score': result.risk_score,
                    'confidence': result.confidence
                })
            
            return result
            
        except Exception as e:
            self.logger.error("Error screening address with Chainalysis", 
                            address=address, error=str(e))
            return None
    
    def _parse_screening_response(self, address: str, response: Dict[str, Any]) -> ChainanalysisScreeningResult:
        """Parse Chainalysis API response into screening result"""
        
        # Default clean result
        result = ChainanalysisScreeningResult(
            address=address,
            is_sanctioned=False,
            confidence=0.1  # Low confidence when no data
        )
        
        # Extract category information
        category = response.get('category', 'unknown')
        category_id = response.get('categoryId', 'unknown')
        
        result.category = category
        result.category_id = category_id
        result.description = response.get('description')
        result.url = response.get('url')
        result.cluster_name = response.get('clusterName')
        
        # Determine if sanctioned
        result.is_sanctioned = category_id == 'sanctions'
        
        # Calculate risk score based on category
        if category_id in self.CATEGORY_RISK_MAPPING:
            risk_level = self.CATEGORY_RISK_MAPPING[category_id]
            if risk_level == RiskLevel.CRITICAL:
                result.risk_score = 1.0
                result.confidence = 1.0
            elif risk_level == RiskLevel.HIGH:
                result.risk_score = 0.8
                result.confidence = 0.9
            elif risk_level == RiskLevel.MEDIUM:
                result.risk_score = 0.5
                result.confidence = 0.7
            elif risk_level == RiskLevel.LOW:
                result.risk_score = 0.3
                result.confidence = 0.6
            else:  # CLEAN
                result.risk_score = 0.0
                result.confidence = 0.8
        
        # Higher confidence for known entities
        if result.cluster_name or result.description:
            result.confidence = min(1.0, result.confidence + 0.1)
        
        self.logger.info(
            "Address screening completed",
            address=address[:10] + "...",
            category=category,
            is_sanctioned=result.is_sanctioned,
            risk_score=result.risk_score
        )
        
        return result
    
    def batch_screen_addresses(self, addresses: List[str]) -> Dict[str, Optional[ChainanalysisScreeningResult]]:
        """Screen multiple addresses (sequential to respect rate limits)"""
        results = {}
        
        for address in addresses:
            results[address] = self.screen_address(address)
        
        return results
    
    def collect_address_data(self, address: str) -> Optional[Dict[str, Any]]:
        """Collect Chainalysis data for an address"""
        screening_result = self.screen_address(address)
        
        if not screening_result:
            return None
        
        return {
            'address': address,
            'screening_result': screening_result,
            'is_sanctioned': screening_result.is_sanctioned,
            'category': screening_result.category,
            'category_id': screening_result.category_id,
            'description': screening_result.description,
            'cluster_name': screening_result.cluster_name,
            'risk_score': screening_result.risk_score,
            'confidence': screening_result.confidence,
            'source': self.source_name,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse Chainalysis data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('screening_result'):
            return risk_factors
        
        screening_result = raw_data['screening_result']
        
        # Skip if no significant findings
        if isinstance(screening_result, dict):
            category_id = screening_result.get('category_id')
            risk_score = screening_result.get('risk_score', 0)
            confidence = screening_result.get('confidence', 0)
            category = screening_result.get('category', 'unknown')
            description = screening_result.get('description', '')
            cluster_name = screening_result.get('cluster_name', '')
        else:
            category_id = screening_result.category_id
            risk_score = screening_result.risk_score or 0
            confidence = screening_result.confidence
            category = screening_result.category
            description = screening_result.description or ''
            cluster_name = screening_result.cluster_name or ''
        
        # Only create risk factors for non-clean categories
        if category_id == 'unknown' or risk_score < 0.1:
            return risk_factors
        
        # Map to our risk levels
        severity = self.CATEGORY_RISK_MAPPING.get(category_id, RiskLevel.LOW)
        
        # Create descriptive text
        if cluster_name:
            desc = f"Address associated with {cluster_name} ({category})"
        elif description:
            desc = f"Address categorized as {category}: {description}"
        else:
            desc = f"Address categorized as {category}"
        
        # Determine factor type
        if category_id == 'sanctions':
            factor_type = 'sanctions'
        elif category_id in ['scam', 'ransomware', 'theft']:
            factor_type = 'criminal_activity'
        elif category_id == 'mixer':
            factor_type = 'privacy_tool'
        elif category_id in ['darknet', 'gambling']:
            factor_type = 'high_risk_service'
        else:
            factor_type = 'entity_attribution'
        
        risk_factor = RiskFactor(
            source=self.source_name,
            factor_type=factor_type,
            severity=severity,
            weight=0.9,  # High weight for Chainalysis data
            description=desc,
            reference_url="https://www.chainalysis.com/",
            confidence=confidence,
            report_count=1
        )
        
        risk_factors.append(risk_factor)
        
        # Log significant findings
        if severity in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            self.logger.warning(
                f"{severity.value.upper()}: High-risk address detected",
                address=address[:10] + "...",
                category=category,
                cluster=cluster_name,
                risk_score=risk_score
            )
        
        return risk_factors
    
    def get_supported_networks(self) -> List[str]:
        """Get list of blockchain networks supported by Chainalysis"""
        return [
            'bitcoin', 'ethereum', 'litecoin', 'bitcoin_cash',
            'zcash', 'dash', 'ethereum_classic', 'tether',
            'binance_smart_chain', 'polygon', 'avalanche'
        ]
    
    def validate_api_key(self) -> bool:
        """Validate that the API key is working"""
        if not self.api_key:
            return False
        
        # Test with a known clean address (Ethereum Foundation donation address)
        test_address = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        
        try:
            result = self.screen_address(test_address)
            return result is not None
        except Exception as e:
            self.logger.error("API key validation failed", error=str(e))
            return False
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """Get API usage statistics (if available)"""
        # This would require additional API endpoints that may not be public
        # For now, return basic stats from our cache
        if not self.cache:
            return {'error': 'No cache available'}
        
        # Count cached screening results
        cached_screenings = 0
        try:
            for key in self.cache:
                if key.startswith(f"{self.source_name}:screen_"):
                    cached_screenings += 1
        except:
            pass
        
        return {
            'cached_screenings': cached_screenings,
            'api_key_configured': bool(self.api_key),
            'api_key_valid': self.validate_api_key() if self.api_key else False
        }