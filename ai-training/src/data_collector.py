"""
Base DataCollector class for threat intelligence data sources.
Provides rate limiting, caching, error handling, and standardized interfaces.
"""

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import json
import logging

import aiohttp
import requests
from pydantic import BaseModel, Field, validator
import diskcache


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CLEAN = "clean"


class DataSourceType(str, Enum):
    SANCTIONS = "sanctions"
    SCAM_DATABASE = "scam_database"
    SMART_CONTRACT = "smart_contract"
    ATTRIBUTION = "attribution"
    BREACH_DATA = "breach_data"
    MALWARE_INTEL = "malware_intel"


@dataclass
class RiskFactor:
    """Individual risk factor from a data source"""
    source: str
    factor_type: str
    severity: RiskLevel
    weight: float
    description: str
    reference_url: Optional[str] = None
    first_seen: Optional[datetime] = None
    report_count: int = 1
    confidence: float = 1.0


class WalletAnalysis(BaseModel):
    """Complete analysis result for a wallet address"""
    address: str = Field(..., description="The analyzed wallet address")
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Overall risk score 0-1")
    risk_level: RiskLevel = Field(..., description="Categorical risk level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Analysis confidence")
    risk_factors: List[RiskFactor] = Field(default_factory=list)
    entity_attribution: Optional[Dict[str, Any]] = None
    recommendations: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    processing_time_ms: Optional[int] = None
    
    @validator('address')
    def validate_address(cls, v):
        """Basic address format validation"""
        if not v:
            raise ValueError("Address cannot be empty")
        # Add more sophisticated validation as needed
        return v.lower()


class RateLimiter:
    """Simple rate limiter for API calls"""
    
    def __init__(self, calls_per_minute: int, burst_limit: int = None):
        self.calls_per_minute = calls_per_minute
        self.burst_limit = burst_limit or calls_per_minute // 6
        self.calls_history = []
        self.burst_count = 0
    
    def wait_if_needed(self):
        """Block if rate limit would be exceeded"""
        now = time.time()
        
        # Clean old calls
        cutoff = now - 60  # 1 minute ago
        self.calls_history = [t for t in self.calls_history if t > cutoff]
        
        # Check burst limit
        if self.burst_count >= self.burst_limit:
            time.sleep(1)
            self.burst_count = 0
        
        # Check rate limit
        if len(self.calls_history) >= self.calls_per_minute:
            sleep_time = 60 - (now - self.calls_history[0])
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        self.calls_history.append(now)
        self.burst_count += 1


class BaseDataCollector(ABC):
    """Abstract base class for all data collectors"""
    
    def __init__(
        self,
        config: Dict[str, Any],
        cache_dir: Optional[str] = None,
        logger: Optional[logging.Logger] = None
    ):
        self.config = config
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        # Set up rate limiter
        rate_config = config.get('rate_limits', {}).get(self.source_name, {})
        self.rate_limiter = RateLimiter(
            rate_config.get('calls_per_minute', 60),
            rate_config.get('burst_limit', 10)
        )
        
        # Set up cache
        self.cache = None
        if cache_dir and config.get('cache', {}).get('enabled', True):
            cache_size = config.get('cache', {}).get('max_size_mb', 500) * 1024 * 1024
            self.cache = diskcache.Cache(
                cache_dir,
                size_limit=cache_size,
                eviction_policy='least-recently-used'
            )
    
    @property
    @abstractmethod
    def source_name(self) -> str:
        """Unique identifier for this data source"""
        pass
    
    @property
    @abstractmethod
    def data_source_type(self) -> DataSourceType:
        """Type of data this collector provides"""
        pass
    
    def get_cache_key(self, identifier: str) -> str:
        """Generate cache key for an identifier"""
        return f"{self.source_name}:{identifier}"
    
    def get_cached_result(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Get cached result if available and not expired"""
        if not self.cache:
            return None
        
        cache_key = self.get_cache_key(identifier)
        try:
            cached = self.cache.get(cache_key)
            if cached:
                # Check if expired
                ttl_hours = self.config.get('cache', {}).get('ttl_hours', 24)
                cache_age = datetime.utcnow() - datetime.fromisoformat(cached['timestamp'])
                if cache_age < timedelta(hours=ttl_hours):
                    self.logger.debug(f"Cache hit for {identifier}")
                    return cached['data']
                else:
                    self.cache.delete(cache_key)
        except Exception as e:
            self.logger.warning(f"Cache read error: {e}")
        
        return None
    
    def cache_result(self, identifier: str, data: Dict[str, Any]):
        """Cache a result"""
        if not self.cache:
            return
        
        cache_key = self.get_cache_key(identifier)
        try:
            self.cache.set(cache_key, {
                'timestamp': datetime.utcnow().isoformat(),
                'data': data
            })
        except Exception as e:
            self.logger.warning(f"Cache write error: {e}")
    
    def make_request(
        self,
        url: str,
        method: str = 'GET',
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        timeout: int = 30
    ) -> Optional[Dict[str, Any]]:
        """Make HTTP request with rate limiting and error handling"""
        
        self.rate_limiter.wait_if_needed()
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json_data,
                timeout=timeout
            )
            response.raise_for_status()
            
            # Try to parse as JSON
            try:
                return response.json()
            except json.JSONDecodeError:
                return {'text': response.text}
                
        except requests.RequestException as e:
            self.logger.error(f"Request failed for {url}: {e}")
            return None
    
    @abstractmethod
    def collect_address_data(self, address: str) -> Optional[Dict[str, Any]]:
        """Collect data for a specific address"""
        pass
    
    def collect_batch_data(self, addresses: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
        """Collect data for multiple addresses (default implementation)"""
        results = {}
        for address in addresses:
            results[address] = self.collect_address_data(address)
        return results
    
    @abstractmethod
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse raw data into standardized risk factors"""
        pass
    
    def analyze_address(self, address: str) -> Optional[WalletAnalysis]:
        """Complete analysis workflow for an address"""
        start_time = time.time()
        
        # Check cache first
        cached = self.get_cached_result(address)
        if cached:
            return WalletAnalysis(**cached)
        
        # Collect fresh data
        raw_data = self.collect_address_data(address)
        if not raw_data:
            return None
        
        # Parse into risk factors
        risk_factors = self.parse_risk_factors(raw_data, address)
        
        # Calculate basic risk score (can be overridden)
        risk_score = self.calculate_risk_score(risk_factors)
        risk_level = self.determine_risk_level(risk_score)
        
        analysis = WalletAnalysis(
            address=address,
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=self.calculate_confidence(risk_factors),
            risk_factors=risk_factors,
            data_sources=[self.source_name],
            processing_time_ms=int((time.time() - start_time) * 1000)
        )
        
        # Cache the result
        self.cache_result(address, analysis.dict())
        
        return analysis
    
    def calculate_risk_score(self, risk_factors: List[RiskFactor]) -> float:
        """Calculate overall risk score from factors"""
        if not risk_factors:
            return 0.0
        
        # Simple weighted average
        total_weight = sum(factor.weight * factor.confidence for factor in risk_factors)
        total_score = sum(
            self._severity_to_score(factor.severity) * factor.weight * factor.confidence
            for factor in risk_factors
        )
        
        if total_weight == 0:
            return 0.0
        
        return min(1.0, total_score / total_weight)
    
    def determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Convert risk score to categorical level"""
        thresholds = self.config.get('risk_scoring', {}).get('thresholds', {})
        
        if risk_score >= thresholds.get('critical', 0.8):
            return RiskLevel.CRITICAL
        elif risk_score >= thresholds.get('high', 0.6):
            return RiskLevel.HIGH
        elif risk_score >= thresholds.get('medium', 0.4):
            return RiskLevel.MEDIUM
        elif risk_score >= thresholds.get('low', 0.2):
            return RiskLevel.LOW
        else:
            return RiskLevel.CLEAN
    
    def calculate_confidence(self, risk_factors: List[RiskFactor]) -> float:
        """Calculate confidence in the analysis"""
        if not risk_factors:
            return 0.1  # Low confidence for no data
        
        # Average confidence weighted by factor importance
        total_weight = sum(factor.weight for factor in risk_factors)
        if total_weight == 0:
            return 0.1
        
        confidence = sum(
            factor.confidence * factor.weight
            for factor in risk_factors
        ) / total_weight
        
        return confidence
    
    @staticmethod
    def _severity_to_score(severity: RiskLevel) -> float:
        """Convert severity level to numeric score"""
        mapping = {
            RiskLevel.CRITICAL: 1.0,
            RiskLevel.HIGH: 0.8,
            RiskLevel.MEDIUM: 0.6,
            RiskLevel.LOW: 0.4,
            RiskLevel.CLEAN: 0.0
        }
        return mapping.get(severity, 0.0)


class DataCollectorManager:
    """Manages multiple data collectors and aggregates results"""
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None):
        self.config = config
        self.cache_dir = cache_dir
        self.collectors: Dict[str, BaseDataCollector] = {}
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def register_collector(self, collector: BaseDataCollector):
        """Register a data collector"""
        self.collectors[collector.source_name] = collector
        self.logger.info(f"Registered collector: {collector.source_name}")
    
    def analyze_address_comprehensive(self, address: str) -> WalletAnalysis:
        """Run analysis across all collectors and aggregate results"""
        start_time = time.time()
        all_risk_factors = []
        data_sources = []
        
        for collector in self.collectors.values():
            try:
                analysis = collector.analyze_address(address)
                if analysis:
                    all_risk_factors.extend(analysis.risk_factors)
                    data_sources.append(collector.source_name)
            except Exception as e:
                self.logger.error(f"Collector {collector.source_name} failed: {e}")
        
        # Aggregate results
        if not all_risk_factors:
            return WalletAnalysis(
                address=address,
                risk_score=0.0,
                risk_level=RiskLevel.CLEAN,
                confidence=0.1,
                data_sources=data_sources,
                processing_time_ms=int((time.time() - start_time) * 1000)
            )
        
        # Calculate aggregated risk score
        risk_score = self._aggregate_risk_score(all_risk_factors)
        risk_level = self._determine_aggregate_risk_level(risk_score)
        confidence = self._calculate_aggregate_confidence(all_risk_factors)
        
        return WalletAnalysis(
            address=address,
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=confidence,
            risk_factors=all_risk_factors,
            data_sources=data_sources,
            processing_time_ms=int((time.time() - start_time) * 1000)
        )
    
    def _aggregate_risk_score(self, risk_factors: List[RiskFactor]) -> float:
        """Aggregate risk scores from multiple sources"""
        if not risk_factors:
            return 0.0
        
        # Use maximum risk score but weight by confidence
        max_score = 0.0
        for factor in risk_factors:
            factor_score = BaseDataCollector._severity_to_score(factor.severity)
            weighted_score = factor_score * factor.confidence * factor.weight
            max_score = max(max_score, weighted_score)
        
        return min(1.0, max_score)
    
    def _determine_aggregate_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine aggregate risk level"""
        thresholds = self.config.get('risk_scoring', {}).get('thresholds', {})
        
        if risk_score >= thresholds.get('critical', 0.8):
            return RiskLevel.CRITICAL
        elif risk_score >= thresholds.get('high', 0.6):
            return RiskLevel.HIGH
        elif risk_score >= thresholds.get('medium', 0.4):
            return RiskLevel.MEDIUM
        elif risk_score >= thresholds.get('low', 0.2):
            return RiskLevel.LOW
        else:
            return RiskLevel.CLEAN
    
    def _calculate_aggregate_confidence(self, risk_factors: List[RiskFactor]) -> float:
        """Calculate confidence in aggregate analysis"""
        if not risk_factors:
            return 0.1
        
        # Higher confidence when multiple sources agree
        source_count = len(set(factor.source for factor in risk_factors))
        base_confidence = sum(factor.confidence for factor in risk_factors) / len(risk_factors)
        
        # Bonus for multiple sources
        multi_source_bonus = min(0.2, (source_count - 1) * 0.1)
        
        return min(1.0, base_confidence + multi_source_bonus)