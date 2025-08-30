"""
Exchange & Service Identification System - identifies major cryptocurrency exchanges,
mixers, DeFi protocols, and other services based on address patterns and known datasets.

Combines multiple data sources for comprehensive service identification including
deposit addresses, hot wallets, and protocol contracts.
"""

import re
import json
import requests
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum
import logging

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin


class ServiceType(Enum):
    """Types of cryptocurrency services"""
    EXCHANGE = "exchange"
    MIXER = "mixer"
    GAMBLING = "gambling"
    DEFI_PROTOCOL = "defi_protocol"
    PAYMENT_PROCESSOR = "payment_processor"
    MINING_POOL = "mining_pool"
    WALLET_SERVICE = "wallet_service"
    ATM = "atm"
    P2P_EXCHANGE = "p2p_exchange"
    DARKNET_MARKET = "darknet_market"
    PRIVACY_SERVICE = "privacy_service"
    INSTITUTIONAL = "institutional"
    MERCHANT = "merchant"
    OTHER = "other"


class RiskTier(Enum):
    """Risk tiers for different service types"""
    VERY_HIGH = "very_high"    # Darknet markets, unregulated mixers
    HIGH = "high"              # Privacy services, P2P exchanges
    MEDIUM = "medium"          # Gambling, some DeFi
    LOW = "low"               # Regulated exchanges, payment processors
    VERY_LOW = "very_low"     # Institutional, major exchanges


@dataclass
class ServiceIdentification:
    """Represents identification of a cryptocurrency service"""
    address: str
    service_name: str
    service_type: ServiceType
    risk_tier: RiskTier
    confidence: float
    source: str
    network: str
    additional_info: Dict[str, Any] = None
    first_seen: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    
    def __post_init__(self):
        if self.additional_info is None:
            self.additional_info = {}


class ExchangeServiceIdentifier(BaseDataCollector, LoggingMixin):
    """
    Identifies cryptocurrency exchanges and services using multiple data sources
    including address patterns, known service databases, and behavioral analysis.
    """
    
    # Known exchange patterns and identifiers
    EXCHANGE_PATTERNS = {
        # Binance patterns
        'binance': {
            'patterns': [
                r'^bc1q[a-z0-9]{39}$',  # Binance bech32 pattern
                r'^3[A-Za-z0-9]{33}$'   # Common Binance P2SH
            ],
            'known_addresses': {
                # Major Binance hot wallets (example addresses)
                'bitcoin': [
                    '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo',  # Binance hot wallet
                    '1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s'   # Binance cold wallet
                ],
                'ethereum': [
                    '0x3f5CE5FBFe3E9af3971dD833D26bA9b5C936f0bE',  # Binance hot wallet
                    '0xD551234Ae421e3BCBA99A0Da6d736074f22192FF'   # Binance cold wallet
                ]
            },
            'service_type': ServiceType.EXCHANGE,
            'risk_tier': RiskTier.LOW
        },
        
        # Coinbase patterns
        'coinbase': {
            'patterns': [
                r'^3[A-Za-z0-9]{33}$'   # Coinbase P2SH addresses
            ],
            'known_addresses': {
                'bitcoin': [
                    '3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64',  # Coinbase hot wallet
                    '3D2oetdNuZUqQHPJmcMDDHYoqkyNVsFk9r'   # Coinbase vault
                ],
                'ethereum': [
                    '0x71660c4005ba85c37ccec55d0c4493e66fe775d3',  # Coinbase hot wallet
                    '0x503828976d22510aad0201ac7ec88293211d23da'   # Coinbase cold wallet
                ]
            },
            'service_type': ServiceType.EXCHANGE,
            'risk_tier': RiskTier.VERY_LOW
        },
        
        # Tornado Cash (mixer)
        'tornado_cash': {
            'known_addresses': {
                'ethereum': [
                    '0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc',  # 0.1 ETH mixer
                    '0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936',  # 1 ETH mixer
                    '0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF'   # 10 ETH mixer
                ]
            },
            'service_type': ServiceType.MIXER,
            'risk_tier': RiskTier.VERY_HIGH
        },
        
        # Uniswap (DeFi)
        'uniswap': {
            'known_addresses': {
                'ethereum': [
                    '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984',  # UNI token
                    '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',  # Uniswap V2 Router
                    '0xE592427A0AEce92De3Edee1F18E0157C05861564'   # Uniswap V3 Router
                ]
            },
            'service_type': ServiceType.DEFI_PROTOCOL,
            'risk_tier': RiskTier.LOW
        }
    }
    
    # Service risk assessment
    SERVICE_RISK_MAPPING = {
        ServiceType.EXCHANGE: RiskTier.LOW,
        ServiceType.MIXER: RiskTier.VERY_HIGH,
        ServiceType.GAMBLING: RiskTier.MEDIUM,
        ServiceType.DEFI_PROTOCOL: RiskTier.LOW,
        ServiceType.PAYMENT_PROCESSOR: RiskTier.LOW,
        ServiceType.MINING_POOL: RiskTier.LOW,
        ServiceType.WALLET_SERVICE: RiskTier.LOW,
        ServiceType.ATM: RiskTier.MEDIUM,
        ServiceType.P2P_EXCHANGE: RiskTier.HIGH,
        ServiceType.DARKNET_MARKET: RiskTier.VERY_HIGH,
        ServiceType.PRIVACY_SERVICE: RiskTier.HIGH,
        ServiceType.INSTITUTIONAL: RiskTier.VERY_LOW,
        ServiceType.MERCHANT: RiskTier.LOW,
        ServiceType.OTHER: RiskTier.MEDIUM
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # Data storage
        self.service_database = {}  # Address -> ServiceIdentification
        self.service_patterns = self.EXCHANGE_PATTERNS.copy()
        
        # Configuration
        self.enable_pattern_matching = config.get('enable_pattern_matching', True)
        self.enable_api_lookups = config.get('enable_api_lookups', True)
        self.confidence_threshold = config.get('confidence_threshold', 0.7)
        
        # Load additional service data
        self._load_service_databases()
        
        # Initialize pattern matching
        self._compile_patterns()
        
        self.logger.info(
            "Exchange & Service Identifier initialized",
            services_loaded=len(self.service_database),
            patterns_enabled=self.enable_pattern_matching
        )
    
    @property
    def source_name(self) -> str:
        return "exchange_service_identifier"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.COMMERCIAL
    
    def _load_service_databases(self):
        """Load service identification databases"""
        # In a real implementation, this would load from various sources:
        # - Public exchange address lists
        # - DeFi protocol registries
        # - Community-maintained databases
        
        # For now, populate with known addresses from patterns
        for service_name, service_info in self.service_patterns.items():
            known_addresses = service_info.get('known_addresses', {})
            service_type = service_info['service_type']
            risk_tier = service_info['risk_tier']
            
            for network, addresses in known_addresses.items():
                for address in addresses:
                    self.service_database[address.lower()] = ServiceIdentification(
                        address=address,
                        service_name=service_name,
                        service_type=service_type,
                        risk_tier=risk_tier,
                        confidence=0.95,  # High confidence for known addresses
                        source='known_database',
                        network=network,
                        last_updated=datetime.now(timezone.utc)
                    )
    
    def _compile_patterns(self):
        """Compile regex patterns for efficient matching"""
        self.compiled_patterns = {}
        
        for service_name, service_info in self.service_patterns.items():
            patterns = service_info.get('patterns', [])
            if patterns:
                self.compiled_patterns[service_name] = [
                    re.compile(pattern, re.IGNORECASE) for pattern in patterns
                ]
    
    def identify_service(self, address: str, network: str = 'bitcoin') -> Optional[ServiceIdentification]:
        """
        Identify service type for a cryptocurrency address.
        
        Args:
            address: Cryptocurrency address to identify
            network: Blockchain network (bitcoin, ethereum, etc.)
            
        Returns:
            ServiceIdentification if found, None otherwise
        """
        address_lower = address.lower()
        
        # First check known database
        if address_lower in self.service_database:
            return self.service_database[address_lower]
        
        # Pattern matching identification
        if self.enable_pattern_matching:
            pattern_result = self._identify_by_pattern(address, network)
            if pattern_result:
                return pattern_result
        
        # API-based identification (placeholder)
        if self.enable_api_lookups:
            api_result = self._identify_by_api(address, network)
            if api_result:
                return api_result
        
        return None
    
    def _identify_by_pattern(self, address: str, network: str) -> Optional[ServiceIdentification]:
        """Identify service using address patterns"""
        
        for service_name, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.match(address):
                    service_info = self.service_patterns[service_name]
                    
                    return ServiceIdentification(
                        address=address,
                        service_name=service_name,
                        service_type=service_info['service_type'],
                        risk_tier=service_info['risk_tier'],
                        confidence=0.6,  # Medium confidence for pattern matching
                        source='pattern_matching',
                        network=network,
                        additional_info={'matched_pattern': pattern.pattern}
                    )
        
        return None
    
    def _identify_by_api(self, address: str, network: str) -> Optional[ServiceIdentification]:
        """Identify service using external APIs (placeholder)"""
        # This would integrate with services like:
        # - OXT API
        # - Chainalysis API
        # - BlockCypher API
        # - Custom exchange APIs
        
        # For now, return None (not implemented)
        return None
    
    def lookup_address(self, address: str, network: str = 'bitcoin') -> Optional[Dict[str, Any]]:
        """
        Look up service identification for an address.
        
        Args:
            address: Cryptocurrency address to look up
            network: Blockchain network
            
        Returns:
            Dictionary containing service identification data
        """
        identification = self.identify_service(address, network)
        
        if not identification:
            return None
        
        # Build comprehensive result
        result = {
            'address': address,
            'network': network,
            'found_service_data': True,
            'timestamp': datetime.utcnow().isoformat(),
            'service_identification': {
                'service_name': identification.service_name,
                'service_type': identification.service_type.value,
                'risk_tier': identification.risk_tier.value,
                'confidence': identification.confidence,
                'source': identification.source,
                'additional_info': identification.additional_info
            },
            'risk_assessment': self._assess_service_risk(identification),
            'compliance_flags': self._get_compliance_flags(identification)
        }
        
        return result
    
    def _assess_service_risk(self, identification: ServiceIdentification) -> Dict[str, Any]:
        """Assess risk based on service identification"""
        
        # Risk score mapping
        risk_score_map = {
            RiskTier.VERY_HIGH: 0.9,
            RiskTier.HIGH: 0.7,
            RiskTier.MEDIUM: 0.5,
            RiskTier.LOW: 0.2,
            RiskTier.VERY_LOW: 0.1
        }
        
        risk_score = risk_score_map.get(identification.risk_tier, 0.5)
        
        # Adjust based on service type
        service_adjustments = {
            ServiceType.MIXER: 0.1,           # Increase risk for mixers
            ServiceType.DARKNET_MARKET: 0.05, # Maximum risk for darknet
            ServiceType.P2P_EXCHANGE: 0.05,   # Increase for unregulated P2P
            ServiceType.INSTITUTIONAL: -0.1,   # Decrease for institutional
            ServiceType.EXCHANGE: -0.05       # Slight decrease for exchanges
        }
        
        adjustment = service_adjustments.get(identification.service_type, 0)
        risk_score = max(0.0, min(1.0, risk_score + adjustment))
        
        # Generate risk indicators
        risk_indicators = []
        if identification.service_type == ServiceType.MIXER:
            risk_indicators.append('privacy_mixing_service')
        if identification.service_type == ServiceType.DARKNET_MARKET:
            risk_indicators.append('darknet_marketplace')
        if identification.risk_tier in [RiskTier.VERY_HIGH, RiskTier.HIGH]:
            risk_indicators.append('high_risk_service_category')
        
        return {
            'risk_score': risk_score,
            'risk_tier': identification.risk_tier.value,
            'confidence': identification.confidence,
            'primary_concerns': risk_indicators,
            'service_category_risk': identification.service_type.value
        }
    
    def _get_compliance_flags(self, identification: ServiceIdentification) -> List[str]:
        """Get compliance-related flags for the service"""
        flags = []
        
        if identification.service_type == ServiceType.MIXER:
            flags.append('privacy_enhancing_service')
            flags.append('aml_reporting_required')
        
        if identification.service_type == ServiceType.DARKNET_MARKET:
            flags.append('illegal_marketplace')
            flags.append('law_enforcement_attention')
        
        if identification.service_type == ServiceType.GAMBLING:
            flags.append('gambling_service')
            flags.append('jurisdiction_restrictions')
        
        if identification.risk_tier == RiskTier.VERY_HIGH:
            flags.append('enhanced_due_diligence_required')
        
        return flags
    
    def analyze_address(self, address: str) -> Optional[WalletAnalysis]:
        """
        Analyze an address for service identification and return structured analysis.
        
        Args:
            address: Cryptocurrency address to analyze
            
        Returns:
            WalletAnalysis containing service identification assessment
        """
        try:
            # Determine likely network (basic heuristic)
            network = self._detect_network(address)
            
            # Look up service identification
            data = self.lookup_address(address, network)
            
            if not data or not data.get('found_service_data'):
                return None
            
            # Parse into risk factors
            risk_factors = self.parse_risk_factors(data, address)
            
            # Create wallet analysis
            service_id = data.get('service_identification', {})
            risk_assessment = data.get('risk_assessment', {})
            
            risk_score = risk_assessment.get('risk_score', 0.0)
            is_flagged = risk_assessment.get('risk_tier') in ['very_high', 'high']
            
            # Create summary
            service_name = service_id.get('service_name', 'Unknown')
            service_type = service_id.get('service_type', 'other')
            summary = f"Service identification: {service_name} ({service_type})"
            
            analysis = WalletAnalysis(
                address=address,
                analysis_timestamp=datetime.now(timezone.utc),
                data_sources=[self.source_name],
                risk_factors=risk_factors,
                overall_risk_score=risk_score,
                risk_level=self._score_to_risk_level(risk_score),
                confidence_score=service_id.get('confidence', 0.0),
                is_flagged=is_flagged,
                summary=summary,
                raw_data=data
            )
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing address {address}: {e}")
            return None
    
    def _detect_network(self, address: str) -> str:
        """Basic network detection based on address format"""
        if address.startswith('0x') and len(address) == 42:
            return 'ethereum'
        elif address.startswith(('1', '3', 'bc1')):
            return 'bitcoin'
        elif address.startswith('L'):
            return 'litecoin'
        else:
            return 'bitcoin'  # Default fallback
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse service identification data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_service_data'):
            return risk_factors
        
        service_id = raw_data.get('service_identification', {})
        risk_assessment = raw_data.get('risk_assessment', {})
        compliance_flags = raw_data.get('compliance_flags', [])
        
        service_name = service_id.get('service_name', 'Unknown')
        service_type = service_id.get('service_type', 'other')
        risk_tier = service_id.get('risk_tier', 'medium')
        confidence = service_id.get('confidence', 0.0)
        
        # Convert risk tier to RiskLevel
        risk_level_map = {
            'very_high': RiskLevel.CRITICAL,
            'high': RiskLevel.HIGH,
            'medium': RiskLevel.MEDIUM,
            'low': RiskLevel.LOW,
            'very_low': RiskLevel.LOW
        }
        
        risk_level = risk_level_map.get(risk_tier, RiskLevel.MEDIUM)
        
        # Create main service identification risk factor
        description = f"Address identified as {service_name} ({service_type})"
        
        # Add warning for high-risk services
        if risk_tier in ['very_high', 'high']:
            description = f"⚠️ HIGH RISK SERVICE: {description}"
        
        risk_factor = RiskFactor(
            type=f"service_identification_{service_type}",
            description=description,
            risk_level=risk_level,
            confidence=confidence,
            source=DataSourceType.COMMERCIAL,
            raw_data={
                'service_name': service_name,
                'service_type': service_type,
                'risk_tier': risk_tier,
                'identification_source': service_id.get('source'),
                'network': raw_data.get('network')
            }
        )
        
        risk_factors.append(risk_factor)
        
        # Add compliance flags as separate risk factors
        for flag in compliance_flags:
            flag_risk_level = RiskLevel.HIGH if 'illegal' in flag or 'law_enforcement' in flag else RiskLevel.MEDIUM
            
            risk_factors.append(RiskFactor(
                type=f"compliance_flag_{flag}",
                description=f"Compliance concern: {flag.replace('_', ' ').title()}",
                risk_level=flag_risk_level,
                confidence=confidence,
                source=DataSourceType.COMMERCIAL,
                raw_data={'compliance_flag': flag}
            ))
        
        return risk_factors
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric risk score to RiskLevel enum"""
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def get_service_statistics(self) -> Dict[str, Any]:
        """Get statistics about identified services"""
        service_type_counts = {}
        risk_tier_counts = {}
        network_counts = {}
        
        for service_id in self.service_database.values():
            # Service type distribution
            service_type = service_id.service_type.value
            service_type_counts[service_type] = service_type_counts.get(service_type, 0) + 1
            
            # Risk tier distribution
            risk_tier = service_id.risk_tier.value
            risk_tier_counts[risk_tier] = risk_tier_counts.get(risk_tier, 0) + 1
            
            # Network distribution
            network = service_id.network
            network_counts[network] = network_counts.get(network, 0) + 1
        
        return {
            'total_services': len(self.service_database),
            'service_type_distribution': service_type_counts,
            'risk_tier_distribution': risk_tier_counts,
            'network_distribution': network_counts,
            'pattern_matching_enabled': self.enable_pattern_matching,
            'api_lookups_enabled': self.enable_api_lookups
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get exchange service identifier statistics"""
        return self.get_service_statistics()