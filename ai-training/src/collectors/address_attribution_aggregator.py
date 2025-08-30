"""
Address Attribution Aggregator - combines multiple attribution sources to provide
comprehensive entity mapping and chain of custody analysis for cryptocurrency addresses.

Integrates GraphSense TagPacks, exchange identification, entity relationships, and 
chain of custody tracking for complete address attribution and fund flow analysis.
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
import logging
import asyncio
from dataclasses import dataclass
from enum import Enum

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin
from .graphsense_tagpacks import GraphSenseTagPacksClient
from .exchange_identifier import ExchangeServiceIdentifier
from .entity_relationship_mapper import EntityRelationshipMapper, RelationshipType, EntityRelationship


class AttributionConfidence(Enum):
    """Confidence levels for attribution"""
    VERY_HIGH = "very_high"    # Multiple sources agree, high confidence
    HIGH = "high"              # Strong evidence from reliable sources
    MEDIUM = "medium"          # Some evidence, needs verification
    LOW = "low"                # Weak evidence, speculative
    CONFLICTING = "conflicting"  # Sources disagree


@dataclass
class ChainOfCustodyStep:
    """Represents a step in the chain of custody analysis"""
    step_number: int
    from_address: str
    to_address: str
    transaction_hash: Optional[str]
    timestamp: Optional[datetime]
    amount: Optional[float]
    attribution_from: Optional[str]  # Entity name for source
    attribution_to: Optional[str]    # Entity name for destination
    step_type: str  # e.g., 'direct_transfer', 'exchange_deposit', 'mixer_entry'
    risk_indicators: List[str]
    confidence: float


@dataclass
class ComprehensiveAttribution:
    """Comprehensive attribution result combining all sources"""
    address: str
    primary_attribution: Optional[str]
    attribution_confidence: AttributionConfidence
    entity_type: Optional[str]
    risk_score: float
    all_attributions: List[Dict[str, Any]]
    conflicting_attributions: List[Dict[str, Any]]
    chain_of_custody: Optional[List[ChainOfCustodyStep]]
    relationship_context: Optional[Dict[str, Any]]
    compliance_status: Dict[str, Any]
    investigation_priority: str  # low, medium, high, critical


class AddressAttributionAggregator(BaseDataCollector, LoggingMixin):
    """
    Aggregates address attribution data from multiple sources and provides
    comprehensive entity mapping with chain of custody analysis capabilities.
    """
    
    # Priority weighting for different attribution sources
    SOURCE_WEIGHTS = {
        'graphsense_tagpacks': 0.9,      # High reliability
        'exchange_identifier': 0.8,      # Good for known services
        'entity_relationships': 0.7,     # Behavioral analysis
        'user_provided': 0.95,           # Highest if verified
        'community_reports': 0.6,        # Variable reliability
        'api_lookup': 0.75              # Depends on API quality
    }
    
    # Risk escalation thresholds
    RISK_THRESHOLDS = {
        'investigation_required': 0.7,
        'enhanced_monitoring': 0.5,
        'compliance_flag': 0.4,
        'low_priority': 0.2
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # Initialize component collectors
        self.graphsense_client = GraphSenseTagPacksClient(config, cache_dir, logger)
        self.exchange_identifier = ExchangeServiceIdentifier(config, cache_dir, logger)
        self.relationship_mapper = EntityRelationshipMapper(config, cache_dir, logger)
        
        # Configuration
        self.enable_chain_of_custody = config.get('enable_chain_of_custody', True)
        self.max_custody_depth = config.get('max_custody_depth', 10)
        self.attribution_timeout = config.get('attribution_timeout_seconds', 30)
        self.require_consensus = config.get('require_consensus', False)
        
        # Chain of custody analysis
        self.transaction_api_config = config.get('transaction_api', {})
        
        self.logger.info(
            "Address Attribution Aggregator initialized",
            chain_of_custody_enabled=self.enable_chain_of_custody,
            max_custody_depth=self.max_custody_depth
        )
    
    @property
    def source_name(self) -> str:
        return "address_attribution_aggregator"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.GOVERNMENT  # Highest trust level for aggregated data
    
    async def get_comprehensive_attribution(self, address: str, include_chain_of_custody: bool = True) -> Optional[ComprehensiveAttribution]:
        """
        Get comprehensive attribution combining all available sources.
        
        Args:
            address: Address to analyze
            include_chain_of_custody: Whether to include chain of custody analysis
            
        Returns:
            ComprehensiveAttribution with all available information
        """
        try:
            # Collect attribution data from all sources in parallel
            attribution_tasks = [
                self._get_graphsense_attribution(address),
                self._get_exchange_attribution(address),
                self._get_relationship_attribution(address)
            ]
            
            attributions = await asyncio.gather(*attribution_tasks, return_exceptions=True)
            
            # Filter successful results
            valid_attributions = [
                attr for attr in attributions 
                if not isinstance(attr, Exception) and attr is not None
            ]
            
            if not valid_attributions:
                return None
            
            # Combine and analyze attributions
            combined_attribution = self._combine_attributions(address, valid_attributions)
            
            # Add chain of custody analysis if requested
            if include_chain_of_custody and self.enable_chain_of_custody:
                custody_chain = await self._analyze_chain_of_custody(address)
                combined_attribution.chain_of_custody = custody_chain
            
            # Determine investigation priority
            combined_attribution.investigation_priority = self._determine_investigation_priority(combined_attribution)
            
            return combined_attribution
            
        except Exception as e:
            self.logger.error(f"Error getting comprehensive attribution for {address}: {e}")
            return None
    
    async def _get_graphsense_attribution(self, address: str) -> Optional[Dict[str, Any]]:
        """Get attribution from GraphSense TagPacks"""
        try:
            data = self.graphsense_client.lookup_address(address)
            if data and data.get('found_graphsense_data'):
                primary_attr = data.get('primary_attribution', {})
                return {
                    'source': 'graphsense_tagpacks',
                    'entity_name': primary_attr.get('entity', 'Unknown'),
                    'entity_type': primary_attr.get('category', 'other'),
                    'confidence': primary_attr.get('confidence', 0.0),
                    'risk_level': primary_attr.get('risk_level', 'neutral'),
                    'raw_data': data,
                    'network': primary_attr.get('network', 'unknown')
                }
        except Exception as e:
            self.logger.warning(f"GraphSense attribution failed for {address}: {e}")
        
        return None
    
    async def _get_exchange_attribution(self, address: str) -> Optional[Dict[str, Any]]:
        """Get attribution from exchange identifier"""
        try:
            data = self.exchange_identifier.lookup_address(address)
            if data and data.get('found_service_data'):
                service_id = data.get('service_identification', {})
                return {
                    'source': 'exchange_identifier',
                    'entity_name': service_id.get('service_name', 'Unknown Service'),
                    'entity_type': service_id.get('service_type', 'other'),
                    'confidence': service_id.get('confidence', 0.0),
                    'risk_level': service_id.get('risk_tier', 'medium'),
                    'raw_data': data,
                    'network': data.get('network', 'unknown')
                }
        except Exception as e:
            self.logger.warning(f"Exchange attribution failed for {address}: {e}")
        
        return None
    
    async def _get_relationship_attribution(self, address: str) -> Optional[Dict[str, Any]]:
        """Get attribution from relationship analysis"""
        try:
            data = self.relationship_mapper.lookup_address(address)
            if data and data.get('found_relationship_data'):
                rel_summary = data.get('relationship_summary', {})
                cluster_info = data.get('cluster_info', {})
                
                entity_name = f"Cluster {cluster_info.get('cluster_id', 'Unknown')}" if cluster_info else 'Relationship Analysis'
                
                return {
                    'source': 'entity_relationships',
                    'entity_name': entity_name,
                    'entity_type': cluster_info.get('cluster_type', 'behavioral_cluster'),
                    'confidence': cluster_info.get('confidence', rel_summary.get('risk_score', 0.0)) if cluster_info else rel_summary.get('risk_score', 0.0),
                    'risk_level': self._score_to_risk_tier(rel_summary.get('risk_score', 0.0)),
                    'raw_data': data,
                    'network': 'multi-network'
                }
        except Exception as e:
            self.logger.warning(f"Relationship attribution failed for {address}: {e}")
        
        return None
    
    def _combine_attributions(self, address: str, attributions: List[Dict[str, Any]]) -> ComprehensiveAttribution:
        """Combine multiple attributions into a comprehensive result"""
        
        # Group attributions by consensus
        entity_names = {}
        entity_types = {}
        risk_scores = []
        confidence_scores = []
        
        for attr in attributions:
            source = attr['source']
            weight = self.SOURCE_WEIGHTS.get(source, 0.5)
            
            # Entity name consensus
            entity_name = attr.get('entity_name', 'Unknown')
            if entity_name not in entity_names:
                entity_names[entity_name] = []
            entity_names[entity_name].append((weight, attr))
            
            # Entity type consensus
            entity_type = attr.get('entity_type', 'other')
            if entity_type not in entity_types:
                entity_types[entity_type] = []
            entity_types[entity_type].append((weight, attr))
            
            # Risk and confidence scoring
            confidence = attr.get('confidence', 0.0)
            risk_score = self._risk_tier_to_score(attr.get('risk_level', 'medium'))
            
            risk_scores.append(risk_score * weight)
            confidence_scores.append(confidence * weight)
        
        # Determine primary attribution (highest weighted consensus)
        primary_entity = max(entity_names.items(), key=lambda x: sum(w for w, _ in x[1]))[0]
        primary_type = max(entity_types.items(), key=lambda x: sum(w for w, _ in x[1]))[0]
        
        # Calculate overall scores
        total_weight = sum(self.SOURCE_WEIGHTS.get(attr['source'], 0.5) for attr in attributions)
        avg_risk_score = sum(risk_scores) / total_weight if total_weight > 0 else 0.0
        avg_confidence = sum(confidence_scores) / total_weight if total_weight > 0 else 0.0
        
        # Determine attribution confidence
        attribution_confidence = self._determine_attribution_confidence(entity_names, attributions)
        
        # Identify conflicting attributions
        conflicting = self._identify_conflicts(attributions)
        
        # Create compliance status
        compliance_status = self._assess_compliance_status(primary_entity, primary_type, avg_risk_score)
        
        return ComprehensiveAttribution(
            address=address,
            primary_attribution=primary_entity if primary_entity != 'Unknown' else None,
            attribution_confidence=attribution_confidence,
            entity_type=primary_type,
            risk_score=avg_risk_score,
            all_attributions=attributions,
            conflicting_attributions=conflicting,
            chain_of_custody=None,  # Will be filled later if requested
            relationship_context=self._build_relationship_context(attributions),
            compliance_status=compliance_status,
            investigation_priority='medium'  # Will be determined later
        )
    
    def _determine_attribution_confidence(self, entity_names: Dict[str, List], attributions: List[Dict[str, Any]]) -> AttributionConfidence:
        """Determine confidence level for attribution"""
        if len(attributions) == 1:
            return AttributionConfidence.MEDIUM
        
        # Check for consensus
        max_consensus = max(len(entities) for entities in entity_names.values())
        
        if max_consensus >= len(attributions) * 0.8:  # 80% agreement
            return AttributionConfidence.VERY_HIGH
        elif max_consensus >= len(attributions) * 0.6:  # 60% agreement
            return AttributionConfidence.HIGH
        elif max_consensus >= len(attributions) * 0.4:  # 40% agreement
            return AttributionConfidence.MEDIUM
        else:
            return AttributionConfidence.CONFLICTING
    
    def _identify_conflicts(self, attributions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify conflicting attributions"""
        conflicts = []
        
        if len(attributions) < 2:
            return conflicts
        
        # Compare entity names
        entity_names = set(attr.get('entity_name', 'Unknown') for attr in attributions)
        if len(entity_names) > 1:
            for attr in attributions:
                if attr.get('entity_name') != list(entity_names)[0]:
                    conflicts.append({
                        'type': 'entity_name_conflict',
                        'source': attr['source'],
                        'value': attr.get('entity_name'),
                        'confidence': attr.get('confidence', 0.0)
                    })
        
        return conflicts
    
    def _assess_compliance_status(self, entity: str, entity_type: str, risk_score: float) -> Dict[str, Any]:
        """Assess compliance status based on attribution"""
        status = {
            'aml_risk_level': 'low',
            'kyc_required': False,
            'sanctions_check_required': False,
            'enhanced_monitoring': False,
            'blocking_recommended': False,
            'reporting_required': False
        }
        
        # Risk-based compliance flags
        if risk_score >= 0.8:
            status.update({
                'aml_risk_level': 'critical',
                'kyc_required': True,
                'enhanced_monitoring': True,
                'blocking_recommended': True,
                'reporting_required': True
            })
        elif risk_score >= 0.6:
            status.update({
                'aml_risk_level': 'high',
                'kyc_required': True,
                'enhanced_monitoring': True,
                'reporting_required': True
            })
        elif risk_score >= 0.4:
            status.update({
                'aml_risk_level': 'medium',
                'kyc_required': True,
                'enhanced_monitoring': True
            })
        
        # Entity type specific flags
        if entity_type in ['mixer', 'darknet_market', 'ransomware']:
            status.update({
                'sanctions_check_required': True,
                'blocking_recommended': True,
                'reporting_required': True
            })
        elif entity_type in ['gambling', 'p2p_exchange']:
            status['enhanced_monitoring'] = True
        
        return status
    
    def _build_relationship_context(self, attributions: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Build relationship context from attribution data"""
        relationship_data = None
        
        for attr in attributions:
            if attr['source'] == 'entity_relationships':
                relationship_data = attr.get('raw_data')
                break
        
        if not relationship_data:
            return None
        
        return {
            'direct_connections': relationship_data.get('relationship_summary', {}).get('direct_connections', 0),
            'high_risk_connections': len(relationship_data.get('high_risk_connections', [])),
            'cluster_membership': relationship_data.get('cluster_info') is not None
        }
    
    async def _analyze_chain_of_custody(self, address: str, depth: int = 0) -> Optional[List[ChainOfCustodyStep]]:
        """
        Analyze chain of custody for an address (placeholder for future implementation).
        
        This would integrate with blockchain APIs to trace transaction history
        and build a complete chain of custody analysis.
        """
        # This is a placeholder for chain of custody analysis
        # In a full implementation, this would:
        # 1. Query blockchain APIs for transaction history
        # 2. Follow funds through multiple hops
        # 3. Identify entities at each step
        # 4. Detect suspicious patterns (mixing, layering, etc.)
        # 5. Build temporal analysis of fund movements
        
        if depth >= self.max_custody_depth:
            return None
        
        # For now, return empty list
        # Real implementation would build ChainOfCustodyStep objects
        return []
    
    def _determine_investigation_priority(self, attribution: ComprehensiveAttribution) -> str:
        """Determine investigation priority based on comprehensive analysis"""
        risk_score = attribution.risk_score
        has_conflicts = len(attribution.conflicting_attributions) > 0
        high_risk_entity = attribution.entity_type in ['mixer', 'darknet_market', 'ransomware']
        
        if risk_score >= 0.8 or high_risk_entity:
            return 'critical'
        elif risk_score >= 0.6 or has_conflicts:
            return 'high'
        elif risk_score >= 0.4:
            return 'medium'
        else:
            return 'low'
    
    def _risk_tier_to_score(self, risk_tier: str) -> float:
        """Convert risk tier to numeric score"""
        mapping = {
            'very_high': 0.9,
            'high': 0.7,
            'medium': 0.5,
            'low': 0.2,
            'very_low': 0.1,
            'neutral': 0.1,
            'critical': 0.95
        }
        return mapping.get(risk_tier, 0.5)
    
    def _score_to_risk_tier(self, score: float) -> str:
        """Convert numeric score to risk tier"""
        if score >= 0.8:
            return 'very_high'
        elif score >= 0.6:
            return 'high'
        elif score >= 0.4:
            return 'medium'
        elif score >= 0.2:
            return 'low'
        else:
            return 'very_low'
    
    def lookup_address(self, address: str) -> Optional[Dict[str, Any]]:
        """
        Look up comprehensive address attribution.
        
        Args:
            address: Address to analyze
            
        Returns:
            Dictionary containing comprehensive attribution data
        """
        try:
            # Run async function in sync context
            import asyncio
            attribution = asyncio.run(self.get_comprehensive_attribution(address))
            
            if not attribution:
                return None
            
            return {
                'address': address,
                'found_attribution_data': True,
                'timestamp': datetime.utcnow().isoformat(),
                'primary_attribution': attribution.primary_attribution,
                'entity_type': attribution.entity_type,
                'attribution_confidence': attribution.attribution_confidence.value,
                'risk_score': attribution.risk_score,
                'investigation_priority': attribution.investigation_priority,
                'all_sources': [attr['source'] for attr in attribution.all_attributions],
                'conflicting_attributions': attribution.conflicting_attributions,
                'compliance_status': attribution.compliance_status,
                'relationship_context': attribution.relationship_context,
                'chain_of_custody_available': attribution.chain_of_custody is not None,
                'attribution_assessment': {
                    'confidence': attribution.attribution_confidence.value,
                    'source_count': len(attribution.all_attributions),
                    'has_conflicts': len(attribution.conflicting_attributions) > 0,
                    'risk_level': self._score_to_risk_tier(attribution.risk_score)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error looking up attribution for {address}: {e}")
            return None
    
    def analyze_address(self, address: str) -> Optional[WalletAnalysis]:
        """
        Analyze address with comprehensive attribution and return structured analysis.
        
        Args:
            address: Address to analyze
            
        Returns:
            WalletAnalysis containing comprehensive attribution assessment
        """
        try:
            # Look up comprehensive attribution
            data = self.lookup_address(address)
            
            if not data or not data.get('found_attribution_data'):
                return None
            
            # Parse into risk factors
            risk_factors = self.parse_risk_factors(data, address)
            
            # Create wallet analysis
            risk_score = data.get('risk_score', 0.0)
            is_flagged = data.get('investigation_priority') in ['critical', 'high']
            
            # Create summary
            primary_attr = data.get('primary_attribution')
            entity_type = data.get('entity_type', 'unknown')
            source_count = len(data.get('all_sources', []))
            
            if primary_attr:
                summary = f"Attribution: {primary_attr} ({entity_type}) from {source_count} sources"
            else:
                summary = f"Multi-source attribution analysis: {source_count} sources analyzed"
            
            analysis = WalletAnalysis(
                address=address,
                analysis_timestamp=datetime.now(timezone.utc),
                data_sources=[self.source_name],
                risk_factors=risk_factors,
                overall_risk_score=risk_score,
                risk_level=self._score_to_risk_level(risk_score),
                confidence_score=self._confidence_to_score(data.get('attribution_confidence', 'medium')),
                is_flagged=is_flagged,
                summary=summary,
                raw_data=data
            )
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing address {address}: {e}")
            return None
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse comprehensive attribution data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_attribution_data'):
            return risk_factors
        
        # Primary attribution risk factor
        primary_attr = raw_data.get('primary_attribution')
        entity_type = raw_data.get('entity_type', 'unknown')
        risk_score = raw_data.get('risk_score', 0.0)
        confidence = raw_data.get('attribution_assessment', {}).get('confidence', 'medium')
        
        if primary_attr:
            risk_factors.append(RiskFactor(
                type=f"comprehensive_attribution_{entity_type}",
                description=f"Multi-source attribution: {primary_attr} ({entity_type})",
                risk_level=self._score_to_risk_level(risk_score),
                confidence=self._confidence_to_score(confidence),
                source=DataSourceType.GOVERNMENT,
                raw_data={
                    'primary_attribution': primary_attr,
                    'entity_type': entity_type,
                    'source_count': len(raw_data.get('all_sources', [])),
                    'investigation_priority': raw_data.get('investigation_priority')
                }
            ))
        
        # Conflicting attributions risk factor
        conflicts = raw_data.get('conflicting_attributions', [])
        if conflicts:
            risk_factors.append(RiskFactor(
                type="conflicting_attributions",
                description=f"Attribution conflicts detected: {len(conflicts)} sources disagree",
                risk_level=RiskLevel.MEDIUM,
                confidence=0.8,
                source=DataSourceType.GOVERNMENT,
                raw_data={'conflicts': conflicts}
            ))
        
        # Compliance flags
        compliance = raw_data.get('compliance_status', {})
        if compliance.get('blocking_recommended'):
            risk_factors.append(RiskFactor(
                type="compliance_blocking_recommended",
                description="⚠️ COMPLIANCE: Blocking recommended based on attribution",
                risk_level=RiskLevel.CRITICAL,
                confidence=0.9,
                source=DataSourceType.GOVERNMENT,
                raw_data=compliance
            ))
        elif compliance.get('enhanced_monitoring'):
            risk_factors.append(RiskFactor(
                type="compliance_enhanced_monitoring",
                description="Enhanced monitoring required based on attribution",
                risk_level=RiskLevel.HIGH,
                confidence=0.8,
                source=DataSourceType.GOVERNMENT,
                raw_data=compliance
            ))
        
        return risk_factors
    
    def _confidence_to_score(self, confidence_level: str) -> float:
        """Convert confidence level to numeric score"""
        mapping = {
            'very_high': 0.95,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.3,
            'conflicting': 0.4
        }
        return mapping.get(confidence_level, 0.5)
    
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
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get address attribution aggregator statistics"""
        
        # Get statistics from component collectors
        graphsense_stats = self.graphsense_client.get_statistics()
        exchange_stats = self.exchange_identifier.get_statistics()
        relationship_stats = self.relationship_mapper.get_statistics()
        
        return {
            'component_collectors': {
                'graphsense_tagpacks': graphsense_stats,
                'exchange_identifier': exchange_stats,
                'entity_relationships': relationship_stats
            },
            'aggregator_config': {
                'chain_of_custody_enabled': self.enable_chain_of_custody,
                'max_custody_depth': self.max_custody_depth,
                'consensus_required': self.require_consensus
            },
            'source_weights': self.SOURCE_WEIGHTS,
            'risk_thresholds': self.RISK_THRESHOLDS
        }