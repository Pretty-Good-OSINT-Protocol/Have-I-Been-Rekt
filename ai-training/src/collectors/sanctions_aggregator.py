"""
Sanctions Aggregator - combines OFAC and Chainalysis sanctions data
for comprehensive compliance screening.
"""

from typing import Dict, List, Optional, Any, Set
from datetime import datetime
import logging

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin
from .ofac_sanctions import OFACSanctionsCollector
from .chainalysis_client import ChainanalysisClient


class SanctionsAggregator(BaseDataCollector, LoggingMixin):
    """
    Aggregates sanctions data from multiple sources (OFAC, Chainalysis)
    to provide comprehensive compliance screening.
    """
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # Initialize component collectors
        self.ofac_collector = OFACSanctionsCollector(config, cache_dir, logger)
        self.chainalysis_client = ChainanalysisClient(config, cache_dir, logger)
        
        # Track which sources are available
        self.available_sources = self._check_available_sources()
        
        self.logger.info(
            "Sanctions aggregator initialized",
            available_sources=list(self.available_sources)
        )
    
    @property
    def source_name(self) -> str:
        return "sanctions_aggregator"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.SANCTIONS
    
    def _check_available_sources(self) -> Set[str]:
        """Check which data sources are available and configured"""
        sources = set()
        
        # OFAC is always available (public data)
        sources.add('ofac')
        
        # Chainalysis requires API key
        if self.config.get('api_keys', {}).get('chainalysis'):
            sources.add('chainalysis')
            
            # Validate API key
            if not self.chainalysis_client.validate_api_key():
                self.logger.warning("Chainalysis API key validation failed")
                sources.discard('chainalysis')
        
        return sources
    
    def collect_address_data(self, address: str) -> Optional[Dict[str, Any]]:
        """Collect comprehensive sanctions data for an address"""
        results = {
            'address': address,
            'timestamp': datetime.utcnow().isoformat(),
            'sources_checked': [],
            'sanctions_found': False,
            'ofac_result': None,
            'chainalysis_result': None,
            'aggregated_risk': {
                'is_sanctioned': False,
                'risk_score': 0.0,
                'confidence': 0.0,
                'primary_concern': None,
                'sources': []
            }
        }
        
        # Collect OFAC data
        if 'ofac' in self.available_sources:
            try:
                ofac_data = self.ofac_collector.collect_address_data(address)
                results['ofac_result'] = ofac_data
                results['sources_checked'].append('ofac')
                
                if ofac_data and ofac_data.get('sanctioned'):
                    results['sanctions_found'] = True
                    results['aggregated_risk']['is_sanctioned'] = True
                    results['aggregated_risk']['sources'].append('ofac')
                    
            except Exception as e:
                self.logger.error("OFAC data collection failed", error=str(e))
        
        # Collect Chainalysis data
        if 'chainalysis' in self.available_sources:
            try:
                chainalysis_data = self.chainalysis_client.collect_address_data(address)
                results['chainalysis_result'] = chainalysis_data
                results['sources_checked'].append('chainalysis')
                
                if chainalysis_data and chainalysis_data.get('is_sanctioned'):
                    results['sanctions_found'] = True
                    results['aggregated_risk']['is_sanctioned'] = True
                    results['aggregated_risk']['sources'].append('chainalysis')
                    
            except Exception as e:
                self.logger.error("Chainalysis data collection failed", error=str(e))
        
        # Aggregate risk assessment
        self._calculate_aggregated_risk(results)
        
        return results
    
    def _calculate_aggregated_risk(self, results: Dict[str, Any]):
        """Calculate aggregated risk score from multiple sources"""
        ofac_data = results.get('ofac_result')
        chainalysis_data = results.get('chainalysis_result')
        aggregated = results['aggregated_risk']
        
        risk_scores = []
        confidence_scores = []
        concerns = []
        
        # Process OFAC results
        if ofac_data and ofac_data.get('sanctioned'):
            risk_scores.append(1.0)  # Maximum risk for OFAC sanctions
            confidence_scores.append(1.0)  # Maximum confidence for official data
            
            entity = ofac_data.get('entity', {})
            program = entity.get('primary_program', 'Unknown')
            concerns.append(f"OFAC sanctions ({program})")
        
        # Process Chainalysis results
        if chainalysis_data:
            chainalysis_risk = chainalysis_data.get('risk_score', 0)
            chainalysis_confidence = chainalysis_data.get('confidence', 0)
            
            if chainalysis_risk > 0:
                risk_scores.append(chainalysis_risk)
                confidence_scores.append(chainalysis_confidence)
                
                category = chainalysis_data.get('category', 'unknown')
                if chainalysis_data.get('is_sanctioned'):
                    concerns.append(f"Chainalysis sanctions ({category})")
                elif chainalysis_risk > 0.5:
                    concerns.append(f"High-risk category ({category})")
        
        # Calculate final scores
        if risk_scores:
            # Use maximum risk score (most conservative approach)
            aggregated['risk_score'] = max(risk_scores)
            
            # Average confidence weighted by risk scores
            total_weight = sum(risk_scores)
            if total_weight > 0:
                weighted_confidence = sum(
                    risk * conf for risk, conf in zip(risk_scores, confidence_scores)
                ) / total_weight
                aggregated['confidence'] = weighted_confidence
            else:
                aggregated['confidence'] = sum(confidence_scores) / len(confidence_scores)
        else:
            # No risks found - low risk, moderate confidence
            aggregated['risk_score'] = 0.0
            aggregated['confidence'] = 0.7 if results['sources_checked'] else 0.1
        
        # Set primary concern
        if concerns:
            aggregated['primary_concern'] = concerns[0]  # Most serious concern first
            aggregated['all_concerns'] = concerns
        
        # Log significant findings
        if aggregated['is_sanctioned']:
            self.logger.warning(
                "SANCTIONED ADDRESS DETECTED",
                address=results['address'][:10] + "...",
                risk_score=aggregated['risk_score'],
                sources=aggregated['sources'],
                concerns=concerns
            )
        elif aggregated['risk_score'] > 0.5:
            self.logger.info(
                "High-risk address detected",
                address=results['address'][:10] + "...",
                risk_score=aggregated['risk_score'],
                primary_concern=aggregated['primary_concern']
            )
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse aggregated sanctions data into risk factors"""
        risk_factors = []
        
        if not raw_data:
            return risk_factors
        
        # Parse OFAC risk factors
        if raw_data.get('ofac_result'):
            ofac_factors = self.ofac_collector.parse_risk_factors(
                raw_data['ofac_result'], address
            )
            risk_factors.extend(ofac_factors)
        
        # Parse Chainalysis risk factors
        if raw_data.get('chainalysis_result'):
            chainalysis_factors = self.chainalysis_client.parse_risk_factors(
                raw_data['chainalysis_result'], address
            )
            risk_factors.extend(chainalysis_factors)
        
        # Add aggregated assessment if we have data from multiple sources
        aggregated_risk = raw_data.get('aggregated_risk', {})
        sources_checked = raw_data.get('sources_checked', [])
        
        if len(sources_checked) > 1 and aggregated_risk.get('risk_score', 0) > 0:
            # Create summary risk factor for multi-source analysis
            all_concerns = aggregated_risk.get('all_concerns', [])
            primary_concern = aggregated_risk.get('primary_concern', 'Multiple risk indicators')
            
            summary_factor = RiskFactor(
                source=self.source_name,
                factor_type="multi_source_analysis",
                severity=RiskLevel.CRITICAL if aggregated_risk.get('is_sanctioned') else RiskLevel.HIGH,
                weight=1.0 if aggregated_risk.get('is_sanctioned') else 0.8,
                description=f"Multi-source analysis: {primary_concern}",
                reference_url="https://github.com/Pretty-Good-OSINT-Protocol/Have-I-Been-Rekt",
                confidence=aggregated_risk.get('confidence', 0.5),
                report_count=len(sources_checked)
            )
            
            # Add to beginning of list (highest priority)
            risk_factors.insert(0, summary_factor)
        
        return risk_factors
    
    def batch_screen_addresses(self, addresses: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
        """Screen multiple addresses for sanctions"""
        results = {}
        
        for address in addresses:
            try:
                results[address] = self.collect_address_data(address)
            except Exception as e:
                self.logger.error(
                    "Failed to screen address in batch",
                    address=address,
                    error=str(e)
                )
                results[address] = None
        
        return results
    
    def get_coverage_stats(self) -> Dict[str, Any]:
        """Get statistics about data source coverage"""
        stats = {
            'available_sources': list(self.available_sources),
            'total_sources': 2,  # OFAC + Chainalysis
            'coverage_percentage': len(self.available_sources) / 2 * 100,
            'source_details': {}
        }
        
        # OFAC stats
        if 'ofac' in self.available_sources:
            try:
                ofac_stats = self.ofac_collector.get_statistics()
                stats['source_details']['ofac'] = ofac_stats
            except Exception as e:
                self.logger.error("Failed to get OFAC stats", error=str(e))
                stats['source_details']['ofac'] = {'error': str(e)}
        
        # Chainalysis stats
        if 'chainalysis' in self.available_sources:
            try:
                chainalysis_stats = self.chainalysis_client.get_usage_stats()
                stats['source_details']['chainalysis'] = chainalysis_stats
            except Exception as e:
                self.logger.error("Failed to get Chainalysis stats", error=str(e))
                stats['source_details']['chainalysis'] = {'error': str(e)}
        
        return stats
    
    def ensure_data_ready(self) -> bool:
        """Ensure all data sources are loaded and ready"""
        success = True
        
        # Ensure OFAC data is loaded
        if 'ofac' in self.available_sources:
            try:
                if not self.ofac_collector.ensure_data_loaded():
                    self.logger.error("Failed to load OFAC data")
                    success = False
            except Exception as e:
                self.logger.error("Error ensuring OFAC data ready", error=str(e))
                success = False
        
        # Chainalysis doesn't require pre-loading (API-based)
        if 'chainalysis' in self.available_sources:
            if not self.chainalysis_client.validate_api_key():
                self.logger.warning("Chainalysis API key validation failed")
                # Don't mark as failure since OFAC might still work
        
        return success
    
    def analyze_address(self, address: str) -> Optional[WalletAnalysis]:
        """Complete sanctions analysis workflow for an address"""
        if not self.ensure_data_ready():
            self.logger.error("Data sources not ready for analysis")
            return None
        
        return super().analyze_address(address)