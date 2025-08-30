"""
Community Scam Database Aggregator - combines multiple community-driven
threat intelligence sources for comprehensive scam detection.

Integrates:
- CryptoScamDB (GitHub community database)
- Chainabuse (community abuse reports)
- ScamSearch.io (global scammer database)
- Whale Alert (large transaction monitoring & suspicious activity detection)
"""

from typing import Dict, List, Optional, Any, Set
from datetime import datetime
import logging

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin
from .cryptoscamdb_collector import CryptoScamDBCollector
from .chainabuse_scraper import ChainabuseScraper  
from .scamsearch_client import ScamSearchClient
from .whale_alert_client import WhaleAlertClient


class CommunityScamAggregator(BaseDataCollector, LoggingMixin):
    """
    Aggregates scam data from multiple community sources to provide
    comprehensive community-driven threat intelligence.
    """
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # Initialize component collectors
        self.cryptoscamdb = CryptoScamDBCollector(config, cache_dir, logger)
        self.chainabuse = ChainabuseScraper(config, cache_dir, logger)
        self.scamsearch = ScamSearchClient(config, cache_dir, logger)
        self.whale_alert = WhaleAlertClient(config, cache_dir, logger)
        
        # Track available sources
        self.available_sources = self._check_available_sources()
        
        self.logger.info(
            "Community scam aggregator initialized",
            available_sources=list(self.available_sources)
        )
    
    @property
    def source_name(self) -> str:
        return "community_scam_aggregator"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.SCAM_DATABASE
    
    def _check_available_sources(self) -> Set[str]:
        """Check which community sources are available and configured"""
        sources = set()
        
        # CryptoScamDB is always available (public GitHub data)
        sources.add('cryptoscamdb')
        
        # Chainabuse requires ethical scraping to be enabled
        chainabuse_config = self.config.get('data_sources', {}).get('chainabuse', {})
        if chainabuse_config.get('enabled', True):
            sources.add('chainabuse')
        
        # ScamSearch.io requires API key for full functionality
        if self.config.get('api_keys', {}).get('scamsearch'):
            sources.add('scamsearch')
            
            # Validate API key
            if not self.scamsearch.validate_api_key():
                self.logger.warning("ScamSearch.io API key validation failed")
                sources.discard('scamsearch')
        
        # Whale Alert requires API key for functionality
        whale_config = self.config.get('community_scam_sources', {}).get('whale_alert', {})
        if whale_config.get('enabled', False) and whale_config.get('api_key'):
            sources.add('whale_alert')
        
        return sources
    
    def collect_address_data(self, address: str) -> Optional[Dict[str, Any]]:
        """Collect comprehensive community scam data for an address"""
        results = {
            'address': address,
            'timestamp': datetime.utcnow().isoformat(),
            'sources_checked': [],
            'scam_reports_found': False,
            'cryptoscamdb_result': None,
            'chainabuse_result': None,
            'scamsearch_result': None,
            'whale_alert_result': None,
            'aggregated_assessment': {
                'is_reported_scam': False,
                'total_reports': 0,
                'risk_score': 0.0,
                'confidence': 0.0,
                'primary_scam_types': [],
                'reporting_sources': []
            }
        }
        
        # Collect CryptoScamDB data
        if 'cryptoscamdb' in self.available_sources:
            try:
                cryptoscamdb_data = self.cryptoscamdb.collect_address_data(address)
                results['cryptoscamdb_result'] = cryptoscamdb_data
                results['sources_checked'].append('cryptoscamdb')
                
                if cryptoscamdb_data and cryptoscamdb_data.get('found_in_database'):
                    results['scam_reports_found'] = True
                    results['aggregated_assessment']['reporting_sources'].append('cryptoscamdb')
                    
            except Exception as e:
                self.logger.error("CryptoScamDB collection failed", error=str(e))
        
        # Collect Chainabuse data
        if 'chainabuse' in self.available_sources:
            try:
                chainabuse_data = self.chainabuse.collect_address_data(address)
                results['chainabuse_result'] = chainabuse_data
                results['sources_checked'].append('chainabuse')
                
                if chainabuse_data and chainabuse_data.get('found_in_chainabuse'):
                    results['scam_reports_found'] = True
                    results['aggregated_assessment']['reporting_sources'].append('chainabuse')
                    
            except Exception as e:
                self.logger.error("Chainabuse collection failed", error=str(e))
        
        # Collect ScamSearch.io data
        if 'scamsearch' in self.available_sources:
            try:
                scamsearch_data = self.scamsearch.collect_address_data(address)
                results['scamsearch_result'] = scamsearch_data
                results['sources_checked'].append('scamsearch')
                
                if scamsearch_data and scamsearch_data.get('found_in_scamsearch'):
                    results['scam_reports_found'] = True
                    results['aggregated_assessment']['reporting_sources'].append('scamsearch')
                    
            except Exception as e:
                self.logger.error("ScamSearch collection failed", error=str(e))
        
        # Collect Whale Alert data
        if 'whale_alert' in self.available_sources:
            try:
                whale_alert_data = self.whale_alert.lookup_address(address)
                results['whale_alert_result'] = whale_alert_data
                results['sources_checked'].append('whale_alert')
                
                if whale_alert_data and (whale_alert_data.get('found_in_whale_alert') or 
                                       whale_alert_data.get('suspicious_activity_detected')):
                    results['scam_reports_found'] = True
                    results['aggregated_assessment']['reporting_sources'].append('whale_alert')
                    
            except Exception as e:
                self.logger.error("Whale Alert collection failed", error=str(e))
        
        # Calculate aggregated assessment
        self._calculate_aggregated_assessment(results)
        
        return results
    
    def _calculate_aggregated_assessment(self, results: Dict[str, Any]):
        """Calculate aggregated risk assessment from multiple community sources"""
        cryptoscamdb_data = results.get('cryptoscamdb_result')
        chainabuse_data = results.get('chainabuse_result')
        scamsearch_data = results.get('scamsearch_result')
        whale_alert_data = results.get('whale_alert_result')
        assessment = results['aggregated_assessment']
        
        total_reports = 0
        risk_scores = []
        confidence_scores = []
        scam_types = set()
        
        # Process CryptoScamDB results
        if cryptoscamdb_data and cryptoscamdb_data.get('found_in_database'):
            db_reports = cryptoscamdb_data.get('report_count', 0)
            total_reports += db_reports
            
            # Extract risk score (convert risk level to numeric)
            highest_risk = cryptoscamdb_data.get('highest_risk_level', 'medium')
            risk_score = self._risk_level_to_score(highest_risk)
            confidence = cryptoscamdb_data.get('average_confidence', 0.7)
            
            risk_scores.append(risk_score * 0.8)  # Weight for CryptoScamDB
            confidence_scores.append(confidence)
            
            # Extract scam types
            for report in cryptoscamdb_data.get('reports', []):
                if report.get('category'):
                    scam_types.add(report['category'].lower())
        
        # Process Chainabuse results
        if chainabuse_data and chainabuse_data.get('found_in_chainabuse'):
            abuse_reports = chainabuse_data.get('report_count', 0)
            total_reports += abuse_reports
            
            highest_risk = chainabuse_data.get('highest_risk_level', 'medium')
            risk_score = self._risk_level_to_score(highest_risk)
            confidence = chainabuse_data.get('average_confidence', 0.6)
            
            risk_scores.append(risk_score * 0.7)  # Weight for Chainabuse
            confidence_scores.append(confidence)
            
            # Extract abuse types
            abuse_types = chainabuse_data.get('abuse_types', [])
            scam_types.update([t.lower() for t in abuse_types if t])
        
        # Process ScamSearch.io results
        if scamsearch_data and scamsearch_data.get('found_in_scamsearch'):
            search_reports = scamsearch_data.get('total_reports', 0)
            total_reports += search_reports
            
            highest_risk = scamsearch_data.get('highest_risk_level', 'medium')
            risk_score = self._risk_level_to_score(highest_risk)
            confidence = scamsearch_data.get('average_confidence', 0.7)
            
            risk_scores.append(risk_score * 0.9)  # Weight for ScamSearch (verified data)
            confidence_scores.append(confidence)
            
            # Extract scam types
            search_scam_types = scamsearch_data.get('scam_types', [])
            scam_types.update([t.lower() for t in search_scam_types if t])
        
        # Process Whale Alert results
        if whale_alert_data and whale_alert_data.get('found_in_whale_alert'):
            # Count whale transactions as "reports" for consistency
            whale_tx_count = whale_alert_data.get('whale_transaction_count', 0)
            total_reports += whale_tx_count
            
            # Check for suspicious activity
            suspicious_activity = whale_alert_data.get('suspicious_activity')
            if suspicious_activity:
                risk_level = suspicious_activity.get('risk_level', 'low')
                risk_score = self._risk_level_to_score(risk_level)
                confidence = suspicious_activity.get('confidence', 0.7)
                
                # Weight Whale Alert higher for suspicious activity
                risk_scores.append(risk_score * 0.85)  
                confidence_scores.append(confidence)
                
                # Extract activity types as scam types
                activity_type = suspicious_activity.get('activity_type', '')
                if activity_type:
                    scam_types.add(activity_type.lower())
                
                # Add tags as additional scam types
                tags = suspicious_activity.get('tags', [])
                scam_types.update([tag.lower() for tag in tags if tag])
            else:
                # Regular whale activity - lower risk but still notable
                if whale_tx_count > 0:
                    risk_scores.append(0.3)  # Moderate risk for whale activity
                    confidence_scores.append(0.5)
                    scam_types.add('whale_activity')
        
        # Calculate final scores
        assessment['total_reports'] = total_reports
        assessment['is_reported_scam'] = total_reports > 0
        
        if risk_scores:
            # Use weighted average of risk scores
            assessment['risk_score'] = sum(risk_scores) / len(risk_scores)
            assessment['confidence'] = sum(confidence_scores) / len(confidence_scores)
            
            # Boost confidence if multiple sources agree
            if len(assessment['reporting_sources']) > 1:
                multi_source_bonus = min(0.2, (len(assessment['reporting_sources']) - 1) * 0.1)
                assessment['confidence'] = min(1.0, assessment['confidence'] + multi_source_bonus)
        else:
            assessment['risk_score'] = 0.0
            assessment['confidence'] = 0.8  # High confidence in "clean" result if checked multiple sources
        
        # Set primary scam types (top 3)
        assessment['primary_scam_types'] = list(scam_types)[:3]
        
        # Log significant findings
        if assessment['is_reported_scam']:
            self.logger.warning(
                "SCAM REPORTS FOUND in community databases",
                address=results['address'][:10] + "...",
                total_reports=total_reports,
                sources=assessment['reporting_sources'],
                scam_types=list(scam_types)[:3],
                risk_score=assessment['risk_score']
            )
        elif len(results['sources_checked']) > 1:
            self.logger.info(
                "Address checked against community databases - clean",
                address=results['address'][:10] + "...",
                sources_checked=len(results['sources_checked'])
            )
    
    def _risk_level_to_score(self, risk_level: str) -> float:
        """Convert risk level string to numeric score"""
        mapping = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
            'clean': 0.0
        }
        return mapping.get(risk_level.lower(), 0.5)
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse aggregated community data into risk factors"""
        risk_factors = []
        
        if not raw_data:
            return risk_factors
        
        # Parse risk factors from each source
        if raw_data.get('cryptoscamdb_result'):
            cryptoscamdb_factors = self.cryptoscamdb.parse_risk_factors(
                raw_data['cryptoscamdb_result'], address
            )
            risk_factors.extend(cryptoscamdb_factors)
        
        if raw_data.get('chainabuse_result'):
            chainabuse_factors = self.chainabuse.parse_risk_factors(
                raw_data['chainabuse_result'], address
            )
            risk_factors.extend(chainabuse_factors)
        
        if raw_data.get('scamsearch_result'):
            scamsearch_factors = self.scamsearch.parse_risk_factors(
                raw_data['scamsearch_result'], address
            )
            risk_factors.extend(scamsearch_factors)
        
        if raw_data.get('whale_alert_result'):
            whale_alert_factors = self.whale_alert.parse_risk_factors(
                raw_data['whale_alert_result'], address
            )
            risk_factors.extend(whale_alert_factors)
        
        # Add aggregated community assessment if we have data from multiple sources
        assessment = raw_data.get('aggregated_assessment', {})
        sources_checked = raw_data.get('sources_checked', [])
        reporting_sources = assessment.get('reporting_sources', [])
        
        if len(reporting_sources) > 1 and assessment.get('is_reported_scam'):
            # Create summary risk factor for multi-source community reports
            total_reports = assessment.get('total_reports', 0)
            risk_score = assessment.get('risk_score', 0)
            primary_types = assessment.get('primary_scam_types', [])
            
            # Determine severity based on aggregated risk
            if risk_score >= 0.8:
                severity = RiskLevel.HIGH
            elif risk_score >= 0.6:
                severity = RiskLevel.MEDIUM
            else:
                severity = RiskLevel.MEDIUM  # Default for community reports
            
            # Build description
            source_names = {
                'cryptoscamdb': 'CryptoScamDB',
                'chainabuse': 'Chainabuse',
                'scamsearch': 'ScamSearch'
            }
            source_list = [source_names.get(s, s) for s in reporting_sources]
            
            description = f"Address reported across {len(reporting_sources)} community databases: {', '.join(source_list)}"
            if total_reports > 1:
                description += f" ({total_reports} total reports)"
            if primary_types:
                description += f" - Types: {', '.join(primary_types[:2])}"
            
            community_factor = RiskFactor(
                source=self.source_name,
                factor_type="multi_source_community_reports",
                severity=severity,
                weight=0.85,  # High weight for multi-source agreement
                description=description,
                reference_url="https://github.com/Pretty-Good-OSINT-Protocol/Have-I-Been-Rekt",
                confidence=assessment.get('confidence', 0.7),
                report_count=total_reports
            )
            
            # Add to beginning of list (highest priority)
            risk_factors.insert(0, community_factor)
        
        return risk_factors
    
    def cross_reference_identity(self, email: Optional[str] = None, username: Optional[str] = None,
                                crypto_address: Optional[str] = None) -> Dict[str, Any]:
        """Cross-reference multiple identity indicators across community databases"""
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'identifiers_checked': {},
            'cross_references_found': False,
            'scamsearch_results': [],
            'linked_addresses': set(),
            'linked_scam_types': set(),
            'risk_assessment': {
                'overall_risk_score': 0.0,
                'confidence': 0.0,
                'linked_identities': 0
            }
        }
        
        # Build identifier dictionary
        identifiers = {}
        if email:
            identifiers['email'] = email
            results['identifiers_checked']['email'] = email
        if username:
            identifiers['username'] = username
            results['identifiers_checked']['username'] = username
        if crypto_address:
            identifiers['crypto_address'] = crypto_address
            results['identifiers_checked']['crypto_address'] = crypto_address
        
        # Cross-reference through ScamSearch if available
        if 'scamsearch' in self.available_sources and identifiers:
            try:
                scamsearch_entries = self.scamsearch.cross_reference_search(identifiers)
                
                if scamsearch_entries:
                    results['cross_references_found'] = True
                    results['scamsearch_results'] = [
                        self.scamsearch._entry_to_dict(entry) for entry in scamsearch_entries
                    ]
                    
                    # Extract linked information
                    for entry in scamsearch_entries:
                        if entry.crypto_address:
                            results['linked_addresses'].add(entry.crypto_address)
                        if entry.scam_type:
                            results['linked_scam_types'].add(entry.scam_type)
                    
                    # Calculate risk assessment
                    total_reports = sum(entry.report_count for entry in scamsearch_entries)
                    avg_confidence = sum(entry.confidence_score for entry in scamsearch_entries) / len(scamsearch_entries)
                    max_risk = max(self._risk_level_to_score(entry.risk_level.value) for entry in scamsearch_entries)
                    
                    results['risk_assessment'] = {
                        'overall_risk_score': max_risk,
                        'confidence': avg_confidence,
                        'linked_identities': len(scamsearch_entries),
                        'total_reports': total_reports
                    }
                    
            except Exception as e:
                self.logger.error("Cross-reference search failed", error=str(e))
        
        # Convert sets to lists for JSON serialization
        results['linked_addresses'] = list(results['linked_addresses'])
        results['linked_scam_types'] = list(results['linked_scam_types'])
        
        return results
    
    def get_coverage_statistics(self) -> Dict[str, Any]:
        """Get statistics about community database coverage"""
        stats = {
            'available_sources': list(self.available_sources),
            'total_possible_sources': 3,  # CryptoScamDB + Chainabuse + ScamSearch
            'coverage_percentage': len(self.available_sources) / 3 * 100,
            'source_details': {}
        }
        
        # CryptoScamDB stats
        if 'cryptoscamdb' in self.available_sources:
            try:
                cryptoscamdb_stats = self.cryptoscamdb.get_statistics()
                stats['source_details']['cryptoscamdb'] = cryptoscamdb_stats
            except Exception as e:
                self.logger.error("Failed to get CryptoScamDB stats", error=str(e))
                stats['source_details']['cryptoscamdb'] = {'error': str(e)}
        
        # Chainabuse stats
        if 'chainabuse' in self.available_sources:
            try:
                chainabuse_stats = self.chainabuse.get_statistics()
                stats['source_details']['chainabuse'] = chainabuse_stats
            except Exception as e:
                self.logger.error("Failed to get Chainabuse stats", error=str(e))
                stats['source_details']['chainabuse'] = {'error': str(e)}
        
        # ScamSearch stats
        if 'scamsearch' in self.available_sources:
            try:
                scamsearch_stats = self.scamsearch.get_usage_statistics()
                stats['source_details']['scamsearch'] = scamsearch_stats
            except Exception as e:
                self.logger.error("Failed to get ScamSearch stats", error=str(e))
                stats['source_details']['scamsearch'] = {'error': str(e)}
        
        return stats
    
    def ensure_data_ready(self) -> bool:
        """Ensure all community data sources are loaded and ready"""
        success = True
        
        # Ensure CryptoScamDB data is loaded
        if 'cryptoscamdb' in self.available_sources:
            try:
                if not self.cryptoscamdb.ensure_data_loaded():
                    self.logger.error("Failed to load CryptoScamDB data")
                    success = False
            except Exception as e:
                self.logger.error("Error ensuring CryptoScamDB data ready", error=str(e))
                success = False
        
        # Chainabuse and ScamSearch don't require pre-loading (on-demand)
        
        return success
    
    def analyze_address(self, address: str) -> Optional[WalletAnalysis]:
        """Complete community scam analysis workflow for an address"""
        if not self.ensure_data_ready():
            self.logger.error("Community data sources not ready for analysis")
            return None
        
        return super().analyze_address(address)