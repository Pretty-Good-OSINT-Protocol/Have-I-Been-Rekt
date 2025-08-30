"""
Historical Crime Data Aggregator - combines multiple crime intelligence sources
for comprehensive threat analysis and ML training data preparation.

Integrates:
- Have I Been Pwned (email breach detection)
- Ransomwhere (ransomware payment tracking)
- Elliptic Dataset (ground truth Bitcoin labels)
- VirusTotal OSINT (malware and threat intelligence)
"""

from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timezone
import logging
import numpy as np

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin
from .hibp_client import HIBPClient
from .ransomwhere_processor import RansomwhereProcessor
from .elliptic_dataset_processor import EllipticDatasetProcessor
from .virustotal_client import VirusTotalClient
from .dehashed_client import DeHashedClient
from .shodan_client import ShodanClient


class HistoricalCrimeAggregator(BaseDataCollector, LoggingMixin):
    """
    Aggregates historical crime data from multiple intelligence sources
    to provide comprehensive criminal activity assessment and ML training data.
    """
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # Initialize component collectors
        self.hibp_client = HIBPClient(config, cache_dir, logger)
        self.ransomware_processor = RansomwhereProcessor(config, cache_dir, logger)
        self.elliptic_processor = EllipticDatasetProcessor(config, cache_dir, logger)
        self.virustotal_client = VirusTotalClient(config, cache_dir, logger)
        self.dehashed_client = DeHashedClient(config, cache_dir, logger)
        self.shodan_client = ShodanClient(config, cache_dir, logger)
        
        # Track available sources
        self.available_sources = self._check_available_sources()
        
        self.logger.info(
            "Historical crime data aggregator initialized",
            available_sources=list(self.available_sources)
        )
    
    @property
    def source_name(self) -> str:
        return "historical_crime_aggregator"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.CRIME_DATABASE
    
    def _check_available_sources(self) -> Set[str]:
        """Check which crime intelligence sources are available"""
        sources = set()
        
        # HIBP requires API key
        if self.hibp_client.api_key:
            sources.add('hibp')
        
        # Ransomware processor is always available (uses cached/downloaded data)
        sources.add('ransomware')
        
        # Elliptic processor is available if dataset exists
        if self.elliptic_processor.transactions or self.elliptic_processor.addresses:
            sources.add('elliptic')
        
        # VirusTotal requires API key
        if self.virustotal_client.api_key:
            sources.add('virustotal')
        
        # DeHashed requires API key
        if self.dehashed_client.is_configured():
            sources.add('dehashed')
        
        # Shodan requires API key
        if self.shodan_client.is_configured():
            sources.add('shodan')
        
        return sources
    
    def collect_email_intelligence(self, email: str) -> Optional[Dict[str, Any]]:
        """Collect breach intelligence for email address"""
        results = {
            'email': email,
            'timestamp': datetime.utcnow().isoformat(),
            'sources_checked': [],
            'breach_exposure_found': False,
            'hibp_result': None,
            'dehashed_result': None,
            'aggregated_assessment': {
                'is_compromised': False,
                'breach_count': 0,
                'risk_score': 0.0,
                'confidence': 0.0,
                'primary_concerns': [],
                'analysis_sources': []
            }
        }
        
        # Collect HIBP data
        if 'hibp' in self.available_sources:
            try:
                hibp_data = self.hibp_client.lookup_address(email)
                results['hibp_result'] = hibp_data
                results['sources_checked'].append('hibp')
                
                if hibp_data and hibp_data.get('found_breach_data'):
                    results['aggregated_assessment']['analysis_sources'].append('hibp')
                    
                    if hibp_data.get('total_breaches', 0) > 0:
                        results['breach_exposure_found'] = True
                        
            except Exception as e:
                self.logger.error("HIBP breach check failed", error=str(e))
        
        # Collect DeHashed data
        if 'dehashed' in self.available_sources:
            try:
                dehashed_data = self.dehashed_client.lookup_address(email)
                results['dehashed_result'] = dehashed_data
                results['sources_checked'].append('dehashed')
                
                if dehashed_data and dehashed_data.get('found_dehashed_data'):
                    results['aggregated_assessment']['analysis_sources'].append('dehashed')
                    
                    if dehashed_data.get('total_records', 0) > 0:
                        results['breach_exposure_found'] = True
                        
            except Exception as e:
                self.logger.error("DeHashed breach check failed", error=str(e))
        
        # Calculate aggregated assessment
        self._calculate_email_assessment(results)
        
        return results
    
    def collect_address_intelligence(self, address: str) -> Optional[Dict[str, Any]]:
        """Collect comprehensive crime intelligence for cryptocurrency address"""
        results = {
            'address': address,
            'timestamp': datetime.utcnow().isoformat(),
            'sources_checked': [],
            'criminal_activity_found': False,
            'ransomware_result': None,
            'elliptic_result': None,
            'virustotal_result': None,
            'shodan_result': None,
            'aggregated_assessment': {
                'is_criminal_address': False,
                'criminal_activities': [],
                'risk_score': 0.0,
                'confidence': 0.0,
                'attribution': [],
                'analysis_sources': []
            }
        }
        
        # Collect Ransomware data
        if 'ransomware' in self.available_sources:
            try:
                ransomware_data = self.ransomware_processor.lookup_address(address)
                results['ransomware_result'] = ransomware_data
                results['sources_checked'].append('ransomware')
                
                if ransomware_data and ransomware_data.get('found_ransomware_data'):
                    results['aggregated_assessment']['analysis_sources'].append('ransomware')
                    
                    if ransomware_data.get('is_ransomware_address'):
                        results['criminal_activity_found'] = True
                        
            except Exception as e:
                self.logger.error("Ransomware lookup failed", error=str(e))
        
        # Collect Elliptic data
        if 'elliptic' in self.available_sources:
            try:
                elliptic_data = self.elliptic_processor.lookup_address(address)
                results['elliptic_result'] = elliptic_data
                results['sources_checked'].append('elliptic')
                
                if elliptic_data and elliptic_data.get('found_elliptic_data'):
                    results['aggregated_assessment']['analysis_sources'].append('elliptic')
                    
                    if elliptic_data.get('label') == 'illicit':
                        results['criminal_activity_found'] = True
                        
            except Exception as e:
                self.logger.error("Elliptic lookup failed", error=str(e))
        
        # Collect VirusTotal data
        if 'virustotal' in self.available_sources:
            try:
                vt_data = self.virustotal_client.lookup_address(address)
                results['virustotal_result'] = vt_data
                results['sources_checked'].append('virustotal')
                
                if vt_data and vt_data.get('found_virustotal_data'):
                    results['aggregated_assessment']['analysis_sources'].append('virustotal')
                    
                    if vt_data.get('found_in_malware'):
                        results['criminal_activity_found'] = True
                        
            except Exception as e:
                self.logger.error("VirusTotal lookup failed", error=str(e))
        
        # Collect Shodan infrastructure data (if address looks like IP/domain)
        if 'shodan' in self.available_sources:
            try:
                # Check if address might be an IP or domain for infrastructure analysis
                import re
                ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
                
                if re.match(ip_pattern, address) or re.match(domain_pattern, address):
                    shodan_data = self.shodan_client.lookup_address(address)
                    results['shodan_result'] = shodan_data
                    results['sources_checked'].append('shodan')
                    
                    if shodan_data and shodan_data.get('found_shodan_data'):
                        results['aggregated_assessment']['analysis_sources'].append('shodan')
                        
                        # Infrastructure findings might indicate suspicious activity
                        infra_intel = shodan_data.get('infrastructure_intelligence', {})
                        if infra_intel.get('suspicious_indicators') or infra_intel.get('vulnerability_count', 0) > 5:
                            results['criminal_activity_found'] = True
                
            except Exception as e:
                self.logger.error("Shodan infrastructure lookup failed", error=str(e))
        
        # Calculate aggregated assessment
        self._calculate_address_assessment(results)
        
        return results
    
    def _calculate_email_assessment(self, results: Dict[str, Any]):
        """Calculate aggregated email breach assessment"""
        hibp_data = results.get('hibp_result')
        assessment = results['aggregated_assessment']
        
        if not hibp_data or not hibp_data.get('found_breach_data'):
            assessment['is_compromised'] = False
            assessment['confidence'] = 0.3
            return
        
        # Extract breach information
        breach_count = hibp_data.get('total_breaches', 0)
        risk_assessment = hibp_data.get('risk_assessment', {})
        
        assessment['breach_count'] = breach_count
        assessment['is_compromised'] = breach_count > 0
        assessment['risk_score'] = risk_assessment.get('risk_score', 0.0)
        assessment['confidence'] = 0.9  # HIBP is highly reliable
        assessment['primary_concerns'] = risk_assessment.get('primary_concerns', [])
        
        # Add breach context
        breach_summary = hibp_data.get('breach_summary', {})
        if breach_summary.get('sensitive_breaches', 0) > 0:
            assessment['primary_concerns'].append('sensitive_data_exposed')
        
        if breach_summary.get('verified_breaches', 0) != breach_count:
            assessment['confidence'] *= 0.9  # Reduce confidence for unverified breaches
    
    def _calculate_address_assessment(self, results: Dict[str, Any]):
        """Calculate aggregated cryptocurrency address assessment"""
        ransomware_data = results.get('ransomware_result')
        elliptic_data = results.get('elliptic_result')
        vt_data = results.get('virustotal_result')
        assessment = results['aggregated_assessment']
        
        risk_scores = []
        confidence_scores = []
        criminal_activities = []
        attribution = []
        
        # Process Ransomware results
        if ransomware_data and ransomware_data.get('found_ransomware_data'):
            if ransomware_data.get('is_ransomware_address'):
                threat_assessment = ransomware_data.get('threat_assessment', {})
                risk_scores.append(threat_assessment.get('threat_score', 0.9))
                confidence_scores.append(threat_assessment.get('confidence', 0.9))
                criminal_activities.append('ransomware_payments')
                
                malware_families = ransomware_data.get('malware_families', [])
                attribution.extend([f"ransomware_{family}" for family in malware_families])
        
        # Process Elliptic results
        if elliptic_data and elliptic_data.get('found_elliptic_data'):
            if elliptic_data.get('is_labeled'):
                label = elliptic_data.get('label')
                confidence = elliptic_data.get('confidence', 0.8)
                
                if label == 'illicit':
                    risk_scores.append(0.9)
                    confidence_scores.append(confidence)
                    criminal_activities.append('elliptic_illicit')
                    attribution.append('elliptic_dataset')
                elif label == 'licit':
                    risk_scores.append(0.1)
                    confidence_scores.append(confidence)
        
        # Process VirusTotal results
        if vt_data and vt_data.get('found_virustotal_data'):
            if vt_data.get('found_in_malware'):
                threat_assessment = vt_data.get('threat_assessment', {})
                risk_scores.append(threat_assessment.get('threat_score', 0.7))
                confidence_scores.append(threat_assessment.get('confidence', 0.8))
                
                # Categorize malware activities
                if vt_data.get('cryptostealer_config_count', 0) > 0:
                    criminal_activities.append('cryptostealer_target')
                    attribution.append('cryptostealer_malware')
                
                if vt_data.get('phishing_url_count', 0) > 0:
                    criminal_activities.append('phishing_association')
                    attribution.append('phishing_campaigns')
                
                if vt_data.get('malware_detection_count', 0) > 0:
                    criminal_activities.append('malware_association')
                    
                malware_families = vt_data.get('malware_families', [])
                attribution.extend([f"malware_{family}" for family in malware_families])
        
        # Calculate final assessment
        if risk_scores:
            # Use weighted average with confidence as weights
            total_weight = sum(confidence_scores) if confidence_scores else len(risk_scores)
            if total_weight > 0:
                weighted_risk = sum(r * c for r, c in zip(risk_scores, confidence_scores)) / total_weight
                assessment['risk_score'] = weighted_risk
                assessment['confidence'] = sum(confidence_scores) / len(confidence_scores)
            else:
                assessment['risk_score'] = sum(risk_scores) / len(risk_scores)
                assessment['confidence'] = 0.5
            
            # Boost confidence if multiple sources agree
            if len([s for s in risk_scores if s > 0.5]) >= 2:
                assessment['confidence'] = min(assessment['confidence'] * 1.2, 1.0)
        else:
            assessment['risk_score'] = 0.0
            assessment['confidence'] = 0.3
        
        # Determine if criminal
        assessment['is_criminal_address'] = assessment['risk_score'] >= 0.6
        assessment['criminal_activities'] = list(set(criminal_activities))
        assessment['attribution'] = list(set(attribution))
    
    def analyze_address(self, address: str) -> Optional[WalletAnalysis]:
        """
        Analyze an address for historical criminal activity and return structured analysis.
        
        Args:
            address: Cryptocurrency address or email to analyze
            
        Returns:
            WalletAnalysis containing historical crime assessment
        """
        
        try:
            # Determine if this is an email or crypto address
            is_email = '@' in address and '.' in address.split('@')[1]
            
            if is_email:
                # Collect email intelligence
                data = self.collect_email_intelligence(address)
            else:
                # Collect address intelligence
                data = self.collect_address_intelligence(address)
            
            if not data:
                return None
            
            # Parse into risk factors
            risk_factors = self.parse_risk_factors(data, address)
            
            # Create wallet analysis
            assessment = data.get('aggregated_assessment', {})
            
            if is_email:
                is_flagged = assessment.get('is_compromised', False)
                risk_score = assessment.get('risk_score', 0.0)
                summary = f"Email breach analysis: {assessment.get('breach_count', 0)} breaches found"
            else:
                is_flagged = assessment.get('is_criminal_address', False)
                risk_score = assessment.get('risk_score', 0.0)
                criminal_activities = assessment.get('criminal_activities', [])
                summary = f"Crime intelligence: {len(criminal_activities)} criminal activities detected"
            
            analysis = WalletAnalysis(
                address=address,
                analysis_timestamp=datetime.now(timezone.utc),
                data_sources=[self.source_name],
                risk_factors=risk_factors,
                overall_risk_score=risk_score,
                risk_level=self._score_to_risk_level(risk_score),
                confidence_score=assessment.get('confidence', 0.0),
                is_flagged=is_flagged,
                summary=summary,
                raw_data=data
            )
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing historical crime data for {address}: {e}")
            return None
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse aggregated crime data into risk factors"""
        risk_factors = []
        
        if not raw_data:
            return risk_factors
        
        # Determine data type
        is_email = '@' in address
        
        if is_email:
            # Parse email breach risk factors
            if raw_data.get('hibp_result'):
                hibp_factors = self.hibp_client.parse_risk_factors(
                    raw_data['hibp_result'], address
                )
                risk_factors.extend(hibp_factors)
        else:
            # Parse cryptocurrency address risk factors from each source
            if raw_data.get('ransomware_result'):
                ransomware_factors = self.ransomware_processor.parse_risk_factors(
                    raw_data['ransomware_result'], address
                )
                risk_factors.extend(ransomware_factors)
            
            if raw_data.get('elliptic_result'):
                elliptic_factors = self.elliptic_processor.parse_risk_factors(
                    raw_data['elliptic_result'], address
                )
                risk_factors.extend(elliptic_factors)
            
            if raw_data.get('virustotal_result'):
                vt_factors = self.virustotal_client.parse_risk_factors(
                    raw_data['virustotal_result'], address
                )
                risk_factors.extend(vt_factors)
        
        # Add aggregated assessment if we have data from multiple sources
        assessment = raw_data.get('aggregated_assessment', {})
        sources_checked = raw_data.get('sources_checked', [])
        analysis_sources = assessment.get('analysis_sources', [])
        
        if len(analysis_sources) > 1:
            # Create summary risk factor for multi-source crime intelligence
            risk_score = assessment.get('risk_score', 0)
            confidence = assessment.get('confidence', 0)
            
            risk_level = self._score_to_risk_level(risk_score)
            
            if is_email:
                if assessment.get('is_compromised'):
                    breach_count = assessment.get('breach_count', 0)
                    risk_factors.append(RiskFactor(
                        type="multi_source_breach_exposure",
                        description=f"Multi-source breach analysis: {breach_count} confirmed breaches",
                        risk_level=risk_level,
                        confidence=confidence,
                        source=DataSourceType.CRIME_DATABASE,
                        raw_data={
                            'breach_count': breach_count,
                            'analysis_sources': analysis_sources,
                            'primary_concerns': assessment.get('primary_concerns', [])
                        }
                    ))
            else:
                if assessment.get('is_criminal_address'):
                    criminal_activities = assessment.get('criminal_activities', [])
                    attribution = assessment.get('attribution', [])
                    
                    risk_factors.append(RiskFactor(
                        type="multi_source_criminal_activity",
                        description=f"Multi-source crime intelligence: {', '.join(criminal_activities)}",
                        risk_level=risk_level,
                        confidence=confidence,
                        source=DataSourceType.CRIME_DATABASE,
                        raw_data={
                            'criminal_activities': criminal_activities,
                            'attribution': attribution,
                            'analysis_sources': analysis_sources,
                            'risk_score': risk_score
                        }
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
    
    def get_ml_training_data(self) -> Optional[Any]:
        """Get prepared ML training data from Elliptic dataset"""
        
        if 'elliptic' in self.available_sources:
            return self.elliptic_processor.get_ml_training_data()
        else:
            self.logger.warning("Elliptic dataset not available for ML training data")
            return None
    
    def export_ml_training_data(self, export_path: str, format: str = 'numpy') -> bool:
        """Export ML training data"""
        
        if 'elliptic' in self.available_sources:
            return self.elliptic_processor.export_training_data(export_path, format)
        else:
            self.logger.error("No ML training data available for export")
            return False
    
    def get_coverage_statistics(self) -> Dict[str, Any]:
        """Get crime intelligence coverage statistics"""
        
        try:
            stats = {
                'available_sources': list(self.available_sources),
                'coverage_percentage': len(self.available_sources) / 4 * 100,  # 4 total sources
                'source_details': {}
            }
            
            # Get statistics from each component
            if 'hibp' in self.available_sources:
                try:
                    stats['source_details']['hibp'] = self.hibp_client.get_statistics()
                except Exception as e:
                    stats['source_details']['hibp'] = {'error': str(e)}
            
            if 'ransomware' in self.available_sources:
                try:
                    stats['source_details']['ransomware'] = self.ransomware_processor.get_statistics()
                except Exception as e:
                    stats['source_details']['ransomware'] = {'error': str(e)}
            
            if 'elliptic' in self.available_sources:
                try:
                    stats['source_details']['elliptic'] = self.elliptic_processor.get_statistics()
                except Exception as e:
                    stats['source_details']['elliptic'] = {'error': str(e)}
            
            if 'virustotal' in self.available_sources:
                try:
                    stats['source_details']['virustotal'] = self.virustotal_client.get_statistics()
                except Exception as e:
                    stats['source_details']['virustotal'] = {'error': str(e)}
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting coverage statistics: {e}")
            return {
                'available_sources': list(self.available_sources),
                'coverage_percentage': 0,
                'error': str(e)
            }
    
    def cross_reference_identity(self, **identifiers) -> Dict[str, Any]:
        """Cross-reference identity across historical crime databases"""
        
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'identifiers_checked': identifiers,
            'cross_references_found': False,
            'breach_results': {},
            'crime_results': {},
            'risk_assessment': {
                'overall_risk_score': 0.0,
                'confidence': 0.0,
                'primary_threats': []
            }
        }
        
        risk_scores = []
        confidence_scores = []
        primary_threats = []
        
        # Check email addresses for breaches
        email = identifiers.get('email')
        if email and 'hibp' in self.available_sources:
            try:
                email_data = self.collect_email_intelligence(email)
                if email_data:
                    results['breach_results']['email'] = email_data
                    
                    assessment = email_data.get('aggregated_assessment', {})
                    if assessment.get('is_compromised'):
                        results['cross_references_found'] = True
                        risk_scores.append(assessment.get('risk_score', 0))
                        confidence_scores.append(assessment.get('confidence', 0))
                        primary_threats.append('email_breach_exposure')
            except Exception as e:
                self.logger.error(f"Email cross-reference failed: {e}")
        
        # Check crypto addresses for criminal activity
        crypto_address = identifiers.get('crypto_address')
        if crypto_address:
            try:
                address_data = self.collect_address_intelligence(crypto_address)
                if address_data:
                    results['crime_results']['crypto_address'] = address_data
                    
                    assessment = address_data.get('aggregated_assessment', {})
                    if assessment.get('is_criminal_address'):
                        results['cross_references_found'] = True
                        risk_scores.append(assessment.get('risk_score', 0))
                        confidence_scores.append(assessment.get('confidence', 0))
                        primary_threats.extend(assessment.get('criminal_activities', []))
            except Exception as e:
                self.logger.error(f"Address cross-reference failed: {e}")
        
        # Calculate overall risk assessment
        if risk_scores and confidence_scores:
            results['risk_assessment']['overall_risk_score'] = sum(risk_scores) / len(risk_scores)
            results['risk_assessment']['confidence'] = sum(confidence_scores) / len(confidence_scores)
            results['risk_assessment']['primary_threats'] = list(set(primary_threats))
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get historical crime aggregator statistics"""
        
        return {
            'available_sources': list(self.available_sources),
            'total_possible_sources': 4,
            'coverage_percentage': len(self.available_sources) / 4 * 100,
            'cache_entries': len(self.cache) if hasattr(self.cache, '__len__') else 'unknown'
        }