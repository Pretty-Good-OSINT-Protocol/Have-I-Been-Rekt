"""
Smart Contract Threat Analysis Aggregator - combines multiple smart contract
security analysis tools for comprehensive DeFi threat detection.

Integrates:
- Honeypot detection (Honeypot.is API + custom analysis)
- Contract source code security analysis
- Rug pull detection and liquidity monitoring
- Web3 provider for real-time blockchain data
"""

from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timezone
import logging

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin
from .honeypot_detector import HoneypotDetector
from .contract_analyzer import ContractAnalyzer
from .rugpull_detector import RugPullDetector
from .web3_provider import Web3Provider


class SmartContractAggregator(BaseDataCollector, LoggingMixin):
    """
    Aggregates smart contract security analysis from multiple specialized tools
    to provide comprehensive DeFi and smart contract threat intelligence.
    """
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # Initialize component analyzers
        self.honeypot_detector = HoneypotDetector(config, cache_dir, logger)
        self.contract_analyzer = ContractAnalyzer(config, cache_dir, logger)
        self.rugpull_detector = RugPullDetector(config, cache_dir, logger)
        self.web3_provider = Web3Provider(config, cache_dir, logger)
        
        # Track available sources
        self.available_sources = self._check_available_sources()
        
        self.logger.info(
            "Smart contract aggregator initialized",
            available_sources=list(self.available_sources)
        )
    
    @property
    def source_name(self) -> str:
        return "smart_contract_aggregator"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.SMART_CONTRACT
    
    def _check_available_sources(self) -> Set[str]:
        """Check which smart contract analysis sources are available"""
        sources = set()
        
        # Honeypot detector is always available (can work without API key)
        sources.add('honeypot_detector')
        
        # Contract analyzer requires blockchain API keys
        analyzer_config = self.config.get('smart_contract_analysis', {}).get('contract_analyzer', {})
        if analyzer_config.get('api_keys'):
            sources.add('contract_analyzer')
        
        # Rug pull detector requires DEX APIs (GraphQL endpoints are public)
        sources.add('rugpull_detector')
        
        # Web3 provider requires RPC endpoints
        web3_config = self.config.get('web3_providers', {})
        if web3_config.get('provider_urls'):
            sources.add('web3_provider')
        
        return sources
    
    def collect_address_data(self, address: str, chain: str = None) -> Optional[Dict[str, Any]]:
        """Collect comprehensive smart contract analysis for an address"""
        results = {
            'address': address,
            'chain': chain or 'ethereum',
            'timestamp': datetime.utcnow().isoformat(),
            'sources_checked': [],
            'smart_contract_threats_found': False,
            'honeypot_result': None,
            'contract_analysis_result': None,
            'rugpull_result': None,
            'web3_result': None,
            'aggregated_assessment': {
                'is_malicious_contract': False,
                'overall_risk_score': 0.0,
                'confidence': 0.0,
                'threat_categories': [],
                'primary_risks': [],
                'analysis_sources': []
            }
        }
        
        # Collect Honeypot analysis
        if 'honeypot_detector' in self.available_sources:
            try:
                honeypot_data = self.honeypot_detector.lookup_address(address, chain)
                results['honeypot_result'] = honeypot_data
                results['sources_checked'].append('honeypot_detector')
                
                if honeypot_data and honeypot_data.get('found_honeypot_data'):
                    results['aggregated_assessment']['analysis_sources'].append('honeypot_detector')
                    
                    if honeypot_data.get('is_honeypot'):
                        results['smart_contract_threats_found'] = True
                        
            except Exception as e:
                self.logger.error("Honeypot detection failed", error=str(e))
        
        # Collect Contract analysis
        if 'contract_analyzer' in self.available_sources:
            try:
                contract_data = self.contract_analyzer.lookup_address(address, chain)
                results['contract_analysis_result'] = contract_data
                results['sources_checked'].append('contract_analyzer')
                
                if contract_data and contract_data.get('found_contract_data'):
                    results['aggregated_assessment']['analysis_sources'].append('contract_analyzer')
                    
                    security_analysis = contract_data.get('security_analysis', {})
                    if security_analysis.get('risk_level') in ['high', 'critical']:
                        results['smart_contract_threats_found'] = True
                        
            except Exception as e:
                self.logger.error("Contract analysis failed", error=str(e))
        
        # Collect Rug pull analysis (for tokens/DeFi contracts)
        if 'rugpull_detector' in self.available_sources:
            try:
                rugpull_data = self.rugpull_detector.lookup_address(address)
                results['rugpull_result'] = rugpull_data
                results['sources_checked'].append('rugpull_detector')
                
                if rugpull_data and rugpull_data.get('found_rugpull_data'):
                    results['aggregated_assessment']['analysis_sources'].append('rugpull_detector')
                    
                    if rugpull_data.get('rug_pull_probability', 0) > 0.5:
                        results['smart_contract_threats_found'] = True
                        
            except Exception as e:
                self.logger.error("Rug pull analysis failed", error=str(e))
        
        # Collect Web3 blockchain data
        if 'web3_provider' in self.available_sources:
            try:
                web3_data = self.web3_provider.lookup_address(address, chain)
                results['web3_result'] = web3_data
                results['sources_checked'].append('web3_provider')
                
                if web3_data and web3_data.get('found_web3_data'):
                    results['aggregated_assessment']['analysis_sources'].append('web3_provider')
                    
            except Exception as e:
                self.logger.error("Web3 analysis failed", error=str(e))
        
        # Calculate aggregated assessment
        self._calculate_aggregated_assessment(results)
        
        return results
    
    def _calculate_aggregated_assessment(self, results: Dict[str, Any]):
        """Calculate aggregated smart contract threat assessment"""
        honeypot_data = results.get('honeypot_result')
        contract_data = results.get('contract_analysis_result')
        rugpull_data = results.get('rugpull_result')
        web3_data = results.get('web3_result')
        assessment = results['aggregated_assessment']
        
        risk_scores = []
        confidence_scores = []
        threat_categories = set()
        primary_risks = []
        
        # Process Honeypot results
        if honeypot_data and honeypot_data.get('found_honeypot_data'):
            if honeypot_data.get('is_honeypot'):
                risk_scores.append(1.0)  # Critical risk for confirmed honeypots
                confidence_scores.append(honeypot_data.get('confidence_score', 0.9))
                threat_categories.add('honeypot_token')
                primary_risks.append(f"Honeypot: {honeypot_data.get('honeypot_reason', 'confirmed')}")
            else:
                # Check for high taxes or other suspicious indicators
                tax_analysis = honeypot_data.get('tax_analysis', {})
                buy_tax = tax_analysis.get('buy_tax', 0)
                sell_tax = tax_analysis.get('sell_tax', 0)
                
                if buy_tax > 10 or sell_tax > 10:
                    risk_scores.append(0.6)
                    confidence_scores.append(0.8)
                    threat_categories.add('high_token_taxes')
                    primary_risks.append(f"High taxes: {buy_tax}% buy, {sell_tax}% sell")
                else:
                    risk_scores.append(0.2)  # Some risk even for analyzed tokens
                    confidence_scores.append(0.6)
        
        # Process Contract analysis results
        if contract_data and contract_data.get('found_contract_data'):
            security_analysis = contract_data.get('security_analysis', {})
            risk_level_str = security_analysis.get('risk_level', 'low')
            confidence = security_analysis.get('confidence_score', 0.5)
            
            risk_level_scores = {
                'low': 0.2,
                'medium': 0.4,
                'high': 0.7,
                'critical': 0.9
            }
            
            risk_score = risk_level_scores.get(risk_level_str, 0.2)
            risk_scores.append(risk_score)
            confidence_scores.append(confidence)
            
            if risk_level_str in ['high', 'critical']:
                threat_categories.add('smart_contract_security')
                primary_risks.append(f"Contract security: {risk_level_str} risk")
            
            # Add specific security issues
            security_issues = security_analysis.get('security_issues', [])
            for issue in security_issues[:3]:  # Top 3 issues
                if issue in ['has_admin_functions', 'has_mint_function', 'upgradeable_contract']:
                    threat_categories.add('admin_privileges')
                    primary_risks.append(f"Admin risk: {issue.replace('_', ' ')}")
                elif 'reentrancy' in issue or 'external_calls' in issue:
                    threat_categories.add('security_vulnerability')
                    primary_risks.append(f"Vulnerability: {issue.replace('_', ' ')}")
        
        # Process Rug pull analysis results
        if rugpull_data and rugpull_data.get('found_rugpull_data'):
            rug_pull_probability = rugpull_data.get('rug_pull_probability', 0)
            risk_level_str = rugpull_data.get('risk_level', 'low')
            confidence = rugpull_data.get('confidence_score', 0.5)
            
            risk_scores.append(rug_pull_probability)
            confidence_scores.append(confidence)
            
            if rug_pull_probability > 0.5:
                threat_categories.add('rug_pull_risk')
                primary_risks.append(f"Rug pull probability: {rug_pull_probability:.1%}")
            
            # Add specific red flags
            red_flags = rugpull_data.get('red_flags', [])
            for flag in red_flags[:2]:  # Top 2 red flags
                if 'liquidity' in flag:
                    threat_categories.add('liquidity_risk')
                elif 'concentration' in flag:
                    threat_categories.add('token_concentration')
                primary_risks.append(f"Warning: {flag.replace('_', ' ')}")
        
        # Process Web3 data for additional context
        if web3_data and web3_data.get('found_web3_data'):
            # Web3 data provides context but typically doesn't add major risk
            # Unless we detect specific patterns like new contracts
            if web3_data.get('is_contract'):
                creation_info = web3_data.get('creation_info', {})
                creation_block = creation_info.get('creation_block', 0)
                
                # Add small risk for very new contracts (placeholder logic)
                if creation_block > 0:  # Would calculate actual age
                    risk_scores.append(0.3)
                    confidence_scores.append(0.6)
                    threat_categories.add('new_contract')
        
        # Calculate final scores
        if risk_scores:
            # Use weighted average, giving more weight to higher-confidence scores
            total_weight = sum(confidence_scores) if confidence_scores else len(risk_scores)
            if total_weight > 0:
                weighted_risk = sum(r * c for r, c in zip(risk_scores, confidence_scores)) / total_weight
                assessment['overall_risk_score'] = weighted_risk
                assessment['confidence'] = sum(confidence_scores) / len(confidence_scores)
            else:
                assessment['overall_risk_score'] = sum(risk_scores) / len(risk_scores)
                assessment['confidence'] = 0.5
        else:
            assessment['overall_risk_score'] = 0.0
            assessment['confidence'] = 0.3
        
        # Determine if malicious
        assessment['is_malicious_contract'] = assessment['overall_risk_score'] >= 0.7
        
        # Set threat categories and risks
        assessment['threat_categories'] = list(threat_categories)
        assessment['primary_risks'] = primary_risks[:5]  # Top 5 risks
        
        # Boost confidence if multiple sources agree on high risk
        if len([s for s in risk_scores if s > 0.6]) >= 2:
            assessment['confidence'] = min(assessment['confidence'] * 1.2, 1.0)
    
    def analyze_address(self, address: str, chain: str = None) -> Optional[WalletAnalysis]:
        """
        Analyze an address for smart contract threats and return structured analysis.
        
        Args:
            address: Smart contract or wallet address to analyze
            chain: Blockchain network (ethereum, bsc, polygon, etc.)
            
        Returns:
            WalletAnalysis containing smart contract threat assessment
        """
        
        try:
            # Collect comprehensive data
            data = self.collect_address_data(address, chain)
            
            if not data:
                return None
            
            # Parse into risk factors
            risk_factors = self.parse_risk_factors(data, address)
            
            # Create wallet analysis
            assessment = data.get('aggregated_assessment', {})
            
            analysis = WalletAnalysis(
                address=address,
                analysis_timestamp=datetime.now(timezone.utc),
                data_sources=[self.source_name],
                risk_factors=risk_factors,
                overall_risk_score=assessment.get('overall_risk_score', 0.0),
                risk_level=self._score_to_risk_level(assessment.get('overall_risk_score', 0.0)),
                confidence_score=assessment.get('confidence', 0.0),
                is_flagged=assessment.get('is_malicious_contract', False),
                summary=f"Smart contract analysis: {len(risk_factors)} threats detected",
                raw_data=data
            )
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing smart contract {address}: {e}")
            return None
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse aggregated smart contract data into risk factors"""
        risk_factors = []
        
        if not raw_data:
            return risk_factors
        
        # Parse risk factors from each source
        if raw_data.get('honeypot_result'):
            honeypot_factors = self.honeypot_detector.parse_risk_factors(
                raw_data['honeypot_result'], address
            )
            risk_factors.extend(honeypot_factors)
        
        if raw_data.get('contract_analysis_result'):
            contract_factors = self.contract_analyzer.parse_risk_factors(
                raw_data['contract_analysis_result'], address
            )
            risk_factors.extend(contract_factors)
        
        if raw_data.get('rugpull_result'):
            rugpull_factors = self.rugpull_detector.parse_risk_factors(
                raw_data['rugpull_result'], address
            )
            risk_factors.extend(rugpull_factors)
        
        if raw_data.get('web3_result'):
            web3_factors = self.web3_provider.parse_risk_factors(
                raw_data['web3_result'], address
            )
            risk_factors.extend(web3_factors)
        
        # Add aggregated assessment if we have data from multiple sources
        assessment = raw_data.get('aggregated_assessment', {})
        sources_checked = raw_data.get('sources_checked', [])
        analysis_sources = assessment.get('analysis_sources', [])
        
        if len(analysis_sources) > 1 and assessment.get('is_malicious_contract'):
            # Create summary risk factor for multi-source smart contract threats
            overall_risk_score = assessment.get('overall_risk_score', 0)
            confidence = assessment.get('confidence', 0)
            threat_categories = assessment.get('threat_categories', [])
            
            risk_level = self._score_to_risk_level(overall_risk_score)
            
            description = f"Multi-source smart contract threat analysis: {', '.join(threat_categories)}"
            
            risk_factors.append(RiskFactor(
                type="smart_contract_multi_threat",
                description=description,
                risk_level=risk_level,
                confidence=confidence,
                source=DataSourceType.SMART_CONTRACT,
                raw_data={
                    'overall_risk_score': overall_risk_score,
                    'threat_categories': threat_categories,
                    'analysis_sources': analysis_sources,
                    'primary_risks': assessment.get('primary_risks', [])
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
    
    def get_coverage_statistics(self) -> Dict[str, Any]:
        """Get smart contract analysis coverage statistics"""
        
        try:
            stats = {
                'available_sources': list(self.available_sources),
                'coverage_percentage': len(self.available_sources) / 4 * 100,  # 4 total sources
                'source_details': {}
            }
            
            # Get statistics from each component
            if 'honeypot_detector' in self.available_sources:
                try:
                    stats['source_details']['honeypot_detector'] = self.honeypot_detector.get_statistics()
                except Exception as e:
                    stats['source_details']['honeypot_detector'] = {'error': str(e)}
            
            if 'contract_analyzer' in self.available_sources:
                try:
                    stats['source_details']['contract_analyzer'] = self.contract_analyzer.get_statistics()
                except Exception as e:
                    stats['source_details']['contract_analyzer'] = {'error': str(e)}
            
            if 'rugpull_detector' in self.available_sources:
                try:
                    stats['source_details']['rugpull_detector'] = self.rugpull_detector.get_statistics()
                except Exception as e:
                    stats['source_details']['rugpull_detector'] = {'error': str(e)}
            
            if 'web3_provider' in self.available_sources:
                try:
                    stats['source_details']['web3_provider'] = self.web3_provider.get_statistics()
                except Exception as e:
                    stats['source_details']['web3_provider'] = {'error': str(e)}
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting coverage statistics: {e}")
            return {
                'available_sources': list(self.available_sources),
                'coverage_percentage': 0,
                'error': str(e)
            }
    
    def cross_reference_contract(self, contract_address: str, **additional_params) -> Dict[str, Any]:
        """Cross-reference a contract across multiple analysis tools"""
        
        results = {
            'contract_address': contract_address,
            'timestamp': datetime.utcnow().isoformat(),
            'cross_references_found': False,
            'analysis_results': {},
            'consensus_assessment': {
                'threat_consensus': False,
                'risk_agreement_score': 0.0,
                'conflicting_assessments': []
            }
        }
        
        # Run analysis on all available sources
        analysis_data = self.collect_address_data(contract_address)
        
        if analysis_data:
            results['analysis_results'] = analysis_data
            results['cross_references_found'] = analysis_data.get('smart_contract_threats_found', False)
            
            # Calculate consensus
            assessment = analysis_data.get('aggregated_assessment', {})
            results['consensus_assessment']['threat_consensus'] = assessment.get('is_malicious_contract', False)
            results['consensus_assessment']['risk_agreement_score'] = assessment.get('confidence', 0.0)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get smart contract aggregator statistics"""
        
        return {
            'available_sources': list(self.available_sources),
            'total_possible_sources': 4,
            'coverage_percentage': len(self.available_sources) / 4 * 100,
            'cache_entries': len(self.cache) if hasattr(self.cache, '__len__') else 'unknown'
        }