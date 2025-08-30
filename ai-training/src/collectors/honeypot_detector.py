"""
Honeypot Detection System - detects malicious smart contracts and token scams.

Integrates with Honeypot.is API and implements custom analysis to detect:
- Honeypot tokens that prevent selling
- Excessive transaction fees and taxes
- Locked liquidity issues
- Ownership and admin function risks
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
import requests
import time
import json
from decimal import Decimal
from urllib.parse import quote

from ..data_collector import BaseDataCollector
from ..utils.logging import get_logger


@dataclass
class HoneypotAnalysis:
    """Results from honeypot detection analysis"""
    
    contract_address: str
    token_symbol: str
    token_name: str
    is_honeypot: bool
    honeypot_reason: Optional[str]
    buy_tax: float  # Percentage
    sell_tax: float  # Percentage
    transfer_tax: float  # Percentage
    can_be_bought: bool
    can_be_sold: bool
    max_sell_amount: Optional[float]
    simulation_success: bool
    gas_estimates: Dict[str, int]  # buy_gas, sell_gas
    liquidity_locked: Optional[bool]
    owner_privileges: List[str]
    risk_factors: List[str]
    confidence_score: float
    analysis_timestamp: datetime


@dataclass 
class ContractSecurityInfo:
    """Security analysis of smart contract"""
    
    contract_address: str
    is_verified: bool
    source_code_available: bool
    proxy_contract: bool
    can_be_upgraded: bool
    has_hidden_mint: bool
    has_admin_functions: bool
    ownership_renounced: bool
    max_transaction_limit: Optional[float]
    transfer_cooldown: Optional[int]  # seconds
    security_issues: List[str]
    risk_level: str  # 'low', 'medium', 'high', 'critical'


class HoneypotDetector(BaseDataCollector):
    """
    Honeypot and malicious smart contract detection system.
    
    Uses multiple detection methods:
    1. Honeypot.is API integration
    2. Custom buy/sell simulation
    3. Contract code analysis
    4. Liquidity and ownership checks
    """
    
    HONEYPOT_IS_API = "https://api.honeypot.is/v2/IsHoneypot"
    SUPPORTED_CHAINS = {
        'ethereum': 1,
        'bsc': 56, 
        'polygon': 137,
        'avalanche': 43114,
        'arbitrum': 42161
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: str):
        super().__init__(config, cache_dir, "honeypot_detector")
        
        self.logger = get_logger(f"{__name__}.HoneypotDetector")
        
        # Load configuration
        smart_contract_config = config.get('smart_contract_analysis', {})
        honeypot_config = smart_contract_config.get('honeypot_detection', {})
        
        self.api_key = honeypot_config.get('api_key')  # Some endpoints may require key
        self.default_chain = honeypot_config.get('default_chain', 'ethereum')
        self.simulation_amount = honeypot_config.get('simulation_amount_eth', '0.1')
        self.max_buy_tax = honeypot_config.get('max_acceptable_buy_tax', 10.0)  # %
        self.max_sell_tax = honeypot_config.get('max_acceptable_sell_tax', 10.0)  # %
        
        # Rate limiting for API calls
        rate_config = config.get('rate_limiting', {})
        self.request_delay = rate_config.get('honeypot_delay_seconds', 1.0)
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Have-I-Been-Rekt-Security-Scanner/1.0'
        })
        
        self.logger.info(f"Initialized Honeypot Detector (chain: {self.default_chain})")
    
    def _make_honeypot_request(self, contract_address: str, chain_id: int = None) -> Optional[Dict[str, Any]]:
        """Make request to Honeypot.is API"""
        
        if not chain_id:
            chain_id = self.SUPPORTED_CHAINS.get(self.default_chain, 1)
        
        try:
            # Rate limiting
            time.sleep(self.request_delay)
            
            params = {
                'address': contract_address,
                'chainID': chain_id
            }
            
            self.logger.debug(f"Checking honeypot status: {contract_address} on chain {chain_id}")
            
            response = self.session.get(self.HONEYPOT_IS_API, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('success'):
                return data
            else:
                self.logger.warning(f"Honeypot API error: {data.get('error', 'Unknown error')}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Honeypot API request failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error in honeypot request: {e}")
            return None
    
    def analyze_token_contract(self, contract_address: str, chain: str = None) -> Optional[HoneypotAnalysis]:
        """
        Analyze token contract for honeypot characteristics.
        
        Args:
            contract_address: Smart contract address to analyze
            chain: Blockchain network (ethereum, bsc, polygon, etc.)
            
        Returns:
            HoneypotAnalysis object with detection results
        """
        
        if not chain:
            chain = self.default_chain
        
        chain_id = self.SUPPORTED_CHAINS.get(chain.lower(), 1)
        
        cache_key = f"honeypot_{contract_address}_{chain_id}"
        cached_result = self.get_cached_result(cache_key, max_age_hours=6)  # Cache for 6 hours
        
        if cached_result:
            cached_result['analysis_timestamp'] = datetime.fromisoformat(cached_result['analysis_timestamp'])
            return HoneypotAnalysis(**cached_result)
        
        self.logger.info(f"Analyzing token contract: {contract_address} on {chain}")
        
        # Get data from Honeypot.is API
        api_data = self._make_honeypot_request(contract_address, chain_id)
        
        if not api_data:
            return None
        
        # Parse API response
        analysis = self._parse_honeypot_response(api_data, contract_address)
        
        # Perform additional custom analysis
        additional_analysis = self._perform_custom_analysis(contract_address, chain_id, api_data)
        analysis = self._merge_analysis_results(analysis, additional_analysis)
        
        # Cache results
        cache_data = analysis.__dict__.copy()
        cache_data['analysis_timestamp'] = cache_data['analysis_timestamp'].isoformat()
        self.cache_result(cache_key, cache_data)
        
        return analysis
    
    def _parse_honeypot_response(self, api_data: Dict[str, Any], contract_address: str) -> HoneypotAnalysis:
        """Parse response from Honeypot.is API"""
        
        # Extract basic token info
        token_info = api_data.get('token', {})
        token_name = token_info.get('name', 'Unknown')
        token_symbol = token_info.get('symbol', 'UNKNOWN')
        
        # Extract honeypot analysis
        honeypot_result = api_data.get('honeypotResult', {})
        is_honeypot = honeypot_result.get('isHoneypot', False)
        honeypot_reason = honeypot_result.get('honeypotReason')
        
        # Extract transaction simulation results
        simulation_result = api_data.get('simulationResult', {})
        buy_tax = float(simulation_result.get('buyTax', 0))
        sell_tax = float(simulation_result.get('sellTax', 0)) 
        transfer_tax = float(simulation_result.get('transferTax', 0))
        
        can_be_bought = simulation_result.get('buyGas', 0) > 0
        can_be_sold = simulation_result.get('sellGas', 0) > 0
        
        buy_gas = simulation_result.get('buyGas', 0)
        sell_gas = simulation_result.get('sellGas', 0)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(api_data)
        
        # Identify risk factors
        risk_factors = self._identify_risk_factors(api_data)
        
        analysis = HoneypotAnalysis(
            contract_address=contract_address,
            token_symbol=token_symbol,
            token_name=token_name,
            is_honeypot=is_honeypot,
            honeypot_reason=honeypot_reason,
            buy_tax=buy_tax,
            sell_tax=sell_tax,
            transfer_tax=transfer_tax,
            can_be_bought=can_be_bought,
            can_be_sold=can_be_sold,
            max_sell_amount=simulation_result.get('maxSellAmount'),
            simulation_success=simulation_result.get('simulationSuccess', False),
            gas_estimates={'buy_gas': buy_gas, 'sell_gas': sell_gas},
            liquidity_locked=None,  # Will be filled by custom analysis
            owner_privileges=[],     # Will be filled by custom analysis
            risk_factors=risk_factors,
            confidence_score=confidence_score,
            analysis_timestamp=datetime.now(timezone.utc)
        )
        
        return analysis
    
    def _perform_custom_analysis(self, contract_address: str, chain_id: int, api_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform additional custom analysis beyond API data"""
        
        custom_analysis = {
            'liquidity_analysis': self._analyze_liquidity(contract_address, chain_id),
            'ownership_analysis': self._analyze_ownership(contract_address, api_data),
            'additional_risks': self._detect_additional_risks(contract_address, api_data)
        }
        
        return custom_analysis
    
    def _analyze_liquidity(self, contract_address: str, chain_id: int) -> Dict[str, Any]:
        """Analyze liquidity pool security"""
        
        # This would typically involve:
        # 1. Checking if liquidity is locked in time-lock contracts
        # 2. Analyzing liquidity pool ownership
        # 3. Checking for rug pull indicators in liquidity
        
        # Placeholder implementation - in production would use DEX APIs
        return {
            'liquidity_locked': None,
            'lock_duration': None,
            'liquidity_pool_owner': None,
            'rug_pull_risk': 'unknown'
        }
    
    def _analyze_ownership(self, contract_address: str, api_data: Dict[str, Any]) -> List[str]:
        """Analyze contract ownership and admin privileges"""
        
        privileges = []
        
        # Extract from API data if available
        holder_analysis = api_data.get('holderAnalysis', {})
        
        # Check ownership concentration
        if holder_analysis.get('holderCount', 0) < 100:
            privileges.append('low_holder_count')
        
        # Check for large holder concentration
        holders = holder_analysis.get('holders', [])
        if holders:
            top_holder_percent = holders[0].get('percent', 0)
            if top_holder_percent > 50:
                privileges.append('majority_holder')
            elif top_holder_percent > 20:
                privileges.append('large_holder_concentration')
        
        # This would typically involve contract code analysis
        # For now, we'll use heuristics from API data
        
        return privileges
    
    def _detect_additional_risks(self, contract_address: str, api_data: Dict[str, Any]) -> List[str]:
        """Detect additional risk factors"""
        
        risks = []
        
        simulation = api_data.get('simulationResult', {})
        
        # High tax risks
        buy_tax = simulation.get('buyTax', 0)
        sell_tax = simulation.get('sellTax', 0)
        
        if buy_tax > self.max_buy_tax:
            risks.append(f'excessive_buy_tax_{buy_tax}%')
        
        if sell_tax > self.max_sell_tax:
            risks.append(f'excessive_sell_tax_{sell_tax}%')
        
        # Gas estimation risks
        buy_gas = simulation.get('buyGas', 0)
        sell_gas = simulation.get('sellGas', 0)
        
        if buy_gas > 500000:  # Very high gas
            risks.append('high_buy_gas')
        
        if sell_gas > 500000:
            risks.append('high_sell_gas')
        
        if sell_gas == 0:  # Cannot sell
            risks.append('cannot_sell')
        
        # Transaction limits
        if simulation.get('maxSellAmount'):
            risks.append('sell_amount_limited')
        
        return risks
    
    def _merge_analysis_results(self, analysis: HoneypotAnalysis, custom_analysis: Dict[str, Any]) -> HoneypotAnalysis:
        """Merge custom analysis results into main analysis"""
        
        # Update liquidity information
        liquidity_data = custom_analysis.get('liquidity_analysis', {})
        analysis.liquidity_locked = liquidity_data.get('liquidity_locked')
        
        # Update owner privileges
        analysis.owner_privileges = custom_analysis.get('ownership_analysis', [])
        
        # Add additional risks
        additional_risks = custom_analysis.get('additional_risks', [])
        analysis.risk_factors.extend(additional_risks)
        
        return analysis
    
    def _calculate_confidence_score(self, api_data: Dict[str, Any]) -> float:
        """Calculate confidence score for the analysis"""
        
        confidence = 0.5  # Base confidence
        
        simulation_result = api_data.get('simulationResult', {})
        
        # Boost confidence if simulation was successful
        if simulation_result.get('simulationSuccess', False):
            confidence += 0.3
        
        # Boost confidence if we have comprehensive holder analysis
        holder_analysis = api_data.get('holderAnalysis', {})
        if holder_analysis.get('holders'):
            confidence += 0.2
        
        # Reduce confidence if results are uncertain
        honeypot_result = api_data.get('honeypotResult', {})
        if not honeypot_result.get('isHoneypot') and simulation_result.get('sellTax', 0) > 50:
            confidence -= 0.2  # Conflicting signals
        
        return min(max(confidence, 0.0), 1.0)  # Clamp to [0, 1]
    
    def _identify_risk_factors(self, api_data: Dict[str, Any]) -> List[str]:
        """Identify risk factors from API response"""
        
        risks = []
        
        honeypot_result = api_data.get('honeypotResult', {})
        simulation_result = api_data.get('simulationResult', {})
        
        # Primary honeypot risk
        if honeypot_result.get('isHoneypot', False):
            risks.append('confirmed_honeypot')
            if honeypot_result.get('honeypotReason'):
                risks.append(f"honeypot_reason_{honeypot_result['honeypotReason']}")
        
        # Tax-related risks
        buy_tax = simulation_result.get('buyTax', 0)
        sell_tax = simulation_result.get('sellTax', 0)
        transfer_tax = simulation_result.get('transferTax', 0)
        
        if buy_tax > 0:
            risks.append('has_buy_tax')
        if sell_tax > 0:
            risks.append('has_sell_tax')
        if transfer_tax > 0:
            risks.append('has_transfer_tax')
        
        # Simulation failure risks
        if not simulation_result.get('simulationSuccess', False):
            risks.append('simulation_failed')
        
        if simulation_result.get('buyGas', 0) == 0:
            risks.append('cannot_buy')
        
        if simulation_result.get('sellGas', 0) == 0:
            risks.append('cannot_sell')
        
        return risks
    
    def lookup_address(self, address: str, chain: str = None) -> Dict[str, Any]:
        """
        Main interface for honeypot analysis.
        
        Args:
            address: Smart contract address to analyze
            chain: Blockchain network
            
        Returns:
            Dictionary containing honeypot analysis results
        """
        
        try:
            self.logger.info(f"Starting honeypot analysis: {address[:10]}...")
            
            analysis = self.analyze_token_contract(address, chain)
            
            if not analysis:
                return {
                    'found_honeypot_data': False,
                    'error': 'Failed to analyze contract'
                }
            
            # Build result dictionary
            result = {
                'found_honeypot_data': True,
                'is_honeypot': analysis.is_honeypot,
                'honeypot_reason': analysis.honeypot_reason,
                'token_info': {
                    'name': analysis.token_name,
                    'symbol': analysis.token_symbol
                },
                'tax_analysis': {
                    'buy_tax': analysis.buy_tax,
                    'sell_tax': analysis.sell_tax,
                    'transfer_tax': analysis.transfer_tax
                },
                'trading_analysis': {
                    'can_be_bought': analysis.can_be_bought,
                    'can_be_sold': analysis.can_be_sold,
                    'max_sell_amount': analysis.max_sell_amount,
                    'simulation_success': analysis.simulation_success
                },
                'security_analysis': {
                    'liquidity_locked': analysis.liquidity_locked,
                    'owner_privileges': analysis.owner_privileges,
                    'risk_factors': analysis.risk_factors
                },
                'confidence_score': analysis.confidence_score,
                'analysis_timestamp': analysis.analysis_timestamp.isoformat()
            }
            
            self.logger.info(f"Honeypot analysis completed: {address[:10]}... (honeypot: {analysis.is_honeypot})")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in honeypot analysis for {address}: {e}")
            return {
                'found_honeypot_data': False,
                'error': str(e)
            }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List:
        """Parse honeypot analysis into risk factors for ML training"""
        
        # Import here to avoid circular imports
        from ..data_collector import RiskFactor, RiskLevel, DataSourceType
        
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_honeypot_data'):
            return risk_factors
        
        # Honeypot detection risk
        if raw_data.get('is_honeypot'):
            honeypot_reason = raw_data.get('honeypot_reason', 'unknown')
            
            risk_factors.append(RiskFactor(
                type="honeypot_token",
                description=f"Confirmed honeypot token: {honeypot_reason}",
                risk_level=RiskLevel.CRITICAL,
                confidence=raw_data.get('confidence_score', 0.9),
                source=DataSourceType.SMART_CONTRACT,
                raw_data={'honeypot_reason': honeypot_reason}
            ))
        
        # Tax analysis risks
        tax_analysis = raw_data.get('tax_analysis', {})
        buy_tax = tax_analysis.get('buy_tax', 0)
        sell_tax = tax_analysis.get('sell_tax', 0)
        
        if buy_tax > self.max_buy_tax or sell_tax > self.max_sell_tax:
            risk_level = RiskLevel.HIGH if max(buy_tax, sell_tax) > 25 else RiskLevel.MEDIUM
            
            risk_factors.append(RiskFactor(
                type="excessive_token_taxes",
                description=f"High transaction taxes: {buy_tax}% buy, {sell_tax}% sell",
                risk_level=risk_level,
                confidence=0.9,
                source=DataSourceType.SMART_CONTRACT,
                raw_data={'buy_tax': buy_tax, 'sell_tax': sell_tax}
            ))
        
        # Trading limitations
        trading_analysis = raw_data.get('trading_analysis', {})
        if not trading_analysis.get('can_be_sold', True):
            risk_factors.append(RiskFactor(
                type="cannot_sell_token",
                description="Token cannot be sold - potential honeypot",
                risk_level=RiskLevel.CRITICAL,
                confidence=0.95,
                source=DataSourceType.SMART_CONTRACT,
                raw_data={'trading_disabled': True}
            ))
        
        # Security issues
        security_analysis = raw_data.get('security_analysis', {})
        risk_factors_list = security_analysis.get('risk_factors', [])
        
        for risk_factor in risk_factors_list:
            if 'excessive' in risk_factor or 'cannot' in risk_factor:
                risk_level = RiskLevel.HIGH
            elif 'high' in risk_factor or 'limited' in risk_factor:
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.LOW
            
            risk_factors.append(RiskFactor(
                type=f"smart_contract_{risk_factor}",
                description=f"Smart contract risk detected: {risk_factor.replace('_', ' ')}",
                risk_level=risk_level,
                confidence=0.7,
                source=DataSourceType.SMART_CONTRACT,
                raw_data={'risk_factor': risk_factor}
            ))
        
        return risk_factors
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get honeypot detector statistics"""
        
        return {
            'supported_chains': list(self.SUPPORTED_CHAINS.keys()),
            'default_chain': self.default_chain,
            'max_buy_tax_threshold': self.max_buy_tax,
            'max_sell_tax_threshold': self.max_sell_tax,
            'simulation_amount': self.simulation_amount,
            'cache_entries': len(self.cache) if hasattr(self.cache, '__len__') else 'unknown'
        }