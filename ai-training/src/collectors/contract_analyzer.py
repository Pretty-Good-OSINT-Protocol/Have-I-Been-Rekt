"""
Smart Contract Source Code Analyzer - analyzes contract security and potential threats.

Integrates with Etherscan/BSCScan APIs to:
- Verify contract source code availability
- Analyze ownership and admin functions
- Detect proxy contracts and upgradeability
- Check for hidden mint functions
- Assess security vulnerabilities
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
import requests
import time
import re
import json
from urllib.parse import quote

from ..data_collector import BaseDataCollector
from ..utils.logging import get_logger


@dataclass
class ContractAnalysis:
    """Results from smart contract analysis"""
    
    contract_address: str
    chain: str
    is_verified: bool
    source_code_available: bool
    contract_name: str
    compiler_version: str
    optimization_used: bool
    proxy_contract: bool
    implementation_address: Optional[str]
    can_be_upgraded: bool
    has_admin_functions: bool
    admin_addresses: List[str]
    ownership_renounced: bool
    has_mint_function: bool
    has_burn_function: bool
    has_pause_function: bool
    max_supply: Optional[int]
    current_supply: Optional[int]
    transfer_restrictions: List[str]
    security_issues: List[str]
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    confidence_score: float
    analysis_timestamp: datetime


@dataclass
class FunctionAnalysis:
    """Analysis of specific contract functions"""
    
    function_name: str
    function_signature: str
    visibility: str  # 'public', 'private', 'internal', 'external'
    mutability: str  # 'view', 'pure', 'nonpayable', 'payable'
    is_admin_only: bool
    modifiers: List[str]
    risk_factors: List[str]


class ContractAnalyzer(BaseDataCollector):
    """
    Smart contract source code analyzer.
    
    Performs static analysis on verified contracts to identify:
    - Admin privileges and ownership patterns
    - Proxy contracts and upgradeability
    - Hidden or dangerous functions
    - Security vulnerabilities
    """
    
    BLOCKCHAIN_APIS = {
        'ethereum': {
            'api_url': 'https://api.etherscan.io/api',
            'api_key_param': 'apikey'
        },
        'bsc': {
            'api_url': 'https://api.bscscan.com/api',
            'api_key_param': 'apikey'
        },
        'polygon': {
            'api_url': 'https://api.polygonscan.com/api',
            'api_key_param': 'apikey'
        },
        'avalanche': {
            'api_url': 'https://api.snowtrace.io/api',
            'api_key_param': 'apikey'
        },
        'arbitrum': {
            'api_url': 'https://api.arbiscan.io/api',
            'api_key_param': 'apikey'
        }
    }
    
    # Dangerous function patterns
    ADMIN_FUNCTION_PATTERNS = [
        r'\bowner\b',
        r'\badmin\b',
        r'\bsetOwner\b',
        r'\btransferOwnership\b',
        r'\brenounceOwnership\b',
        r'\bsetAdmin\b',
        r'\bmint\b',
        r'\bburn\b',
        r'\bpause\b',
        r'\bunpause\b',
        r'\bwithdraw\b',
        r'\bemergencyWithdraw\b',
        r'\bblacklist\b',
        r'\bwhitelist\b',
        r'\bsetTaxes\b',
        r'\bsetFee\b',
        r'\bexcludeFrom\b',
        r'\bincludeIn\b'
    ]
    
    # Proxy contract patterns
    PROXY_PATTERNS = [
        r'\bdelegateCall\b',
        r'\bProxyAdmin\b',
        r'\bTransparentUpgradeableProxy\b',
        r'\bBeaconProxy\b',
        r'\bimplementation\b',
        r'\bupgrade\b',
        r'\bupgradeTo\b'
    ]
    
    def __init__(self, config: Dict[str, Any], cache_dir: str):
        super().__init__(config, cache_dir, "contract_analyzer")
        
        self.logger = get_logger(f"{__name__}.ContractAnalyzer")
        
        # Load configuration
        smart_contract_config = config.get('smart_contract_analysis', {})
        analyzer_config = smart_contract_config.get('contract_analyzer', {})
        
        self.api_keys = analyzer_config.get('api_keys', {})  # {chain: api_key}
        self.default_chain = analyzer_config.get('default_chain', 'ethereum')
        self.analyze_bytecode = analyzer_config.get('analyze_bytecode', True)
        self.check_proxy_implementation = analyzer_config.get('check_proxy_implementation', True)
        
        # Rate limiting for API calls
        rate_config = config.get('rate_limiting', {})
        self.request_delay = rate_config.get('etherscan_delay_seconds', 0.2)
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Have-I-Been-Rekt-Contract-Analyzer/1.0'
        })
        
        self.logger.info(f"Initialized Contract Analyzer (chains: {list(self.api_keys.keys())})")
    
    def _make_blockchain_api_request(self, chain: str, module: str, action: str, 
                                   additional_params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Make request to blockchain explorer API (Etherscan, BSCScan, etc.)"""
        
        if chain not in self.BLOCKCHAIN_APIS:
            self.logger.error(f"Unsupported blockchain: {chain}")
            return None
        
        api_config = self.BLOCKCHAIN_APIS[chain]
        api_key = self.api_keys.get(chain)
        
        if not api_key:
            self.logger.warning(f"No API key configured for {chain}")
            return None
        
        try:
            # Rate limiting
            time.sleep(self.request_delay)
            
            params = {
                'module': module,
                'action': action,
                api_config['api_key_param']: api_key
            }
            
            if additional_params:
                params.update(additional_params)
            
            self.logger.debug(f"Making {chain} API request: {module}.{action}")
            
            response = self.session.get(api_config['api_url'], params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('status') == '1' or data.get('message') == 'OK':
                return data
            else:
                error_msg = data.get('message', data.get('result', 'Unknown error'))
                self.logger.warning(f"{chain} API error: {error_msg}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"{chain} API request failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error in {chain} API request: {e}")
            return None
    
    def get_contract_source_code(self, contract_address: str, chain: str = None) -> Optional[Dict[str, Any]]:
        """Get verified source code for a contract"""
        
        if not chain:
            chain = self.default_chain
        
        return self._make_blockchain_api_request(
            chain, 'contract', 'getsourcecode', 
            {'address': contract_address}
        )
    
    def get_contract_abi(self, contract_address: str, chain: str = None) -> Optional[List[Dict[str, Any]]]:
        """Get contract ABI"""
        
        if not chain:
            chain = self.default_chain
        
        response = self._make_blockchain_api_request(
            chain, 'contract', 'getabi',
            {'address': contract_address}
        )
        
        if response and response.get('result'):
            try:
                return json.loads(response['result'])
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse ABI JSON: {e}")
                return None
        
        return None
    
    def analyze_contract(self, contract_address: str, chain: str = None) -> Optional[ContractAnalysis]:
        """
        Perform comprehensive contract analysis.
        
        Args:
            contract_address: Smart contract address to analyze
            chain: Blockchain network
            
        Returns:
            ContractAnalysis with security assessment results
        """
        
        if not chain:
            chain = self.default_chain
        
        cache_key = f"contract_analysis_{contract_address}_{chain}"
        cached_result = self.get_cached_result(cache_key, max_age_hours=24)  # Cache for 24 hours
        
        if cached_result:
            cached_result['analysis_timestamp'] = datetime.fromisoformat(cached_result['analysis_timestamp'])
            return ContractAnalysis(**cached_result)
        
        self.logger.info(f"Analyzing contract: {contract_address} on {chain}")
        
        try:
            # Get contract source code
            source_response = self.get_contract_source_code(contract_address, chain)
            
            if not source_response:
                return None
            
            source_data = source_response.get('result', [{}])[0]
            
            # Basic contract information
            is_verified = source_data.get('SourceCode', '') != ''
            contract_name = source_data.get('ContractName', 'Unknown')
            compiler_version = source_data.get('CompilerVersion', '')
            optimization_used = source_data.get('OptimizationUsed') == '1'
            
            # Initialize analysis
            analysis = ContractAnalysis(
                contract_address=contract_address,
                chain=chain,
                is_verified=is_verified,
                source_code_available=is_verified,
                contract_name=contract_name,
                compiler_version=compiler_version,
                optimization_used=optimization_used,
                proxy_contract=False,
                implementation_address=None,
                can_be_upgraded=False,
                has_admin_functions=False,
                admin_addresses=[],
                ownership_renounced=False,
                has_mint_function=False,
                has_burn_function=False,
                has_pause_function=False,
                max_supply=None,
                current_supply=None,
                transfer_restrictions=[],
                security_issues=[],
                risk_level='low',
                confidence_score=0.5,
                analysis_timestamp=datetime.now(timezone.utc)
            )
            
            if is_verified:
                # Analyze source code
                source_code = source_data.get('SourceCode', '')
                analysis = self._analyze_source_code(analysis, source_code)
                
                # Analyze ABI if available
                abi = self.get_contract_abi(contract_address, chain)
                if abi:
                    analysis = self._analyze_contract_abi(analysis, abi)
                
                # Check for proxy pattern
                if self.check_proxy_implementation:
                    analysis = self._check_proxy_pattern(analysis, source_code, abi)
            else:
                analysis.security_issues.append('contract_not_verified')
                analysis.confidence_score = 0.2
            
            # Calculate final risk level
            analysis = self._calculate_risk_level(analysis)
            
            # Cache results
            cache_data = analysis.__dict__.copy()
            cache_data['analysis_timestamp'] = cache_data['analysis_timestamp'].isoformat()
            self.cache_result(cache_key, cache_data)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing contract {contract_address}: {e}")
            return None
    
    def _analyze_source_code(self, analysis: ContractAnalysis, source_code: str) -> ContractAnalysis:
        """Analyze contract source code for security issues"""
        
        if not source_code:
            return analysis
        
        # Remove JSON wrapper if present (for multi-file contracts)
        if source_code.startswith('{'):
            try:
                parsed = json.loads(source_code)
                if 'sources' in parsed:
                    # Extract all source code from multi-file project
                    all_source = ""
                    for file_path, file_data in parsed['sources'].items():
                        all_source += file_data.get('content', '') + "\n"
                    source_code = all_source
            except json.JSONDecodeError:
                pass
        
        # Check for admin functions
        admin_functions = []
        for pattern in self.ADMIN_FUNCTION_PATTERNS:
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            if matches:
                admin_functions.extend(matches)
        
        if admin_functions:
            analysis.has_admin_functions = True
            analysis.security_issues.append('has_admin_functions')
        
        # Check for specific dangerous functions
        if re.search(r'\bmint\b', source_code, re.IGNORECASE):
            analysis.has_mint_function = True
            analysis.security_issues.append('has_mint_function')
        
        if re.search(r'\bburn\b', source_code, re.IGNORECASE):
            analysis.has_burn_function = True
        
        if re.search(r'\bpause\b', source_code, re.IGNORECASE):
            analysis.has_pause_function = True
            analysis.security_issues.append('has_pause_function')
        
        # Check for proxy patterns
        for pattern in self.PROXY_PATTERNS:
            if re.search(pattern, source_code, re.IGNORECASE):
                analysis.proxy_contract = True
                analysis.can_be_upgraded = True
                analysis.security_issues.append('upgradeable_contract')
                break
        
        # Check for ownership patterns
        if re.search(r'\brenounceOwnership\b', source_code, re.IGNORECASE):
            # Check if ownership is actually renounced in constructor or elsewhere
            if re.search(r'renounceOwnership\(\)', source_code):
                analysis.ownership_renounced = True
            else:
                analysis.security_issues.append('can_renounce_ownership')
        
        # Check for transfer restrictions
        transfer_restrictions = []
        
        if re.search(r'\bblacklist\b', source_code, re.IGNORECASE):
            transfer_restrictions.append('blacklist_functionality')
        
        if re.search(r'\bmaxTransaction\b', source_code, re.IGNORECASE):
            transfer_restrictions.append('max_transaction_limit')
        
        if re.search(r'\btradingEnabled\b', source_code, re.IGNORECASE):
            transfer_restrictions.append('trading_can_be_disabled')
        
        if re.search(r'\bcooldown\b', source_code, re.IGNORECASE):
            transfer_restrictions.append('transfer_cooldown')
        
        analysis.transfer_restrictions = transfer_restrictions
        
        # Check for common security issues
        security_issues = []
        
        # Check for reentrancy guards
        if not re.search(r'\bnonReentrant\b', source_code, re.IGNORECASE):
            if re.search(r'\.call\{', source_code) or re.search(r'\.send\(', source_code):
                security_issues.append('potential_reentrancy')
        
        # Check for unchecked external calls
        if re.search(r'\.call\(', source_code):
            security_issues.append('external_calls_present')
        
        # Check for hardcoded addresses
        if re.search(r'0x[a-fA-F0-9]{40}', source_code):
            security_issues.append('hardcoded_addresses')
        
        analysis.security_issues.extend(security_issues)
        
        return analysis
    
    def _analyze_contract_abi(self, analysis: ContractAnalysis, abi: List[Dict[str, Any]]) -> ContractAnalysis:
        """Analyze contract ABI for additional insights"""
        
        function_analyses = []
        admin_functions = []
        
        for item in abi:
            if item.get('type') == 'function':
                function_name = item.get('name', '')
                
                # Check if function name suggests admin privileges
                if any(pattern in function_name.lower() for pattern in ['owner', 'admin', 'mint', 'burn', 'pause', 'withdraw', 'emergency']):
                    admin_functions.append(function_name)
                
                # Analyze function for risks
                function_analysis = self._analyze_function(item)
                function_analyses.append(function_analysis)
        
        if admin_functions:
            analysis.has_admin_functions = True
            analysis.admin_addresses = admin_functions  # Store function names for now
        
        # Check for specific patterns in ABI
        function_names = [item.get('name', '') for item in abi if item.get('type') == 'function']
        
        if any('mint' in name.lower() for name in function_names):
            analysis.has_mint_function = True
        
        if any('burn' in name.lower() for name in function_names):
            analysis.has_burn_function = True
        
        if any('pause' in name.lower() for name in function_names):
            analysis.has_pause_function = True
        
        return analysis
    
    def _analyze_function(self, function_abi: Dict[str, Any]) -> FunctionAnalysis:
        """Analyze individual function for security risks"""
        
        function_name = function_abi.get('name', '')
        visibility = function_abi.get('stateMutability', 'nonpayable')
        
        # Determine if function is admin-only based on name patterns
        is_admin_only = any(pattern in function_name.lower() 
                           for pattern in ['owner', 'admin', 'emergency', 'rescue'])
        
        # Identify risk factors
        risk_factors = []
        
        if visibility == 'payable':
            risk_factors.append('payable_function')
        
        if is_admin_only:
            risk_factors.append('admin_only_function')
        
        if 'withdraw' in function_name.lower():
            risk_factors.append('withdrawal_function')
        
        if 'mint' in function_name.lower():
            risk_factors.append('mint_function')
        
        return FunctionAnalysis(
            function_name=function_name,
            function_signature=f"{function_name}({','.join([inp.get('type', '') for inp in function_abi.get('inputs', [])])})",
            visibility='external',  # Simplified - would need more complex parsing
            mutability=visibility,
            is_admin_only=is_admin_only,
            modifiers=[],  # Would need source code parsing to extract modifiers
            risk_factors=risk_factors
        )
    
    def _check_proxy_pattern(self, analysis: ContractAnalysis, source_code: str, abi: Optional[List[Dict[str, Any]]]) -> ContractAnalysis:
        """Check if contract follows proxy pattern and can be upgraded"""
        
        # Check source code for proxy patterns
        proxy_indicators = [
            'delegatecall',
            'implementation',
            'upgrade',
            'proxy',
            'beacon'
        ]
        
        proxy_score = 0
        for indicator in proxy_indicators:
            if re.search(indicator, source_code, re.IGNORECASE):
                proxy_score += 1
        
        if proxy_score >= 2:
            analysis.proxy_contract = True
            analysis.can_be_upgraded = True
            analysis.security_issues.append('proxy_pattern_detected')
        
        # Check ABI for proxy functions
        if abi:
            proxy_functions = ['implementation', 'upgrade', 'upgradeTo', 'admin']
            abi_functions = [item.get('name', '').lower() for item in abi if item.get('type') == 'function']
            
            for proxy_func in proxy_functions:
                if proxy_func in abi_functions:
                    analysis.proxy_contract = True
                    analysis.can_be_upgraded = True
                    break
        
        return analysis
    
    def _calculate_risk_level(self, analysis: ContractAnalysis) -> ContractAnalysis:
        """Calculate overall risk level based on analysis results"""
        
        risk_score = 0
        
        # Base score adjustments
        if not analysis.is_verified:
            risk_score += 40  # Unverified contracts are high risk
        
        # Admin function risks
        if analysis.has_admin_functions:
            risk_score += 15
        
        if analysis.has_mint_function:
            risk_score += 10
        
        if analysis.has_pause_function:
            risk_score += 10
        
        # Upgradeability risks
        if analysis.can_be_upgraded:
            risk_score += 20
        
        # Security issue penalties
        critical_issues = ['potential_reentrancy', 'external_calls_present']
        for issue in analysis.security_issues:
            if issue in critical_issues:
                risk_score += 15
            else:
                risk_score += 5
        
        # Transfer restriction risks
        risk_score += len(analysis.transfer_restrictions) * 5
        
        # Ownership benefits
        if analysis.ownership_renounced:
            risk_score -= 10
        
        # Calculate risk level and confidence
        if risk_score >= 60:
            analysis.risk_level = 'critical'
            analysis.confidence_score = 0.9
        elif risk_score >= 40:
            analysis.risk_level = 'high'
            analysis.confidence_score = 0.8
        elif risk_score >= 20:
            analysis.risk_level = 'medium'
            analysis.confidence_score = 0.7
        else:
            analysis.risk_level = 'low'
            analysis.confidence_score = 0.6 if analysis.is_verified else 0.3
        
        return analysis
    
    def lookup_address(self, address: str, chain: str = None) -> Dict[str, Any]:
        """
        Main interface for contract analysis.
        
        Args:
            address: Smart contract address to analyze
            chain: Blockchain network
            
        Returns:
            Dictionary containing contract analysis results
        """
        
        try:
            self.logger.info(f"Starting contract analysis: {address[:10]}...")
            
            analysis = self.analyze_contract(address, chain)
            
            if not analysis:
                return {
                    'found_contract_data': False,
                    'error': 'Failed to analyze contract'
                }
            
            # Build result dictionary
            result = {
                'found_contract_data': True,
                'contract_info': {
                    'name': analysis.contract_name,
                    'chain': analysis.chain,
                    'is_verified': analysis.is_verified,
                    'compiler_version': analysis.compiler_version,
                    'optimization_used': analysis.optimization_used
                },
                'security_analysis': {
                    'risk_level': analysis.risk_level,
                    'confidence_score': analysis.confidence_score,
                    'security_issues': analysis.security_issues,
                    'has_admin_functions': analysis.has_admin_functions,
                    'ownership_renounced': analysis.ownership_renounced
                },
                'functionality_analysis': {
                    'has_mint_function': analysis.has_mint_function,
                    'has_burn_function': analysis.has_burn_function,
                    'has_pause_function': analysis.has_pause_function,
                    'transfer_restrictions': analysis.transfer_restrictions
                },
                'proxy_analysis': {
                    'is_proxy_contract': analysis.proxy_contract,
                    'can_be_upgraded': analysis.can_be_upgraded,
                    'implementation_address': analysis.implementation_address
                },
                'analysis_timestamp': analysis.analysis_timestamp.isoformat()
            }
            
            self.logger.info(f"Contract analysis completed: {address[:10]}... (risk: {analysis.risk_level})")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in contract analysis for {address}: {e}")
            return {
                'found_contract_data': False,
                'error': str(e)
            }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List:
        """Parse contract analysis into risk factors for ML training"""
        
        # Import here to avoid circular imports
        from ..data_collector import RiskFactor, RiskLevel, DataSourceType
        
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_contract_data'):
            return risk_factors
        
        security_analysis = raw_data.get('security_analysis', {})
        risk_level_str = security_analysis.get('risk_level', 'low')
        confidence = security_analysis.get('confidence_score', 0.5)
        
        # Map risk level string to enum
        risk_level_map = {
            'low': RiskLevel.LOW,
            'medium': RiskLevel.MEDIUM,
            'high': RiskLevel.HIGH,
            'critical': RiskLevel.CRITICAL
        }
        
        risk_level = risk_level_map.get(risk_level_str, RiskLevel.MEDIUM)
        
        # Overall contract risk
        if risk_level != RiskLevel.LOW:
            risk_factors.append(RiskFactor(
                type="smart_contract_security",
                description=f"Smart contract security analysis: {risk_level_str} risk",
                risk_level=risk_level,
                confidence=confidence,
                source=DataSourceType.SMART_CONTRACT,
                raw_data=security_analysis
            ))
        
        # Specific security issues
        security_issues = security_analysis.get('security_issues', [])
        for issue in security_issues:
            if 'reentrancy' in issue or 'external_calls' in issue:
                issue_risk_level = RiskLevel.HIGH
            elif 'admin_functions' in issue or 'mint_function' in issue:
                issue_risk_level = RiskLevel.MEDIUM
            else:
                issue_risk_level = RiskLevel.LOW
            
            risk_factors.append(RiskFactor(
                type=f"contract_{issue}",
                description=f"Contract security issue: {issue.replace('_', ' ')}",
                risk_level=issue_risk_level,
                confidence=0.8,
                source=DataSourceType.SMART_CONTRACT,
                raw_data={'security_issue': issue}
            ))
        
        # Proxy contract risks
        proxy_analysis = raw_data.get('proxy_analysis', {})
        if proxy_analysis.get('can_be_upgraded'):
            risk_factors.append(RiskFactor(
                type="upgradeable_contract",
                description="Contract can be upgraded, introducing potential risks",
                risk_level=RiskLevel.MEDIUM,
                confidence=0.9,
                source=DataSourceType.SMART_CONTRACT,
                raw_data=proxy_analysis
            ))
        
        return risk_factors
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get contract analyzer statistics"""
        
        return {
            'supported_chains': list(self.BLOCKCHAIN_APIS.keys()),
            'configured_chains': list(self.api_keys.keys()),
            'default_chain': self.default_chain,
            'analyze_bytecode': self.analyze_bytecode,
            'check_proxy_implementation': self.check_proxy_implementation,
            'cache_entries': len(self.cache) if hasattr(self.cache, '__len__') else 'unknown'
        }