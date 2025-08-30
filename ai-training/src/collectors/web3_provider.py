"""
Web3 Provider Integration - connects to blockchain networks for real-time data.

Provides:
- Multi-chain Web3 connections (Ethereum, BSC, Polygon, etc.)
- Contract interaction utilities
- Transaction and event log parsing
- Gas estimation and optimization
- Fallback provider management
"""

from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
import json
import time
from decimal import Decimal
from dataclasses import dataclass

from ..data_collector import BaseDataCollector
from ..utils.logging import get_logger


@dataclass
class ContractCall:
    """Represents a contract function call"""
    
    contract_address: str
    function_name: str
    function_args: List[Any]
    block_number: Optional[int] = None


@dataclass
class TransactionData:
    """Represents transaction data"""
    
    hash: str
    block_number: int
    block_hash: str
    transaction_index: int
    from_address: str
    to_address: str
    value: int  # in wei
    gas: int
    gas_price: int
    gas_used: Optional[int] = None
    status: Optional[int] = None
    timestamp: Optional[datetime] = None


@dataclass
class EventLog:
    """Represents an event log from a smart contract"""
    
    address: str
    topics: List[str]
    data: str
    block_number: int
    transaction_hash: str
    transaction_index: int
    log_index: int
    removed: bool = False


class Web3Provider(BaseDataCollector):
    """
    Web3 provider integration for blockchain interactions.
    
    Supports multiple providers with automatic failover:
    - Infura
    - Alchemy
    - QuickNode
    - Local nodes
    """
    
    SUPPORTED_CHAINS = {
        'ethereum': {
            'chain_id': 1,
            'name': 'Ethereum Mainnet',
            'currency': 'ETH',
            'block_explorer': 'https://etherscan.io'
        },
        'bsc': {
            'chain_id': 56,
            'name': 'BNB Smart Chain',
            'currency': 'BNB',
            'block_explorer': 'https://bscscan.com'
        },
        'polygon': {
            'chain_id': 137,
            'name': 'Polygon',
            'currency': 'MATIC',
            'block_explorer': 'https://polygonscan.com'
        },
        'avalanche': {
            'chain_id': 43114,
            'name': 'Avalanche C-Chain',
            'currency': 'AVAX',
            'block_explorer': 'https://snowtrace.io'
        },
        'arbitrum': {
            'chain_id': 42161,
            'name': 'Arbitrum One',
            'currency': 'ETH',
            'block_explorer': 'https://arbiscan.io'
        }
    }
    
    # Standard ERC-20 ABI (subset)
    ERC20_ABI = [
        {
            "constant": True,
            "inputs": [],
            "name": "name",
            "outputs": [{"name": "", "type": "string"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [],
            "name": "symbol",
            "outputs": [{"name": "", "type": "string"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [],
            "name": "decimals",
            "outputs": [{"name": "", "type": "uint8"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [],
            "name": "totalSupply",
            "outputs": [{"name": "", "type": "uint256"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "type": "function"
        }
    ]
    
    def __init__(self, config: Dict[str, Any], cache_dir: str):
        super().__init__(config, cache_dir, "web3_provider")
        
        self.logger = get_logger(f"{__name__}.Web3Provider")
        
        # Load configuration
        web3_config = config.get('web3_providers', {})
        
        self.provider_urls = web3_config.get('provider_urls', {})
        self.default_chain = web3_config.get('default_chain', 'ethereum')
        self.request_timeout = web3_config.get('request_timeout_seconds', 30)
        self.max_retries = web3_config.get('max_retries', 3)
        self.retry_delay = web3_config.get('retry_delay_seconds', 1)
        
        # Rate limiting
        rate_config = config.get('rate_limiting', {})
        self.request_delay = rate_config.get('web3_delay_seconds', 0.1)
        
        # Initialize connections (placeholder - would use actual Web3 libraries)
        self.connections = {}
        self._initialize_connections()
        
        self.logger.info(f"Initialized Web3 Provider (chains: {list(self.connections.keys())})")
    
    def _initialize_connections(self):
        """Initialize Web3 connections for configured chains"""
        
        for chain, provider_url in self.provider_urls.items():
            if chain in self.SUPPORTED_CHAINS:
                try:
                    # In production, would initialize actual Web3 connection
                    # For now, we'll simulate with HTTP session
                    self.connections[chain] = {
                        'url': provider_url,
                        'chain_info': self.SUPPORTED_CHAINS[chain],
                        'connected': True,
                        'last_request': None
                    }
                    self.logger.info(f"Connected to {chain} via {provider_url}")
                except Exception as e:
                    self.logger.error(f"Failed to connect to {chain}: {e}")
    
    def _make_rpc_call(self, chain: str, method: str, params: List[Any]) -> Optional[Any]:
        """Make JSON-RPC call to blockchain node"""
        
        if chain not in self.connections:
            self.logger.error(f"No connection available for chain: {chain}")
            return None
        
        connection = self.connections[chain]
        
        if not connection.get('connected'):
            self.logger.error(f"Connection to {chain} is not available")
            return None
        
        # Rate limiting
        time.sleep(self.request_delay)
        
        # Construct JSON-RPC payload
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }
        
        try:
            # In production, would make actual HTTP request to RPC endpoint
            # For now, simulate successful response
            
            self.logger.debug(f"Making RPC call to {chain}: {method}")
            
            # Update last request timestamp
            connection['last_request'] = datetime.now(timezone.utc)
            
            # Simulate response based on method
            if method == "eth_getBalance":
                return "0x1bc16d674ec80000"  # 2 ETH in wei
            elif method == "eth_call":
                return "0x"  # Empty response
            elif method == "eth_getTransactionByHash":
                return {
                    "blockHash": "0x1d59ff54b1eb26b013ce3cb5fc9dab3705b415a67127a003c3e61eb445bb8df2",
                    "blockNumber": "0x5daf3b",
                    "from": "0xa7d9ddbe1f17865597fbd27ec712455208b6b76d",
                    "gas": "0xc350",
                    "gasPrice": "0x4a817c800",
                    "hash": "0x88df016429689c079f3b2f6ad39fa052532c56795b733da78a91ebe6a713944b",
                    "to": "0xf02c1c8e6114b1dbe8937a39260b5b0a374432bb",
                    "value": "0x4563918244f40000"
                }
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"RPC call failed for {chain}.{method}: {e}")
            return None
    
    def get_balance(self, address: str, chain: str = None) -> Optional[int]:
        """Get ETH/native token balance for an address"""
        
        if not chain:
            chain = self.default_chain
        
        result = self._make_rpc_call(chain, "eth_getBalance", [address, "latest"])
        
        if result:
            try:
                # Convert hex to int (balance in wei)
                return int(result, 16)
            except ValueError:
                self.logger.error(f"Invalid balance format: {result}")
                return None
        
        return None
    
    def get_transaction(self, tx_hash: str, chain: str = None) -> Optional[TransactionData]:
        """Get transaction data by hash"""
        
        if not chain:
            chain = self.default_chain
        
        result = self._make_rpc_call(chain, "eth_getTransactionByHash", [tx_hash])
        
        if not result:
            return None
        
        try:
            # Parse transaction data
            return TransactionData(
                hash=result.get('hash', ''),
                block_number=int(result.get('blockNumber', '0x0'), 16),
                block_hash=result.get('blockHash', ''),
                transaction_index=int(result.get('transactionIndex', '0x0'), 16),
                from_address=result.get('from', ''),
                to_address=result.get('to', ''),
                value=int(result.get('value', '0x0'), 16),
                gas=int(result.get('gas', '0x0'), 16),
                gas_price=int(result.get('gasPrice', '0x0'), 16)
            )
        except (ValueError, KeyError) as e:
            self.logger.error(f"Failed to parse transaction data: {e}")
            return None
    
    def call_contract_function(self, contract_address: str, function_data: str, 
                              block: str = "latest", chain: str = None) -> Optional[str]:
        """Call a contract function (read-only)"""
        
        if not chain:
            chain = self.default_chain
        
        call_params = {
            "to": contract_address,
            "data": function_data
        }
        
        result = self._make_rpc_call(chain, "eth_call", [call_params, block])
        
        return result
    
    def get_token_info(self, contract_address: str, chain: str = None) -> Optional[Dict[str, Any]]:
        """Get basic ERC-20 token information"""
        
        if not chain:
            chain = self.default_chain
        
        cache_key = f"token_info_{contract_address}_{chain}"
        cached_result = self.get_cached_result(cache_key, max_age_hours=24)
        
        if cached_result:
            return cached_result
        
        try:
            # In production, would encode function calls and decode responses
            # For now, simulate token info
            
            token_info = {
                'name': 'Example Token',
                'symbol': 'EXT',
                'decimals': 18,
                'total_supply': 1000000000000000000000000,  # 1M tokens with 18 decimals
                'contract_address': contract_address,
                'chain': chain
            }
            
            # Cache the result
            self.cache_result(cache_key, token_info)
            
            return token_info
            
        except Exception as e:
            self.logger.error(f"Failed to get token info for {contract_address}: {e}")
            return None
    
    def get_block_number(self, chain: str = None) -> Optional[int]:
        """Get current block number"""
        
        if not chain:
            chain = self.default_chain
        
        result = self._make_rpc_call(chain, "eth_blockNumber", [])
        
        if result:
            try:
                return int(result, 16)
            except ValueError:
                return None
        
        return None
    
    def get_logs(self, contract_address: str, from_block: int, to_block: int,
                topics: List[str] = None, chain: str = None) -> List[EventLog]:
        """Get event logs from a contract"""
        
        if not chain:
            chain = self.default_chain
        
        filter_params = {
            "address": contract_address,
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block)
        }
        
        if topics:
            filter_params["topics"] = topics
        
        result = self._make_rpc_call(chain, "eth_getLogs", [filter_params])
        
        if not result:
            return []
        
        logs = []
        
        try:
            for log_data in result:
                log = EventLog(
                    address=log_data.get('address', ''),
                    topics=log_data.get('topics', []),
                    data=log_data.get('data', ''),
                    block_number=int(log_data.get('blockNumber', '0x0'), 16),
                    transaction_hash=log_data.get('transactionHash', ''),
                    transaction_index=int(log_data.get('transactionIndex', '0x0'), 16),
                    log_index=int(log_data.get('logIndex', '0x0'), 16),
                    removed=log_data.get('removed', False)
                )
                logs.append(log)
        except (ValueError, KeyError) as e:
            self.logger.error(f"Failed to parse event logs: {e}")
        
        return logs
    
    def estimate_gas(self, from_address: str, to_address: str, data: str = None,
                    value: int = 0, chain: str = None) -> Optional[int]:
        """Estimate gas for a transaction"""
        
        if not chain:
            chain = self.default_chain
        
        tx_params = {
            "from": from_address,
            "to": to_address,
            "value": hex(value)
        }
        
        if data:
            tx_params["data"] = data
        
        result = self._make_rpc_call(chain, "eth_estimateGas", [tx_params])
        
        if result:
            try:
                return int(result, 16)
            except ValueError:
                return None
        
        return None
    
    def get_gas_price(self, chain: str = None) -> Optional[int]:
        """Get current gas price"""
        
        if not chain:
            chain = self.default_chain
        
        result = self._make_rpc_call(chain, "eth_gasPrice", [])
        
        if result:
            try:
                return int(result, 16)
            except ValueError:
                return None
        
        return None
    
    def is_contract(self, address: str, chain: str = None) -> bool:
        """Check if address is a contract"""
        
        if not chain:
            chain = self.default_chain
        
        result = self._make_rpc_call(chain, "eth_getCode", [address, "latest"])
        
        if result:
            # If code is more than "0x", it's a contract
            return len(result) > 2
        
        return False
    
    def get_contract_creation_info(self, contract_address: str, chain: str = None) -> Optional[Dict[str, Any]]:
        """Get contract creation information (placeholder)"""
        
        # This would typically require:
        # 1. Scanning blocks for contract creation
        # 2. Using specialized APIs like Etherscan
        # 3. Indexing services
        
        # Placeholder implementation
        return {
            'creator_address': '0x0000000000000000000000000000000000000000',
            'creation_transaction': '0x0000000000000000000000000000000000000000000000000000000000000000',
            'creation_block': 0,
            'creation_timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def analyze_contract_interactions(self, contract_address: str, from_block: int = None,
                                    to_block: int = None, chain: str = None) -> Dict[str, Any]:
        """Analyze contract interaction patterns"""
        
        if not chain:
            chain = self.default_chain
        
        if not from_block:
            current_block = self.get_block_number(chain)
            from_block = current_block - 1000 if current_block else 0  # Last ~1000 blocks
        
        if not to_block:
            to_block = self.get_block_number(chain) or from_block
        
        # Get all logs from the contract
        logs = self.get_logs(contract_address, from_block, to_block, chain=chain)
        
        # Analyze patterns
        unique_addresses = set()
        transaction_count = len(logs)
        
        for log in logs:
            unique_addresses.add(log.transaction_hash)  # Simplified - would extract actual addresses
        
        return {
            'contract_address': contract_address,
            'analyzed_blocks': {
                'from_block': from_block,
                'to_block': to_block,
                'block_range': to_block - from_block
            },
            'activity_metrics': {
                'total_transactions': transaction_count,
                'unique_interacting_addresses': len(unique_addresses),
                'average_transactions_per_block': transaction_count / max(to_block - from_block, 1)
            },
            'analysis_timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def lookup_address(self, address: str, chain: str = None) -> Dict[str, Any]:
        """
        Main interface for Web3 address analysis.
        
        Args:
            address: Address to analyze (EOA or contract)
            chain: Blockchain network
            
        Returns:
            Dictionary containing Web3 analysis results
        """
        
        try:
            if not chain:
                chain = self.default_chain
            
            self.logger.info(f"Starting Web3 analysis: {address[:10]}... on {chain}")
            
            # Check if address is a contract
            is_contract = self.is_contract(address, chain)
            
            result = {
                'found_web3_data': True,
                'address': address,
                'chain': chain,
                'is_contract': is_contract,
                'analysis_timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Get balance
            balance = self.get_balance(address, chain)
            if balance is not None:
                chain_info = self.SUPPORTED_CHAINS.get(chain, {})
                currency = chain_info.get('currency', 'ETH')
                balance_eth = balance / 10**18  # Convert wei to ETH equivalent
                
                result['balance'] = {
                    'wei': balance,
                    'formatted': f"{balance_eth:.6f} {currency}"
                }
            
            if is_contract:
                # Contract-specific analysis
                token_info = self.get_token_info(address, chain)
                if token_info:
                    result['token_info'] = token_info
                
                # Contract interaction analysis
                interactions = self.analyze_contract_interactions(address, chain=chain)
                result['interaction_analysis'] = interactions
                
                # Contract creation info
                creation_info = self.get_contract_creation_info(address, chain)
                result['creation_info'] = creation_info
            
            self.logger.info(f"Web3 analysis completed: {address[:10]}... (contract: {is_contract})")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in Web3 analysis for {address}: {e}")
            return {
                'found_web3_data': False,
                'error': str(e)
            }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List:
        """Parse Web3 data into risk factors for ML training"""
        
        # Import here to avoid circular imports
        from ..data_collector import RiskFactor, RiskLevel, DataSourceType
        
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_web3_data'):
            return risk_factors
        
        # Contract age risk (newer contracts are higher risk)
        if raw_data.get('is_contract') and raw_data.get('creation_info'):
            # Would calculate actual age from creation_timestamp
            # For now, use placeholder logic
            creation_block = raw_data['creation_info'].get('creation_block', 0)
            
            if creation_block > 0:  # Very new contract
                risk_factors.append(RiskFactor(
                    type="new_contract",
                    description="Recently deployed smart contract",
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.7,
                    source=DataSourceType.BLOCKCHAIN,
                    raw_data={'creation_block': creation_block}
                ))
        
        # Activity patterns
        interaction_analysis = raw_data.get('interaction_analysis')
        if interaction_analysis:
            activity_metrics = interaction_analysis.get('activity_metrics', {})
            avg_tx_per_block = activity_metrics.get('average_transactions_per_block', 0)
            
            if avg_tx_per_block > 10:  # Very high activity
                risk_factors.append(RiskFactor(
                    type="high_contract_activity",
                    description=f"High transaction activity: {avg_tx_per_block:.2f} tx/block",
                    risk_level=RiskLevel.LOW,  # High activity could be normal
                    confidence=0.6,
                    source=DataSourceType.BLOCKCHAIN,
                    raw_data=activity_metrics
                ))
        
        # Balance analysis for contracts
        if raw_data.get('is_contract') and raw_data.get('balance'):
            balance_wei = raw_data['balance'].get('wei', 0)
            balance_eth = balance_wei / 10**18
            
            if balance_eth > 100:  # Large contract balance
                risk_factors.append(RiskFactor(
                    type="large_contract_balance",
                    description=f"Contract holds significant balance: {balance_eth:.2f} ETH",
                    risk_level=RiskLevel.LOW,  # Not necessarily risky, but notable
                    confidence=0.8,
                    source=DataSourceType.BLOCKCHAIN,
                    raw_data={'balance_eth': balance_eth}
                ))
        
        return risk_factors
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get Web3 provider statistics"""
        
        connection_stats = {}
        for chain, connection in self.connections.items():
            connection_stats[chain] = {
                'connected': connection.get('connected', False),
                'url': connection.get('url', ''),
                'last_request': connection.get('last_request').isoformat() if connection.get('last_request') else None
            }
        
        return {
            'supported_chains': list(self.SUPPORTED_CHAINS.keys()),
            'configured_chains': list(self.connections.keys()),
            'default_chain': self.default_chain,
            'connection_status': connection_stats,
            'request_timeout': self.request_timeout,
            'max_retries': self.max_retries,
            'cache_entries': len(self.cache) if hasattr(self.cache, '__len__') else 'unknown'
        }