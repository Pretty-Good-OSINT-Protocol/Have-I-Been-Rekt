"""
Ethereum Blockchain Investigation Dataset Processor - Comprehensive integration
for Ethereum ecosystem fraud detection, smart contract vulnerabilities, and DeFi analysis.

Prioritizes Ethereum-focused data sources:
- Ethereum Fraud Detection Dataset (Kaggle)
- Smart Contract Vulnerability Datasets (HuggingFace)
- BCCC-SCsVul-2024 comprehensive vulnerability dataset
- DeFi protocol analysis and MEV detection
- ERC20 token fraud patterns
"""

import pandas as pd
import numpy as np
import os
import requests
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field
import logging
import pickle
import hashlib
from web3 import Web3
import kaggle

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin


@dataclass
class EthereumTransaction:
    """Represents an Ethereum transaction with comprehensive features"""
    tx_hash: str
    address: str
    fraud_flag: bool
    features: Dict[str, float]
    transaction_type: str  # 'normal', 'erc20', 'contract_creation', 'defi'
    confidence: float = 1.0
    timestamp: Optional[datetime] = None


@dataclass
class SmartContractVulnerability:
    """Represents a smart contract vulnerability"""
    contract_address: str
    vulnerability_type: str  # 'reentrancy', 'overflow', 'access_control', etc.
    severity: str  # 'critical', 'high', 'medium', 'low'
    confidence: float
    description: str
    vulnerability_features: Dict[str, Any] = field(default_factory=dict)


@dataclass 
class DeFiAnalysis:
    """DeFi protocol analysis results"""
    protocol_type: str  # 'dex', 'lending', 'staking', 'bridge', etc.
    risk_indicators: List[str]
    mev_exposure: float  # MEV exploitation risk
    liquidity_risk: float
    governance_risk: float


@dataclass
class EthereumIntelligence:
    """Comprehensive Ethereum ecosystem intelligence"""
    query_address: str
    transaction_analysis: List[EthereumTransaction]
    contract_vulnerabilities: List[SmartContractVulnerability]
    defi_analysis: Optional[DeFiAnalysis]
    erc20_activity: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    ml_features: Dict[str, float]


class EthereumDatasetProcessor(BaseDataCollector, LoggingMixin):
    """
    Comprehensive processor for Ethereum blockchain investigation datasets.
    Prioritizes Ethereum ecosystem analysis with focus on DeFi, smart contracts, and fraud detection.
    """
    
    # Dataset URLs and sources
    DATASET_SOURCES = {
        'ethereum_fraud_kaggle': {
            'kaggle_dataset': 'vagifa/ethereum-frauddetection-dataset',
            'local_path': 'ethereum_fraud_detection.csv'
        },
        'smart_contract_vulnerabilities': {
            'huggingface_repo': 'mwritescode/slither-audited-smart-contracts',
            'local_path': 'smart_contract_vulnerabilities'
        },
        'disl_contracts': {
            'huggingface_repo': 'disl/solidity-contracts',
            'local_path': 'disl_solidity_contracts'
        }
    }
    
    # Ethereum-specific vulnerability types
    VULNERABILITY_TYPES = {
        'reentrancy': 'Reentrancy attacks allowing recursive calls',
        'integer_overflow': 'Integer overflow/underflow vulnerabilities', 
        'access_control': 'Access control and authorization issues',
        'front_running': 'Front-running and MEV exploitation vectors',
        'flash_loan': 'Flash loan attack vulnerabilities',
        'oracle_manipulation': 'Price oracle manipulation risks',
        'governance_attack': 'Governance token and voting manipulation',
        'liquidity_drain': 'Liquidity pool drainage attacks',
        'sandwich_attack': 'Sandwich attack vulnerabilities in AMMs',
        'rug_pull': 'Rug pull and exit scam patterns'
    }
    
    # DeFi protocol categories
    DEFI_PROTOCOLS = {
        'dex': ['uniswap', 'sushiswap', '1inch', 'curve', 'balancer'],
        'lending': ['aave', 'compound', 'maker', 'liquity', 'euler'],
        'staking': ['lido', 'rocketpool', 'ankr', 'stakewise'],
        'bridge': ['multichain', 'synapse', 'hop', 'across', 'stargate'],
        'derivatives': ['gmx', 'dydx', 'perpetual', 'mcdex'],
        'yield': ['yearn', 'convex', 'beefy', 'harvest']
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # Configuration
        self.data_dir = config.get('ethereum_data_dir', './data/ethereum')
        self.enable_auto_download = config.get('ethereum_auto_download', True)
        
        # Web3 configuration for contract analysis
        self.web3_provider = config.get('web3_provider_url')
        self.web3 = None
        if self.web3_provider:
            try:
                self.web3 = Web3(Web3.HTTPProvider(self.web3_provider))
                self.logger.info("Web3 provider connected")
            except Exception as e:
                self.logger.warning(f"Web3 connection failed: {e}")
        
        # Kaggle configuration
        self.kaggle_configured = self._check_kaggle_config()
        
        # Ensure data directory exists
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Dataset containers
        self.fraud_dataset = None
        self.vulnerability_data = {}
        self.contract_metadata = {}
        
        # Load datasets if available
        self._load_datasets()
        
        self.logger.info("Ethereum dataset processor initialized",
                        fraud_records=len(self.fraud_dataset) if self.fraud_dataset is not None else 0,
                        vulnerability_sources=len(self.vulnerability_data))
    
    @property
    def source_name(self) -> str:
        return "ethereum_datasets"
    
    @property  
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.ACADEMIC
    
    def is_configured(self) -> bool:
        """Check if Ethereum datasets are available"""
        fraud_data_path = os.path.join(self.data_dir, 
                                     self.DATASET_SOURCES['ethereum_fraud_kaggle']['local_path'])
        return os.path.exists(fraud_data_path) or self.kaggle_configured
    
    def _check_kaggle_config(self) -> bool:
        """Check if Kaggle is configured"""
        try:
            kaggle.api.authenticate()
            return True
        except Exception as e:
            self.logger.debug(f"Kaggle authentication failed: {e}")
            return False
    
    def download_datasets(self) -> bool:
        """Download Ethereum datasets from various sources"""
        
        if not self.enable_auto_download:
            self.logger.warning("Auto-download disabled. Please download datasets manually.")
            return False
        
        success_count = 0
        total_datasets = len(self.DATASET_SOURCES)
        
        # Download Kaggle fraud detection dataset
        if self.kaggle_configured:
            try:
                kaggle_dataset = self.DATASET_SOURCES['ethereum_fraud_kaggle']['kaggle_dataset']
                self.logger.info(f"Downloading Kaggle dataset: {kaggle_dataset}")
                
                kaggle.api.dataset_download_files(
                    kaggle_dataset,
                    path=self.data_dir,
                    unzip=True
                )
                success_count += 1
                self.logger.info("Ethereum fraud detection dataset downloaded")
                
            except Exception as e:
                self.logger.error(f"Kaggle dataset download failed: {e}")
        
        # Download HuggingFace datasets (placeholder - would need HuggingFace datasets library)
        try:
            self.logger.info("HuggingFace datasets require manual setup:")
            self.logger.info("1. Install: pip install datasets")
            self.logger.info("2. Use datasets.load_dataset() for smart contract data")
            self.logger.info("3. Suggested datasets:")
            for name, config in self.DATASET_SOURCES.items():
                if 'huggingface_repo' in config:
                    self.logger.info(f"   - {config['huggingface_repo']}")
        
        except Exception as e:
            self.logger.error(f"HuggingFace dataset setup info failed: {e}")
        
        return success_count > 0
    
    def _load_datasets(self) -> bool:
        """Load Ethereum datasets from local files"""
        
        loaded_count = 0
        
        try:
            # Load fraud detection dataset
            fraud_path = os.path.join(self.data_dir, 
                                    self.DATASET_SOURCES['ethereum_fraud_kaggle']['local_path'])
            
            # Look for CSV files in directory (Kaggle extracts with various names)
            csv_files = [f for f in os.listdir(self.data_dir) if f.endswith('.csv')] if os.path.exists(self.data_dir) else []
            
            for csv_file in csv_files:
                try:
                    csv_path = os.path.join(self.data_dir, csv_file)
                    df = pd.read_csv(csv_path)
                    
                    # Check if this looks like the Ethereum fraud dataset
                    if 'FLAG' in df.columns or 'flag' in df.columns:
                        self.fraud_dataset = df
                        loaded_count += 1
                        self.logger.info(f"Loaded Ethereum fraud dataset: {len(df)} records from {csv_file}")
                        break
                        
                except Exception as e:
                    self.logger.debug(f"Error loading {csv_file}: {e}")
            
            # Load vulnerability data (placeholder for future HuggingFace integration)
            vuln_dir = os.path.join(self.data_dir, 'vulnerabilities')
            if os.path.exists(vuln_dir):
                for vuln_file in os.listdir(vuln_dir):
                    if vuln_file.endswith(('.json', '.csv')):
                        try:
                            vuln_path = os.path.join(vuln_dir, vuln_file)
                            if vuln_file.endswith('.json'):
                                with open(vuln_path, 'r') as f:
                                    self.vulnerability_data[vuln_file] = json.load(f)
                            else:
                                self.vulnerability_data[vuln_file] = pd.read_csv(vuln_path)
                            loaded_count += 1
                        except Exception as e:
                            self.logger.debug(f"Error loading vulnerability data {vuln_file}: {e}")
            
            return loaded_count > 0
            
        except Exception as e:
            self.logger.error(f"Dataset loading failed: {e}")
            return False
    
    def analyze_address_fraud(self, address: str) -> Optional[EthereumTransaction]:
        """Analyze address for fraud patterns using the fraud detection dataset"""
        
        if self.fraud_dataset is None:
            return None
        
        try:
            # Look for address in dataset (exact match)
            address_lower = address.lower()
            matching_records = self.fraud_dataset[
                self.fraud_dataset.apply(
                    lambda row: any(str(val).lower() == address_lower for val in row if pd.notna(val)), 
                    axis=1
                )
            ]
            
            if matching_records.empty:
                return None
            
            # Use first matching record
            record = matching_records.iloc[0]
            
            # Extract fraud flag
            fraud_flag = False
            flag_col = None
            for col in ['FLAG', 'flag', 'is_fraud', 'fraud']:
                if col in record.index:
                    fraud_flag = bool(record[col])
                    flag_col = col
                    break
            
            # Extract features (all numeric columns except the flag)
            features = {}
            for col in self.fraud_dataset.columns:
                if col != flag_col and pd.api.types.is_numeric_dtype(self.fraud_dataset[col]):
                    features[col] = float(record[col]) if pd.notna(record[col]) else 0.0
            
            # Classify transaction type based on features
            tx_type = self._classify_transaction_type(features)
            
            return EthereumTransaction(
                tx_hash=f"dataset_{address}_{hash(address) % 1000000}",
                address=address,
                fraud_flag=fraud_flag,
                features=features,
                transaction_type=tx_type,
                confidence=1.0 if fraud_flag else 0.8
            )
            
        except Exception as e:
            self.logger.error(f"Address fraud analysis failed for {address}: {e}")
            return None
    
    def _classify_transaction_type(self, features: Dict[str, float]) -> str:
        """Classify transaction type based on features"""
        
        # Look for ERC20 indicators
        erc20_indicators = ['erc20', 'token', 'total_ether_sent_contracts', 'total_ether_received_contracts']
        if any(indicator in str(k).lower() for k in features.keys() for indicator in erc20_indicators):
            return 'erc20'
        
        # Look for contract indicators
        contract_indicators = ['contract', 'unique_sent_to_addresses', 'unique_received_from_addresses']
        if any(indicator in str(k).lower() for k in features.keys() for indicator in contract_indicators):
            return 'contract_creation'
        
        # High-frequency patterns might indicate DeFi
        if features.get('total_transactions', 0) > 100:
            return 'defi'
        
        return 'normal'
    
    def detect_smart_contract_vulnerabilities(self, address: str) -> List[SmartContractVulnerability]:
        """Detect smart contract vulnerabilities for an address"""
        
        vulnerabilities = []
        
        try:
            # If we have Web3, try to analyze contract
            if self.web3 and self.web3.is_connected():
                vulnerabilities.extend(self._analyze_contract_with_web3(address))
            
            # Check vulnerability databases
            vulnerabilities.extend(self._check_vulnerability_databases(address))
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Vulnerability detection failed for {address}: {e}")
            return []
    
    def _analyze_contract_with_web3(self, address: str) -> List[SmartContractVulnerability]:
        """Analyze contract using Web3 connection"""
        
        vulnerabilities = []
        
        try:
            # Check if address is a contract
            code = self.web3.eth.get_code(Web3.to_checksum_address(address))
            
            if len(code) > 2:  # Has contract code
                # Basic heuristic checks (placeholder for more sophisticated analysis)
                code_str = code.hex()
                
                # Check for potential reentrancy patterns
                if 'call' in code_str and 'send' in code_str:
                    vulnerabilities.append(SmartContractVulnerability(
                        contract_address=address,
                        vulnerability_type='reentrancy',
                        severity='medium',
                        confidence=0.6,
                        description='Potential reentrancy vulnerability detected',
                        vulnerability_features={'code_size': len(code)}
                    ))
                
                # Check for access control patterns
                if 'onlyowner' in code_str.lower() or 'require' in code_str:
                    vulnerabilities.append(SmartContractVulnerability(
                        contract_address=address,
                        vulnerability_type='access_control',
                        severity='low',
                        confidence=0.4,
                        description='Access control patterns detected',
                        vulnerability_features={'access_patterns': True}
                    ))
        
        except Exception as e:
            self.logger.debug(f"Web3 contract analysis error: {e}")
        
        return vulnerabilities
    
    def _check_vulnerability_databases(self, address: str) -> List[SmartContractVulnerability]:
        """Check loaded vulnerability databases"""
        
        vulnerabilities = []
        
        for db_name, db_data in self.vulnerability_data.items():
            try:
                if isinstance(db_data, pd.DataFrame):
                    # Look for address in DataFrame
                    matching_rows = db_data[
                        db_data.apply(
                            lambda row: any(str(val).lower() == address.lower() for val in row if pd.notna(val)),
                            axis=1
                        )
                    ]
                    
                    for _, row in matching_rows.iterrows():
                        vuln_type = row.get('vulnerability_type', 'unknown')
                        severity = row.get('severity', 'medium')
                        confidence = float(row.get('confidence', 0.7))
                        
                        vulnerabilities.append(SmartContractVulnerability(
                            contract_address=address,
                            vulnerability_type=vuln_type,
                            severity=severity,
                            confidence=confidence,
                            description=f"Vulnerability found in {db_name}",
                            vulnerability_features={'source_database': db_name}
                        ))
                
            except Exception as e:
                self.logger.debug(f"Database check error for {db_name}: {e}")
        
        return vulnerabilities
    
    def analyze_defi_exposure(self, address: str) -> Optional[DeFiAnalysis]:
        """Analyze DeFi protocol exposure and risks"""
        
        try:
            risk_indicators = []
            mev_exposure = 0.0
            liquidity_risk = 0.0
            governance_risk = 0.0
            protocol_type = 'unknown'
            
            # Analyze transaction patterns from fraud dataset
            fraud_analysis = self.analyze_address_fraud(address)
            if fraud_analysis and fraud_analysis.transaction_type == 'defi':
                protocol_type = 'defi_general'
                
                # High transaction volume indicates MEV exposure
                tx_count = fraud_analysis.features.get('total_transactions', 0)
                if tx_count > 1000:
                    mev_exposure = min(0.9, tx_count / 10000)
                    risk_indicators.append('high_transaction_volume')
                
                # Multiple contracts indicate protocol interaction
                unique_contracts = fraud_analysis.features.get('unique_sent_to_addresses', 0)
                if unique_contracts > 10:
                    liquidity_risk = min(0.8, unique_contracts / 50)
                    risk_indicators.append('multiple_protocol_interaction')
            
            # Check for specific protocol patterns (would need more data)
            if self._is_dex_related(address):
                protocol_type = 'dex'
                mev_exposure += 0.3  # DEXs are high MEV risk
            elif self._is_lending_related(address):
                protocol_type = 'lending'
                liquidity_risk += 0.2
            
            # Governance token exposure (placeholder)
            if self._has_governance_tokens(address):
                governance_risk = 0.4
                risk_indicators.append('governance_exposure')
            
            if not risk_indicators:
                return None
            
            return DeFiAnalysis(
                protocol_type=protocol_type,
                risk_indicators=risk_indicators,
                mev_exposure=min(1.0, mev_exposure),
                liquidity_risk=min(1.0, liquidity_risk), 
                governance_risk=min(1.0, governance_risk)
            )
            
        except Exception as e:
            self.logger.error(f"DeFi analysis failed for {address}: {e}")
            return None
    
    def _is_dex_related(self, address: str) -> bool:
        """Check if address is related to DEX protocols"""
        # Placeholder - would need actual DEX contract addresses
        return False
    
    def _is_lending_related(self, address: str) -> bool:
        """Check if address is related to lending protocols"""
        # Placeholder - would need actual lending contract addresses
        return False
    
    def _has_governance_tokens(self, address: str) -> bool:
        """Check if address holds governance tokens"""
        # Placeholder - would need token balance analysis
        return False
    
    def analyze_address(self, address: str) -> Optional[EthereumIntelligence]:
        """Comprehensive Ethereum address analysis"""
        
        try:
            # Fraud analysis
            fraud_analysis = self.analyze_address_fraud(address)
            transaction_analysis = [fraud_analysis] if fraud_analysis else []
            
            # Vulnerability analysis
            vulnerabilities = self.detect_smart_contract_vulnerabilities(address)
            
            # DeFi analysis
            defi_analysis = self.analyze_defi_exposure(address)
            
            # ERC20 analysis (placeholder)
            erc20_activity = self._analyze_erc20_activity(address)
            
            # ML features
            ml_features = self._extract_ml_features(address, transaction_analysis, vulnerabilities, defi_analysis)
            
            # Risk assessment
            risk_assessment = self._create_risk_assessment(transaction_analysis, vulnerabilities, defi_analysis)
            
            intelligence = EthereumIntelligence(
                query_address=address,
                transaction_analysis=transaction_analysis,
                contract_vulnerabilities=vulnerabilities,
                defi_analysis=defi_analysis,
                erc20_activity=erc20_activity,
                risk_assessment=risk_assessment,
                ml_features=ml_features
            )
            
            return intelligence
            
        except Exception as e:
            self.logger.error(f"Ethereum address analysis failed for {address}: {e}")
            return None
    
    def _analyze_erc20_activity(self, address: str) -> Dict[str, Any]:
        """Analyze ERC20 token activity"""
        # Placeholder for ERC20 analysis
        return {
            'token_transfers': 0,
            'unique_tokens': 0,
            'high_value_transfers': False
        }
    
    def _extract_ml_features(self, address: str, transactions: List[EthereumTransaction],
                           vulnerabilities: List[SmartContractVulnerability], 
                           defi_analysis: Optional[DeFiAnalysis]) -> Dict[str, float]:
        """Extract machine learning features"""
        
        features = {
            'fraud_transactions': sum(1 for tx in transactions if tx.fraud_flag),
            'total_transactions': len(transactions),
            'vulnerability_count': len(vulnerabilities),
            'critical_vulnerabilities': sum(1 for v in vulnerabilities if v.severity == 'critical'),
            'high_vulnerabilities': sum(1 for v in vulnerabilities if v.severity == 'high'),
        }
        
        # Add DeFi features
        if defi_analysis:
            features.update({
                'mev_exposure': defi_analysis.mev_exposure,
                'liquidity_risk': defi_analysis.liquidity_risk,
                'governance_risk': defi_analysis.governance_risk,
                'defi_risk_indicators': len(defi_analysis.risk_indicators)
            })
        
        # Add transaction features if available
        if transactions:
            tx = transactions[0]  # Use first transaction's features
            for key, value in tx.features.items():
                if isinstance(value, (int, float)):
                    features[f"tx_{key}"] = float(value)
        
        return features
    
    def _create_risk_assessment(self, transactions: List[EthereumTransaction],
                               vulnerabilities: List[SmartContractVulnerability],
                               defi_analysis: Optional[DeFiAnalysis]) -> Dict[str, Any]:
        """Create comprehensive risk assessment"""
        
        risk_score = 0.0
        risk_factors = []
        
        # Transaction-based risk
        fraud_transactions = sum(1 for tx in transactions if tx.fraud_flag)
        if fraud_transactions > 0:
            risk_score += 0.6
            risk_factors.append('fraudulent_transactions')
        
        # Vulnerability-based risk
        critical_vulns = sum(1 for v in vulnerabilities if v.severity == 'critical')
        high_vulns = sum(1 for v in vulnerabilities if v.severity == 'high')
        
        if critical_vulns > 0:
            risk_score += 0.4
            risk_factors.append('critical_vulnerabilities')
        elif high_vulns > 0:
            risk_score += 0.2  
            risk_factors.append('high_vulnerabilities')
        
        # DeFi-based risk
        if defi_analysis:
            defi_risk = max(defi_analysis.mev_exposure, defi_analysis.liquidity_risk, defi_analysis.governance_risk)
            risk_score += defi_risk * 0.3
            if defi_risk > 0.7:
                risk_factors.append('high_defi_risk')
        
        risk_score = min(1.0, risk_score)
        
        # Risk level classification
        if risk_score >= 0.8:
            risk_level = 'critical'
        elif risk_score >= 0.6:
            risk_level = 'high'
        elif risk_score >= 0.3:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'confidence': 0.85,
            'risk_factors': risk_factors,
            'ethereum_specific': True
        }
    
    def lookup_address(self, address: str) -> Optional[Dict[str, Any]]:
        """Standard lookup interface for Ethereum addresses"""
        
        intelligence = self.analyze_address(address)
        
        if not intelligence:
            return None
        
        return {
            'address': address,
            'found_ethereum_data': True,
            'timestamp': datetime.utcnow().isoformat(),
            'fraud_analysis': {
                'has_fraud_records': len(intelligence.transaction_analysis) > 0 and any(tx.fraud_flag for tx in intelligence.transaction_analysis),
                'transaction_types': list(set(tx.transaction_type for tx in intelligence.transaction_analysis)),
                'total_features': sum(len(tx.features) for tx in intelligence.transaction_analysis)
            },
            'vulnerability_analysis': {
                'vulnerability_count': len(intelligence.contract_vulnerabilities),
                'severity_breakdown': {
                    severity: sum(1 for v in intelligence.contract_vulnerabilities if v.severity == severity)
                    for severity in ['critical', 'high', 'medium', 'low']
                },
                'vulnerability_types': list(set(v.vulnerability_type for v in intelligence.contract_vulnerabilities))
            },
            'defi_analysis': {
                'protocol_type': intelligence.defi_analysis.protocol_type if intelligence.defi_analysis else None,
                'mev_exposure': intelligence.defi_analysis.mev_exposure if intelligence.defi_analysis else 0.0,
                'risk_indicators': intelligence.defi_analysis.risk_indicators if intelligence.defi_analysis else []
            },
            'ml_features': intelligence.ml_features,
            'risk_assessment': intelligence.risk_assessment
        }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse Ethereum data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_ethereum_data'):
            return risk_factors
        
        fraud_analysis = raw_data.get('fraud_analysis', {})
        vuln_analysis = raw_data.get('vulnerability_analysis', {})
        defi_analysis = raw_data.get('defi_analysis', {})
        risk_assessment = raw_data.get('risk_assessment', {})
        
        # Fraud-based factors
        if fraud_analysis.get('has_fraud_records'):
            risk_factors.append(RiskFactor(
                type="ethereum_fraud_detected",
                description="Address flagged in Ethereum fraud detection dataset",
                risk_level=RiskLevel.HIGH,
                confidence=0.9,
                source=DataSourceType.ACADEMIC,
                raw_data={'transaction_types': fraud_analysis.get('transaction_types', [])}
            ))
        
        # Vulnerability-based factors
        vuln_count = vuln_analysis.get('vulnerability_count', 0)
        if vuln_count > 0:
            severity_breakdown = vuln_analysis.get('severity_breakdown', {})
            
            if severity_breakdown.get('critical', 0) > 0:
                risk_level = RiskLevel.CRITICAL
            elif severity_breakdown.get('high', 0) > 0:
                risk_level = RiskLevel.HIGH
            else:
                risk_level = RiskLevel.MEDIUM
            
            risk_factors.append(RiskFactor(
                type="smart_contract_vulnerabilities",
                description=f"Smart contract vulnerabilities detected: {vuln_count} total",
                risk_level=risk_level,
                confidence=0.85,
                source=DataSourceType.ACADEMIC,
                raw_data={
                    'vulnerability_count': vuln_count,
                    'severity_breakdown': severity_breakdown,
                    'vulnerability_types': vuln_analysis.get('vulnerability_types', [])
                }
            ))
        
        # DeFi-based factors  
        mev_exposure = defi_analysis.get('mev_exposure', 0.0)
        if mev_exposure > 0.5:
            risk_factors.append(RiskFactor(
                type="high_mev_exposure",
                description=f"High MEV exploitation risk: {mev_exposure:.2f}",
                risk_level=RiskLevel.HIGH if mev_exposure > 0.8 else RiskLevel.MEDIUM,
                confidence=0.7,
                source=DataSourceType.ACADEMIC,
                raw_data={'mev_exposure': mev_exposure}
            ))
        
        risk_indicators = defi_analysis.get('risk_indicators', [])
        if risk_indicators:
            risk_factors.append(RiskFactor(
                type="defi_risk_exposure",
                description=f"DeFi protocol risks: {', '.join(risk_indicators)}",
                risk_level=RiskLevel.MEDIUM,
                confidence=0.6,
                source=DataSourceType.ACADEMIC,
                raw_data={'risk_indicators': risk_indicators}
            ))
        
        return risk_factors
    
    def get_training_data(self, include_features: bool = True) -> Dict[str, Any]:
        """Extract training data for ML models"""
        
        training_data = {
            'ethereum_transactions': [],
            'smart_contract_vulnerabilities': [],
            'metadata': {
                'dataset_source': 'ethereum_comprehensive',
                'total_transactions': 0,
                'fraud_transactions': 0,
                'vulnerability_records': 0,
                'feature_count': 0
            }
        }
        
        try:
            if self.fraud_dataset is not None:
                fraud_count = 0
                
                for _, row in self.fraud_dataset.iterrows():
                    # Extract fraud flag
                    fraud_flag = False
                    for col in ['FLAG', 'flag', 'is_fraud', 'fraud']:
                        if col in row.index:
                            fraud_flag = bool(row[col])
                            break
                    
                    if fraud_flag:
                        fraud_count += 1
                    
                    # Extract features if requested
                    features = {}
                    if include_features:
                        for col in self.fraud_dataset.columns:
                            if pd.api.types.is_numeric_dtype(self.fraud_dataset[col]):
                                features[col] = float(row[col]) if pd.notna(row[col]) else 0.0
                    
                    training_data['ethereum_transactions'].append({
                        'features': features,
                        'is_fraud': fraud_flag,
                        'source': 'ethereum_fraud_dataset'
                    })
                
                training_data['metadata'].update({
                    'total_transactions': len(self.fraud_dataset),
                    'fraud_transactions': fraud_count,
                    'feature_count': len([col for col in self.fraud_dataset.columns 
                                        if pd.api.types.is_numeric_dtype(self.fraud_dataset[col])])
                })
            
            # Add vulnerability training data
            for db_name, db_data in self.vulnerability_data.items():
                if isinstance(db_data, pd.DataFrame):
                    for _, row in db_data.iterrows():
                        training_data['smart_contract_vulnerabilities'].append({
                            'vulnerability_type': row.get('vulnerability_type', 'unknown'),
                            'severity': row.get('severity', 'medium'),
                            'features': {col: val for col, val in row.items() 
                                       if pd.api.types.is_numeric_dtype(type(val))},
                            'source': db_name
                        })
            
            training_data['metadata']['vulnerability_records'] = len(training_data['smart_contract_vulnerabilities'])
            
            self.logger.info("Ethereum training data extracted",
                           transactions=training_data['metadata']['total_transactions'],
                           vulnerabilities=training_data['metadata']['vulnerability_records'])
            
            return training_data
            
        except Exception as e:
            self.logger.error(f"Training data extraction failed: {e}")
            return training_data
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get Ethereum dataset processor statistics"""
        
        stats = {
            'configured': self.is_configured(),
            'kaggle_configured': self.kaggle_configured,
            'web3_connected': self.web3 is not None and (self.web3.is_connected() if self.web3 else False),
            'data_directory': self.data_dir,
            'auto_download_enabled': self.enable_auto_download
        }
        
        if self.fraud_dataset is not None:
            fraud_count = 0
            for col in ['FLAG', 'flag', 'is_fraud', 'fraud']:
                if col in self.fraud_dataset.columns:
                    fraud_count = self.fraud_dataset[col].sum()
                    break
            
            stats.update({
                'fraud_dataset_size': len(self.fraud_dataset),
                'fraud_records': int(fraud_count),
                'fraud_features': len([col for col in self.fraud_dataset.columns 
                                     if pd.api.types.is_numeric_dtype(self.fraud_dataset[col])])
            })
        
        stats.update({
            'vulnerability_databases': len(self.vulnerability_data),
            'supported_vulnerabilities': list(self.VULNERABILITY_TYPES.keys()),
            'supported_defi_protocols': list(self.DEFI_PROTOCOLS.keys())
        })
        
        return stats