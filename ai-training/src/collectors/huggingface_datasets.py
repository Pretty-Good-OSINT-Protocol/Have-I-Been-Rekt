"""
HuggingFace Datasets Integration - Streamlined access to blockchain investigation
datasets hosted on HuggingFace Hub, with focus on smart contract vulnerabilities
and Ethereum ecosystem analysis.
"""

import os
import json
import pandas as pd
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
import logging

from ..data_collector import BaseDataCollector, DataSourceType
from ..utils.logging import LoggingMixin

try:
    from datasets import load_dataset, Dataset
    DATASETS_AVAILABLE = True
except ImportError:
    DATASETS_AVAILABLE = False
    Dataset = None


class HuggingFaceDatasetManager(BaseDataCollector, LoggingMixin):
    """
    Manager for blockchain investigation datasets on HuggingFace Hub.
    Provides unified access to smart contract vulnerability datasets.
    """
    
    # Available datasets on HuggingFace Hub
    AVAILABLE_DATASETS = {
        'smart_contract_vulnerabilities': {
            'repo_id': 'mwritescode/slither-audited-smart-contracts',
            'description': 'Smart contract vulnerability dataset with Slither analysis',
            'data_type': 'vulnerability_analysis'
        },
        'malicious_smart_contracts': {
            'repo_id': 'forta/malicious-smart-contract-dataset',
            'description': 'Malicious smart contract detection dataset',
            'data_type': 'malicious_contracts'
        },
        'disl_solidity_contracts': {
            'repo_id': 'disl/solidity-contracts',
            'description': 'Large-scale Solidity smart contract dataset (514k+ contracts)',
            'data_type': 'contract_source_code'
        }
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # Configuration
        self.data_dir = config.get('huggingface_cache_dir', './data/huggingface')
        self.auto_download = config.get('huggingface_auto_download', True)
        
        # HuggingFace configuration
        self.hf_token = config.get('huggingface_token')  # Optional for private datasets
        
        # Ensure data directory exists
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Dataset cache
        self.loaded_datasets = {}
        
        # Check if datasets library is available
        if not DATASETS_AVAILABLE:
            self.logger.warning("HuggingFace datasets library not installed. Run: pip install datasets")
        
        self.logger.info("HuggingFace dataset manager initialized",
                        datasets_lib_available=DATASETS_AVAILABLE,
                        available_datasets=len(self.AVAILABLE_DATASETS))
    
    @property
    def source_name(self) -> str:
        return "huggingface_datasets"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.ACADEMIC
    
    def is_configured(self) -> bool:
        """Check if HuggingFace datasets integration is configured"""
        return DATASETS_AVAILABLE
    
    def list_available_datasets(self) -> Dict[str, Dict[str, str]]:
        """List all available datasets"""
        return self.AVAILABLE_DATASETS.copy()
    
    def load_dataset_from_hub(self, dataset_name: str, split: str = 'train') -> Optional[Dataset]:
        """Load dataset from HuggingFace Hub"""
        
        if not DATASETS_AVAILABLE:
            self.logger.error("HuggingFace datasets library not available")
            return None
        
        if dataset_name not in self.AVAILABLE_DATASETS:
            self.logger.error(f"Unknown dataset: {dataset_name}")
            return None
        
        try:
            dataset_config = self.AVAILABLE_DATASETS[dataset_name]
            repo_id = dataset_config['repo_id']
            
            self.logger.info(f"Loading dataset: {repo_id}")
            
            # Load with authentication if token provided
            load_kwargs = {
                'path': repo_id,
                'split': split,
                'cache_dir': self.data_dir
            }
            
            if self.hf_token:
                load_kwargs['use_auth_token'] = self.hf_token
            
            dataset = load_dataset(**load_kwargs)
            
            # Cache the dataset
            self.loaded_datasets[dataset_name] = {
                'dataset': dataset,
                'loaded_at': datetime.utcnow(),
                'config': dataset_config
            }
            
            self.logger.info(f"Successfully loaded dataset: {dataset_name} ({len(dataset)} samples)")
            
            return dataset
            
        except Exception as e:
            self.logger.error(f"Failed to load dataset {dataset_name}: {e}")
            return None
    
    def get_smart_contract_vulnerabilities(self) -> Optional[pd.DataFrame]:
        """Get smart contract vulnerability data as DataFrame"""
        
        dataset_name = 'smart_contract_vulnerabilities'
        
        # Check cache first
        if dataset_name in self.loaded_datasets:
            dataset = self.loaded_datasets[dataset_name]['dataset']
        else:
            dataset = self.load_dataset_from_hub(dataset_name)
        
        if not dataset:
            return None
        
        try:
            # Convert to pandas DataFrame
            df = dataset.to_pandas()
            
            self.logger.info(f"Smart contract vulnerabilities DataFrame: {len(df)} records")
            
            return df
            
        except Exception as e:
            self.logger.error(f"Failed to convert vulnerability dataset to DataFrame: {e}")
            return None
    
    def get_malicious_contracts(self) -> Optional[pd.DataFrame]:
        """Get malicious smart contract data as DataFrame"""
        
        dataset_name = 'malicious_smart_contracts'
        
        # Check cache first
        if dataset_name in self.loaded_datasets:
            dataset = self.loaded_datasets[dataset_name]['dataset']
        else:
            dataset = self.load_dataset_from_hub(dataset_name)
        
        if not dataset:
            return None
        
        try:
            # Convert to pandas DataFrame
            df = dataset.to_pandas()
            
            self.logger.info(f"Malicious contracts DataFrame: {len(df)} records")
            
            return df
            
        except Exception as e:
            self.logger.error(f"Failed to convert malicious contracts dataset to DataFrame: {e}")
            return None
    
    def get_solidity_contracts(self, sample_size: Optional[int] = 10000) -> Optional[pd.DataFrame]:
        """Get Solidity contract source code dataset"""
        
        dataset_name = 'disl_solidity_contracts'
        
        # Check cache first
        if dataset_name in self.loaded_datasets:
            dataset = self.loaded_datasets[dataset_name]['dataset']
        else:
            dataset = self.load_dataset_from_hub(dataset_name)
        
        if not dataset:
            return None
        
        try:
            # For large datasets, optionally sample
            if sample_size and len(dataset) > sample_size:
                dataset = dataset.shuffle(seed=42).select(range(sample_size))
                self.logger.info(f"Sampled {sample_size} contracts from {dataset_name}")
            
            # Convert to pandas DataFrame
            df = dataset.to_pandas()
            
            self.logger.info(f"Solidity contracts DataFrame: {len(df)} records")
            
            return df
            
        except Exception as e:
            self.logger.error(f"Failed to convert Solidity contracts dataset to DataFrame: {e}")
            return None
    
    def search_contract_by_address(self, address: str) -> Optional[Dict[str, Any]]:
        """Search for contract information by address across loaded datasets"""
        
        results = {
            'address': address,
            'found_in_datasets': [],
            'vulnerability_info': None,
            'malicious_flags': None,
            'source_code': None
        }
        
        try:
            # Search in smart contract vulnerabilities
            vuln_df = self.get_smart_contract_vulnerabilities()
            if vuln_df is not None:
                # Look for address in any column
                address_matches = vuln_df[
                    vuln_df.apply(
                        lambda row: any(str(val).lower() == address.lower() for val in row if pd.notna(val)),
                        axis=1
                    )
                ]
                
                if not address_matches.empty:
                    results['found_in_datasets'].append('smart_contract_vulnerabilities')
                    results['vulnerability_info'] = address_matches.to_dict('records')
            
            # Search in malicious contracts
            malicious_df = self.get_malicious_contracts()
            if malicious_df is not None:
                address_matches = malicious_df[
                    malicious_df.apply(
                        lambda row: any(str(val).lower() == address.lower() for val in row if pd.notna(val)),
                        axis=1
                    )
                ]
                
                if not address_matches.empty:
                    results['found_in_datasets'].append('malicious_smart_contracts')
                    results['malicious_flags'] = address_matches.to_dict('records')
            
            # Search in Solidity contracts (sample search)
            solidity_df = self.get_solidity_contracts(sample_size=5000)
            if solidity_df is not None:
                address_matches = solidity_df[
                    solidity_df.apply(
                        lambda row: any(str(val).lower() == address.lower() for val in row if pd.notna(val)),
                        axis=1
                    )
                ]
                
                if not address_matches.empty:
                    results['found_in_datasets'].append('disl_solidity_contracts')
                    results['source_code'] = address_matches.to_dict('records')
            
            if results['found_in_datasets']:
                self.logger.info(f"Address {address} found in datasets: {', '.join(results['found_in_datasets'])}")
                return results
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"Contract search failed for {address}: {e}")
            return None
    
    def get_vulnerability_statistics(self) -> Optional[Dict[str, Any]]:
        """Get statistics about vulnerability datasets"""
        
        stats = {
            'datasets_loaded': len(self.loaded_datasets),
            'vulnerability_datasets': [],
            'total_vulnerability_records': 0,
            'vulnerability_types': [],
            'severity_distribution': {}
        }
        
        try:
            # Smart contract vulnerabilities stats
            vuln_df = self.get_smart_contract_vulnerabilities()
            if vuln_df is not None:
                stats['vulnerability_datasets'].append('smart_contract_vulnerabilities')
                stats['total_vulnerability_records'] += len(vuln_df)
                
                # Extract vulnerability types and severities if available
                if 'vulnerability_type' in vuln_df.columns:
                    stats['vulnerability_types'] = vuln_df['vulnerability_type'].unique().tolist()
                
                if 'severity' in vuln_df.columns:
                    stats['severity_distribution'] = vuln_df['severity'].value_counts().to_dict()
            
            # Malicious contracts stats
            malicious_df = self.get_malicious_contracts()
            if malicious_df is not None:
                stats['vulnerability_datasets'].append('malicious_smart_contracts')
                stats['total_vulnerability_records'] += len(malicious_df)
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Statistics generation failed: {e}")
            return stats
    
    def export_for_training(self, output_dir: str) -> Dict[str, str]:
        """Export datasets for ML training"""
        
        exported_files = {}
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            # Export vulnerability data
            vuln_df = self.get_smart_contract_vulnerabilities()
            if vuln_df is not None:
                vuln_path = os.path.join(output_dir, 'smart_contract_vulnerabilities.csv')
                vuln_df.to_csv(vuln_path, index=False)
                exported_files['vulnerabilities'] = vuln_path
            
            # Export malicious contracts
            malicious_df = self.get_malicious_contracts()
            if malicious_df is not None:
                malicious_path = os.path.join(output_dir, 'malicious_contracts.csv')
                malicious_df.to_csv(malicious_path, index=False)
                exported_files['malicious_contracts'] = malicious_path
            
            # Export contract source code (sample)
            solidity_df = self.get_solidity_contracts(sample_size=1000)
            if solidity_df is not None:
                solidity_path = os.path.join(output_dir, 'solidity_contracts_sample.csv')
                solidity_df.to_csv(solidity_path, index=False)
                exported_files['solidity_contracts'] = solidity_path
            
            # Export metadata
            metadata = {
                'export_timestamp': datetime.utcnow().isoformat(),
                'datasets_exported': list(exported_files.keys()),
                'source': 'huggingface_hub',
                'statistics': self.get_vulnerability_statistics()
            }
            
            metadata_path = os.path.join(output_dir, 'dataset_metadata.json')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            exported_files['metadata'] = metadata_path
            
            self.logger.info(f"Exported {len(exported_files)} dataset files to {output_dir}")
            
            return exported_files
            
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            return exported_files
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get HuggingFace dataset manager statistics"""
        
        stats = {
            'configured': self.is_configured(),
            'datasets_library_available': DATASETS_AVAILABLE,
            'data_directory': self.data_dir,
            'auto_download_enabled': self.auto_download,
            'has_auth_token': bool(self.hf_token)
        }
        
        stats.update({
            'available_datasets': len(self.AVAILABLE_DATASETS),
            'loaded_datasets': len(self.loaded_datasets),
            'dataset_types': list(set(config['data_type'] for config in self.AVAILABLE_DATASETS.values()))
        })
        
        # Add loaded dataset details
        if self.loaded_datasets:
            stats['loaded_dataset_details'] = {
                name: {
                    'loaded_at': info['loaded_at'].isoformat(),
                    'description': info['config']['description'],
                    'data_type': info['config']['data_type']
                }
                for name, info in self.loaded_datasets.items()
            }
        
        return stats