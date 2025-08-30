"""
Elliptic Dataset Processor - processes Elliptic Bitcoin dataset for ML training.

Handles:
- Elliptic Bitcoin Transaction Dataset (203k+ labeled transactions)
- Elliptic++ Dataset (822k addresses with ground truth labels)
- Feature extraction for machine learning models
- Training/validation dataset preparation
- Ground truth label processing (licit/illicit classification)
"""

from typing import Dict, List, Optional, Any, Set, Tuple, Union
from datetime import datetime, timezone
from dataclasses import dataclass
import pandas as pd
import numpy as np
import json
import pickle
import os
from pathlib import Path
from decimal import Decimal
import logging

from ..data_collector import BaseDataCollector
from ..utils.logging import get_logger


@dataclass
class EllipticTransaction:
    """Elliptic transaction record with features"""
    
    transaction_id: str
    time_step: int
    address_features: List[float]  # Node features (166 dimensions)
    edge_features: Dict[str, List[float]]  # Edge features to other transactions
    label: Optional[str]  # 'licit', 'illicit', or None (unknown)
    label_confidence: float
    metadata: Dict[str, Any]


@dataclass 
class EllipticAddress:
    """Elliptic++ address record"""
    
    address: str
    label: str  # 'licit' or 'illicit'
    confidence: float
    transaction_count: int
    total_btc_received: Decimal
    total_btc_sent: Decimal
    first_seen_block: int
    last_seen_block: int
    address_type: str  # e.g., 'exchange', 'mixing', 'gambling', etc.
    risk_category: str
    source_attribution: str


@dataclass
class MLTrainingData:
    """Prepared ML training data"""
    
    X_train: np.ndarray
    X_val: np.ndarray
    X_test: np.ndarray
    y_train: np.ndarray
    y_val: np.ndarray
    y_test: np.ndarray
    feature_names: List[str]
    label_mapping: Dict[str, int]
    metadata: Dict[str, Any]


@dataclass
class EllipticIntelligence:
    """Intelligence report from Elliptic data"""
    
    address: str
    transaction_id: Optional[str]
    is_labeled: bool
    label: Optional[str]
    confidence: float
    risk_assessment: Dict[str, Any]
    feature_vector: Optional[np.ndarray]
    related_entities: List[str]
    analysis_timestamp: datetime


class EllipticDatasetProcessor(BaseDataCollector):
    """
    Elliptic dataset processor for Bitcoin transaction analysis.
    
    Processes the academic Elliptic dataset to:
    - Extract ground truth labels for ML training
    - Prepare feature vectors for classification models
    - Provide transaction risk assessment
    - Generate training/validation splits
    """
    
    # Elliptic dataset URLs (academic research)
    ELLIPTIC_DATASET_URL = "https://www.elliptic.co/hubfs/Elliptic%20Data%20Set.zip"
    ELLIPTIC_PLUS_URL = "https://github.com/elliptic-dataset/elliptic_plus"
    
    # Label mappings
    LABEL_MAPPING = {
        'licit': 0,
        'illicit': 1,
        'unknown': -1
    }
    
    # Risk categories from Elliptic classification
    RISK_CATEGORIES = {
        'exchange': 'licit',
        'gambling': 'semi_licit',
        'mixing': 'illicit',
        'darknet_market': 'illicit',
        'ransomware': 'illicit',
        'scam': 'illicit',
        'stolen_coins': 'illicit',
        'mining_pool': 'licit'
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: str):
        super().__init__(config, cache_dir, "elliptic_processor")
        
        self.logger = get_logger(f"{__name__}.EllipticDatasetProcessor")
        
        # Load configuration
        crime_config = config.get('historical_crime_data', {})
        elliptic_config = crime_config.get('elliptic', {})
        
        self.dataset_path = elliptic_config.get('dataset_path', 'data/elliptic/')
        self.auto_download = elliptic_config.get('auto_download', False)
        self.train_split = elliptic_config.get('train_split', 0.7)
        self.val_split = elliptic_config.get('validation_split', 0.15)
        self.test_split = elliptic_config.get('test_split', 0.15)
        self.min_confidence = elliptic_config.get('min_confidence', 0.8)
        
        # Feature configuration
        self.use_node_features = elliptic_config.get('use_node_features', True)
        self.use_edge_features = elliptic_config.get('use_edge_features', False)
        self.feature_scaling = elliptic_config.get('feature_scaling', 'standard')
        
        # Create data directory
        os.makedirs(self.dataset_path, exist_ok=True)
        
        # In-memory datasets
        self.transactions = {}  # transaction_id -> EllipticTransaction
        self.addresses = {}     # address -> EllipticAddress
        self.ml_data = None     # Prepared ML training data
        
        # Feature extraction
        self.feature_extractors = {}
        
        # Initialize dataset
        self._initialize_dataset()
        
        self.logger.info(f"Initialized Elliptic Processor ({len(self.transactions)} transactions, {len(self.addresses)} addresses)")
    
    def _initialize_dataset(self):
        """Initialize Elliptic datasets"""
        
        try:
            # Check for existing processed data
            processed_file = Path(self.dataset_path) / 'processed_elliptic.pkl'
            
            if processed_file.exists():
                self.logger.info("Loading processed Elliptic dataset")
                self._load_processed_dataset(str(processed_file))
            else:
                # Load raw dataset files
                self._load_raw_dataset()
            
        except Exception as e:
            self.logger.error(f"Error initializing Elliptic dataset: {e}")
    
    def _load_processed_dataset(self, file_path: str):
        """Load pre-processed dataset"""
        
        try:
            with open(file_path, 'rb') as f:
                data = pickle.load(f)
            
            self.transactions = data.get('transactions', {})
            self.addresses = data.get('addresses', {})
            self.ml_data = data.get('ml_data')
            
            self.logger.info(f"Loaded processed dataset: {len(self.transactions)} transactions")
            
        except Exception as e:
            self.logger.error(f"Error loading processed dataset: {e}")
    
    def _load_raw_dataset(self):
        """Load and process raw Elliptic dataset files"""
        
        dataset_dir = Path(self.dataset_path)
        
        # Look for standard Elliptic dataset files
        files = {
            'classes': dataset_dir / 'elliptic_txs_classes.csv',
            'features': dataset_dir / 'elliptic_txs_features.csv',
            'edges': dataset_dir / 'elliptic_txs_edgelist.csv',
            'addresses': dataset_dir / 'elliptic_plus_addresses.csv'
        }
        
        # Check if files exist
        missing_files = [name for name, path in files.items() if not path.exists()]
        
        if missing_files:
            self.logger.warning(f"Missing dataset files: {missing_files}")
            if self.auto_download:
                self._download_dataset()
            else:
                self.logger.info("Dataset files not found and auto_download disabled")
                return
        
        try:
            # Load transaction classes (labels)
            if files['classes'].exists():
                self._load_transaction_classes(str(files['classes']))
            
            # Load transaction features
            if files['features'].exists():
                self._load_transaction_features(str(files['features']))
            
            # Load transaction edges
            if files['edges'].exists():
                self._load_transaction_edges(str(files['edges']))
            
            # Load Elliptic++ addresses
            if files['addresses'].exists():
                self._load_elliptic_plus_addresses(str(files['addresses']))
            
            # Prepare ML training data
            if self.transactions:
                self._prepare_ml_data()
            
            # Save processed data
            self._save_processed_dataset()
            
        except Exception as e:
            self.logger.error(f"Error loading raw dataset: {e}")
    
    def _download_dataset(self):
        """Download Elliptic dataset (placeholder)"""
        
        self.logger.info("Dataset auto-download not implemented - please download manually")
        self.logger.info("Available at: https://www.elliptic.co/discovery/elliptic-data-set")
    
    def _load_transaction_classes(self, file_path: str):
        """Load transaction classification labels"""
        
        try:
            df = pd.read_csv(file_path)
            
            for _, row in df.iterrows():
                tx_id = str(row['txId'])
                label = str(row['class']) if pd.notna(row['class']) else None
                
                # Convert numeric labels to string labels
                if label == '1':
                    label = 'illicit'
                elif label == '2':
                    label = 'licit'
                elif label in ['unknown', 'unlabeled', '3']:
                    label = None
                
                # Update or create transaction record
                if tx_id in self.transactions:
                    self.transactions[tx_id].label = label
                    self.transactions[tx_id].label_confidence = 1.0  # Ground truth
                else:
                    # Create minimal transaction record
                    self.transactions[tx_id] = EllipticTransaction(
                        transaction_id=tx_id,
                        time_step=0,  # Will be updated from features
                        address_features=[],
                        edge_features={},
                        label=label,
                        label_confidence=1.0,
                        metadata={}
                    )
            
            self.logger.info(f"Loaded transaction classes: {len(df)} records")
            
        except Exception as e:
            self.logger.error(f"Error loading transaction classes: {e}")
    
    def _load_transaction_features(self, file_path: str):
        """Load transaction node features"""
        
        try:
            df = pd.read_csv(file_path)
            
            for _, row in df.iterrows():
                tx_id = str(row['txId'])
                time_step = int(row['1'])  # Second column is time step
                
                # Extract feature vector (columns 2-167 are features)
                feature_cols = [str(i) for i in range(2, 167)]
                features = [float(row[col]) if pd.notna(row[col]) else 0.0 
                           for col in feature_cols if col in row.index]
                
                # Update or create transaction record
                if tx_id in self.transactions:
                    self.transactions[tx_id].time_step = time_step
                    self.transactions[tx_id].address_features = features
                else:
                    self.transactions[tx_id] = EllipticTransaction(
                        transaction_id=tx_id,
                        time_step=time_step,
                        address_features=features,
                        edge_features={},
                        label=None,
                        label_confidence=0.0,
                        metadata={}
                    )
            
            self.logger.info(f"Loaded transaction features: {len(df)} records")
            
        except Exception as e:
            self.logger.error(f"Error loading transaction features: {e}")
    
    def _load_transaction_edges(self, file_path: str):
        """Load transaction edge information"""
        
        try:
            df = pd.read_csv(file_path)
            
            # Build edge features for each transaction
            edge_features = {}
            
            for _, row in df.iterrows():
                tx_from = str(row['txId1'])
                tx_to = str(row['txId2'])
                
                # Add edge information
                if tx_from not in edge_features:
                    edge_features[tx_from] = {'outgoing': [], 'incoming': []}
                if tx_to not in edge_features:
                    edge_features[tx_to] = {'outgoing': [], 'incoming': []}
                
                edge_features[tx_from]['outgoing'].append(tx_to)
                edge_features[tx_to]['incoming'].append(tx_from)
            
            # Update transaction records with edge features
            for tx_id, edges in edge_features.items():
                if tx_id in self.transactions:
                    self.transactions[tx_id].edge_features = edges
            
            self.logger.info(f"Loaded transaction edges: {len(df)} edges")
            
        except Exception as e:
            self.logger.error(f"Error loading transaction edges: {e}")
    
    def _load_elliptic_plus_addresses(self, file_path: str):
        """Load Elliptic++ address dataset"""
        
        try:
            df = pd.read_csv(file_path)
            
            for _, row in df.iterrows():
                address = str(row['address'])
                label = str(row['label']).lower()
                
                # Parse additional fields if available
                confidence = float(row.get('confidence', 1.0))
                tx_count = int(row.get('tx_count', 0))
                btc_received = Decimal(str(row.get('btc_received', 0)))
                btc_sent = Decimal(str(row.get('btc_sent', 0)))
                
                elliptic_address = EllipticAddress(
                    address=address,
                    label=label,
                    confidence=confidence,
                    transaction_count=tx_count,
                    total_btc_received=btc_received,
                    total_btc_sent=btc_sent,
                    first_seen_block=int(row.get('first_block', 0)),
                    last_seen_block=int(row.get('last_block', 0)),
                    address_type=str(row.get('type', 'unknown')),
                    risk_category=self._map_risk_category(str(row.get('category', 'unknown'))),
                    source_attribution=str(row.get('source', 'elliptic'))
                )
                
                self.addresses[address] = elliptic_address
            
            self.logger.info(f"Loaded Elliptic++ addresses: {len(df)} records")
            
        except Exception as e:
            self.logger.error(f"Error loading Elliptic++ addresses: {e}")
    
    def _map_risk_category(self, category: str) -> str:
        """Map category to risk level"""
        
        category_lower = category.lower()
        return self.RISK_CATEGORIES.get(category_lower, 'unknown')
    
    def _prepare_ml_data(self):
        """Prepare data for machine learning training"""
        
        try:
            # Filter transactions with labels and features
            labeled_transactions = [
                tx for tx in self.transactions.values()
                if tx.label is not None and len(tx.address_features) > 0
            ]
            
            if not labeled_transactions:
                self.logger.warning("No labeled transactions with features found")
                return
            
            # Prepare feature matrix and labels
            X = []
            y = []
            feature_names = [f"feature_{i}" for i in range(len(labeled_transactions[0].address_features))]
            
            for tx in labeled_transactions:
                X.append(tx.address_features)
                y.append(self.LABEL_MAPPING.get(tx.label, -1))
            
            X = np.array(X)
            y = np.array(y)
            
            # Remove unknown labels
            known_mask = y != -1
            X = X[known_mask]
            y = y[known_mask]
            
            # Train/validation/test split
            n_samples = len(X)
            train_end = int(n_samples * self.train_split)
            val_end = int(n_samples * (self.train_split + self.val_split))
            
            # Shuffle data
            indices = np.random.permutation(n_samples)
            X_shuffled = X[indices]
            y_shuffled = y[indices]
            
            # Split
            X_train = X_shuffled[:train_end]
            X_val = X_shuffled[train_end:val_end]
            X_test = X_shuffled[val_end:]
            
            y_train = y_shuffled[:train_end]
            y_val = y_shuffled[train_end:val_end]
            y_test = y_shuffled[val_end:]
            
            # Feature scaling
            if self.feature_scaling == 'standard':
                from sklearn.preprocessing import StandardScaler
                scaler = StandardScaler()
                X_train = scaler.fit_transform(X_train)
                X_val = scaler.transform(X_val)
                X_test = scaler.transform(X_test)
            
            # Create ML training data object
            self.ml_data = MLTrainingData(
                X_train=X_train,
                X_val=X_val,
                X_test=X_test,
                y_train=y_train,
                y_val=y_val,
                y_test=y_test,
                feature_names=feature_names,
                label_mapping={v: k for k, v in self.LABEL_MAPPING.items() if k != 'unknown'},
                metadata={
                    'total_samples': n_samples,
                    'train_samples': len(X_train),
                    'val_samples': len(X_val),
                    'test_samples': len(X_test),
                    'feature_count': len(feature_names),
                    'class_distribution': {
                        'licit': int(np.sum(y == 0)),
                        'illicit': int(np.sum(y == 1))
                    },
                    'feature_scaling': self.feature_scaling
                }
            )
            
            self.logger.info(f"Prepared ML data: {n_samples} samples, {len(feature_names)} features")
            self.logger.info(f"Class distribution - Licit: {np.sum(y == 0)}, Illicit: {np.sum(y == 1)}")
            
        except Exception as e:
            self.logger.error(f"Error preparing ML data: {e}")
    
    def _save_processed_dataset(self):
        """Save processed dataset to disk"""
        
        try:
            processed_file = Path(self.dataset_path) / 'processed_elliptic.pkl'
            
            data = {
                'transactions': self.transactions,
                'addresses': self.addresses,
                'ml_data': self.ml_data,
                'metadata': {
                    'processed_timestamp': datetime.now(timezone.utc).isoformat(),
                    'transaction_count': len(self.transactions),
                    'address_count': len(self.addresses),
                    'labeled_transaction_count': sum(1 for tx in self.transactions.values() if tx.label),
                    'processor_config': {
                        'train_split': self.train_split,
                        'val_split': self.val_split,
                        'test_split': self.test_split,
                        'feature_scaling': self.feature_scaling
                    }
                }
            }
            
            with open(processed_file, 'wb') as f:
                pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
            
            self.logger.info(f"Saved processed dataset to {processed_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving processed dataset: {e}")
    
    def lookup_transaction(self, transaction_id: str) -> Optional[EllipticIntelligence]:
        """
        Lookup transaction in Elliptic dataset.
        
        Args:
            transaction_id: Bitcoin transaction ID
            
        Returns:
            EllipticIntelligence if transaction is in dataset
        """
        
        transaction_data = self.transactions.get(transaction_id)
        
        if not transaction_data:
            return None
        
        # Build intelligence report
        is_labeled = transaction_data.label is not None
        
        # Risk assessment
        risk_assessment = self._assess_transaction_risk(transaction_data)
        
        # Find related entities
        related_entities = []
        if transaction_data.edge_features:
            related_entities.extend(transaction_data.edge_features.get('incoming', [])[:5])
            related_entities.extend(transaction_data.edge_features.get('outgoing', [])[:5])
        
        intelligence = EllipticIntelligence(
            address='',  # Transaction-based, not address-based
            transaction_id=transaction_id,
            is_labeled=is_labeled,
            label=transaction_data.label,
            confidence=transaction_data.label_confidence,
            risk_assessment=risk_assessment,
            feature_vector=np.array(transaction_data.address_features) if transaction_data.address_features else None,
            related_entities=related_entities[:10],  # Top 10 related
            analysis_timestamp=datetime.now(timezone.utc)
        )
        
        return intelligence
    
    def lookup_address(self, address: str) -> Optional[EllipticIntelligence]:
        """
        Lookup address in Elliptic++ dataset.
        
        Args:
            address: Bitcoin address
            
        Returns:
            EllipticIntelligence if address is in dataset
        """
        
        address_data = self.addresses.get(address)
        
        if not address_data:
            return None
        
        # Build intelligence report
        risk_assessment = self._assess_address_risk(address_data)
        
        intelligence = EllipticIntelligence(
            address=address,
            transaction_id=None,
            is_labeled=True,
            label=address_data.label,
            confidence=address_data.confidence,
            risk_assessment=risk_assessment,
            feature_vector=None,
            related_entities=[],  # Would need graph analysis
            analysis_timestamp=datetime.now(timezone.utc)
        )
        
        return intelligence
    
    def _assess_transaction_risk(self, transaction_data: EllipticTransaction) -> Dict[str, Any]:
        """Assess risk for a transaction"""
        
        if transaction_data.label == 'illicit':
            risk_level = 'critical'
            risk_score = 0.95
        elif transaction_data.label == 'licit':
            risk_level = 'low'
            risk_score = 0.1
        else:
            risk_level = 'unknown'
            risk_score = 0.5
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'label': transaction_data.label,
            'confidence': transaction_data.label_confidence,
            'time_step': transaction_data.time_step,
            'feature_availability': len(transaction_data.address_features) > 0,
            'connected_transactions': len(transaction_data.edge_features.get('incoming', [])) + len(transaction_data.edge_features.get('outgoing', []))
        }
    
    def _assess_address_risk(self, address_data: EllipticAddress) -> Dict[str, Any]:
        """Assess risk for an address"""
        
        if address_data.label == 'illicit':
            risk_level = 'critical'
            risk_score = 0.9
        else:
            risk_level = 'low'
            risk_score = 0.2
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'label': address_data.label,
            'confidence': address_data.confidence,
            'address_type': address_data.address_type,
            'risk_category': address_data.risk_category,
            'transaction_volume': {
                'tx_count': address_data.transaction_count,
                'btc_received': str(address_data.total_btc_received),
                'btc_sent': str(address_data.total_btc_sent)
            },
            'activity_period': {
                'first_block': address_data.first_seen_block,
                'last_block': address_data.last_seen_block
            }
        }
    
    def get_ml_training_data(self) -> Optional[MLTrainingData]:
        """Get prepared ML training data"""
        
        if self.ml_data is None:
            self.logger.warning("ML training data not prepared - run _prepare_ml_data() first")
            self._prepare_ml_data()
        
        return self.ml_data
    
    def export_training_data(self, export_path: str, format: str = 'numpy') -> bool:
        """Export training data in specified format"""
        
        if self.ml_data is None:
            self.logger.error("No ML training data available for export")
            return False
        
        try:
            export_dir = Path(export_path)
            export_dir.mkdir(parents=True, exist_ok=True)
            
            if format == 'numpy':
                # Save as numpy arrays
                np.save(export_dir / 'X_train.npy', self.ml_data.X_train)
                np.save(export_dir / 'X_val.npy', self.ml_data.X_val)
                np.save(export_dir / 'X_test.npy', self.ml_data.X_test)
                np.save(export_dir / 'y_train.npy', self.ml_data.y_train)
                np.save(export_dir / 'y_val.npy', self.ml_data.y_val)
                np.save(export_dir / 'y_test.npy', self.ml_data.y_test)
                
                # Save metadata
                with open(export_dir / 'metadata.json', 'w') as f:
                    json.dump(self.ml_data.metadata, f, indent=2)
                
                with open(export_dir / 'feature_names.json', 'w') as f:
                    json.dump(self.ml_data.feature_names, f, indent=2)
            
            elif format == 'csv':
                # Save as CSV files
                train_df = pd.DataFrame(self.ml_data.X_train, columns=self.ml_data.feature_names)
                train_df['label'] = self.ml_data.y_train
                train_df.to_csv(export_dir / 'train.csv', index=False)
                
                val_df = pd.DataFrame(self.ml_data.X_val, columns=self.ml_data.feature_names)
                val_df['label'] = self.ml_data.y_val
                val_df.to_csv(export_dir / 'validation.csv', index=False)
                
                test_df = pd.DataFrame(self.ml_data.X_test, columns=self.ml_data.feature_names)
                test_df['label'] = self.ml_data.y_test
                test_df.to_csv(export_dir / 'test.csv', index=False)
            
            self.logger.info(f"Training data exported to {export_dir} in {format} format")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting training data: {e}")
            return False
    
    def lookup_address(self, address: str) -> Dict[str, Any]:
        """
        Main interface for Elliptic analysis.
        
        Args:
            address: Bitcoin address or transaction ID to analyze
            
        Returns:
            Dictionary containing Elliptic analysis results
        """
        
        try:
            self.logger.info(f"Analyzing with Elliptic data: {address[:10]}...")
            
            # Try as address first
            intelligence = self.lookup_address(address)
            
            # If not found as address, try as transaction
            if not intelligence:
                intelligence = self.lookup_transaction(address)
            
            if not intelligence:
                return {
                    'found_elliptic_data': False,
                    'is_labeled': False
                }
            
            # Build result dictionary
            result = {
                'found_elliptic_data': True,
                'is_labeled': intelligence.is_labeled,
                'label': intelligence.label,
                'confidence': intelligence.confidence,
                'risk_assessment': intelligence.risk_assessment,
                'data_type': 'address' if intelligence.address else 'transaction',
                'feature_vector_available': intelligence.feature_vector is not None,
                'related_entities_count': len(intelligence.related_entities),
                'analysis_timestamp': intelligence.analysis_timestamp.isoformat()
            }
            
            self.logger.info(f"Elliptic analysis completed: {address[:10]}... (label: {intelligence.label})")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in Elliptic analysis for {address}: {e}")
            return {
                'found_elliptic_data': False,
                'error': str(e)
            }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List:
        """Parse Elliptic data into risk factors for ML training"""
        
        # Import here to avoid circular imports
        from ..data_collector import RiskFactor, RiskLevel, DataSourceType
        
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_elliptic_data'):
            return risk_factors
        
        if raw_data.get('is_labeled'):
            label = raw_data.get('label')
            confidence = raw_data.get('confidence', 0.8)
            risk_assessment = raw_data.get('risk_assessment', {})
            
            if label == 'illicit':
                risk_factors.append(RiskFactor(
                    type="elliptic_illicit_label",
                    description="Labeled as illicit in Elliptic dataset",
                    risk_level=RiskLevel.CRITICAL,
                    confidence=confidence,
                    source=DataSourceType.ACADEMIC_DATASET,
                    raw_data={'elliptic_label': label, 'risk_assessment': risk_assessment}
                ))
            elif label == 'licit':
                risk_factors.append(RiskFactor(
                    type="elliptic_licit_label",
                    description="Labeled as licit in Elliptic dataset",
                    risk_level=RiskLevel.LOW,
                    confidence=confidence,
                    source=DataSourceType.ACADEMIC_DATASET,
                    raw_data={'elliptic_label': label, 'risk_assessment': risk_assessment}
                ))
        
        return risk_factors
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get Elliptic processor statistics"""
        
        stats = {
            'total_transactions': len(self.transactions),
            'total_addresses': len(self.addresses),
            'labeled_transactions': sum(1 for tx in self.transactions.values() if tx.label),
            'dataset_path': self.dataset_path,
            'ml_data_available': self.ml_data is not None
        }
        
        if self.ml_data:
            stats['ml_data_stats'] = self.ml_data.metadata
        
        # Label distribution for transactions
        tx_labels = {}
        for tx in self.transactions.values():
            label = tx.label or 'unlabeled'
            tx_labels[label] = tx_labels.get(label, 0) + 1
        stats['transaction_label_distribution'] = tx_labels
        
        # Label distribution for addresses
        addr_labels = {}
        for addr in self.addresses.values():
            label = addr.label or 'unlabeled'
            addr_labels[label] = addr_labels.get(label, 0) + 1
        stats['address_label_distribution'] = addr_labels
        
        return stats