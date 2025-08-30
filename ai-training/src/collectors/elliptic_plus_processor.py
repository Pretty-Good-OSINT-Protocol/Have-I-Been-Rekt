"""
Elliptic++ Dataset Processor - Integration with Elliptic Labs' latest open-source
blockchain investigation training data (2024).

Processes both transaction-level and actor-level (wallet address) Bitcoin data:
- 203k Bitcoin transactions with 183 features
- 822k wallet addresses with 56 features  
- Comprehensive labeling: Illicit, Licit, Unknown
- Graph network structure with temporal features
"""

import pandas as pd
import numpy as np
import os
import requests
import zipfile
import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
import logging
import pickle
import json

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin


@dataclass
class EllipticTransaction:
    """Represents a Bitcoin transaction from Elliptic++ dataset"""
    tx_id: str
    time_step: int
    features: List[float]
    label: str  # 'illicit', 'licit', 'unknown'
    confidence: float = 1.0


@dataclass 
class EllipticActor:
    """Represents a Bitcoin wallet address from Elliptic++ dataset"""
    address: str
    time_step: int
    features: List[float]
    label: str  # 'illicit', 'licit', 'unknown'
    connected_transactions: List[str] = None
    confidence: float = 1.0
    
    def __post_init__(self):
        if self.connected_transactions is None:
            self.connected_transactions = []


@dataclass
class EllipticIntelligence:
    """Comprehensive intelligence from Elliptic++ dataset"""
    query_address: str
    found_transactions: List[EllipticTransaction]
    found_actors: List[EllipticActor]
    graph_connections: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    temporal_analysis: Dict[str, Any]


class EllipticPlusProcessor(BaseDataCollector, LoggingMixin):
    """
    Processor for Elliptic++ dataset - the most comprehensive open-source
    Bitcoin investigation dataset with both transaction and actor-level labels.
    """
    
    # Dataset URLs and metadata
    DATASET_URLS = {
        'elliptic_plus': 'https://drive.google.com/uc?id=1ZPeIjCk_MjP6B6Q1YYKfCWPjG6JmhXSD',
        'backup_url': 'https://github.com/git-disl/EllipticPlusPlus/raw/main/data'
    }
    
    DATASET_FILES = {
        'transactions': {
            'features': 'txs_features.csv',
            'classes': 'txs_classes.csv', 
            'edges': 'txs_edgelist.csv'
        },
        'actors': {
            'features': 'wallets_features.csv',
            'classes': 'wallets_classes.csv',
            'edges': 'wallets_edgelist.csv'
        }
    }
    
    # Label mapping
    LABEL_MAPPING = {
        1: 'illicit',
        2: 'licit',
        3: 'unknown'
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # Configuration
        self.data_dir = config.get('elliptic_data_dir', './data/elliptic_plus')
        self.enable_auto_download = config.get('elliptic_auto_download', True)
        
        # Ensure data directory exists
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Dataset containers
        self.transactions_data = {}
        self.actors_data = {}
        self.graph_edges = {}
        
        # Load datasets if available
        self._load_datasets()
        
        self.logger.info("Elliptic++ processor initialized", 
                        transactions=len(self.transactions_data.get('features', [])),
                        actors=len(self.actors_data.get('features', [])))
    
    @property
    def source_name(self) -> str:
        return "elliptic_plus"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.ACADEMIC
    
    def is_configured(self) -> bool:
        """Check if Elliptic++ datasets are available"""
        required_files = [
            os.path.join(self.data_dir, f) 
            for dataset in self.DATASET_FILES.values()
            for f in dataset.values()
        ]
        return all(os.path.exists(f) for f in required_files)
    
    def download_datasets(self) -> bool:
        """Download Elliptic++ datasets"""
        
        if not self.enable_auto_download:
            self.logger.warning("Auto-download disabled. Please download datasets manually.")
            return False
        
        self.logger.info("Downloading Elliptic++ datasets...")
        
        try:
            # This is a placeholder - actual implementation would need
            # proper handling of Google Drive downloads or direct file access
            self.logger.info("Dataset download requires manual steps:")
            self.logger.info("1. Visit: https://github.com/git-disl/EllipticPlusPlus")
            self.logger.info("2. Download the dataset files to: " + self.data_dir)
            self.logger.info("3. Expected files:")
            
            for dataset_name, files in self.DATASET_FILES.items():
                self.logger.info(f"   {dataset_name.title()}:")
                for file_type, filename in files.items():
                    self.logger.info(f"     - {filename}")
            
            return False
            
        except Exception as e:
            self.logger.error(f"Dataset download failed: {e}")
            return False
    
    def _load_datasets(self) -> bool:
        """Load Elliptic++ datasets from CSV files"""
        
        try:
            # Load transaction data
            tx_features_path = os.path.join(self.data_dir, self.DATASET_FILES['transactions']['features'])
            tx_classes_path = os.path.join(self.data_dir, self.DATASET_FILES['transactions']['classes'])
            tx_edges_path = os.path.join(self.data_dir, self.DATASET_FILES['transactions']['edges'])
            
            if os.path.exists(tx_features_path) and os.path.exists(tx_classes_path):
                self.logger.info("Loading transaction data...")
                
                tx_features = pd.read_csv(tx_features_path)
                tx_classes = pd.read_csv(tx_classes_path)
                
                # Merge features and classes
                tx_data = pd.merge(tx_features, tx_classes, on='txId', how='left')
                
                self.transactions_data = {
                    'features': tx_data,
                    'count': len(tx_data)
                }
                
                # Load edges if available
                if os.path.exists(tx_edges_path):
                    tx_edges = pd.read_csv(tx_edges_path)
                    self.graph_edges['transactions'] = tx_edges
                
                self.logger.info(f"Loaded {len(tx_data)} transaction records")
            
            # Load actor data
            actor_features_path = os.path.join(self.data_dir, self.DATASET_FILES['actors']['features'])
            actor_classes_path = os.path.join(self.data_dir, self.DATASET_FILES['actors']['classes'])
            actor_edges_path = os.path.join(self.data_dir, self.DATASET_FILES['actors']['edges'])
            
            if os.path.exists(actor_features_path) and os.path.exists(actor_classes_path):
                self.logger.info("Loading actor data...")
                
                actor_features = pd.read_csv(actor_features_path)
                actor_classes = pd.read_csv(actor_classes_path)
                
                # Merge features and classes
                actor_data = pd.merge(actor_features, actor_classes, on='address', how='left')
                
                self.actors_data = {
                    'features': actor_data,
                    'count': len(actor_data)
                }
                
                # Load edges if available
                if os.path.exists(actor_edges_path):
                    actor_edges = pd.read_csv(actor_edges_path)
                    self.graph_edges['actors'] = actor_edges
                
                self.logger.info(f"Loaded {len(actor_data)} actor records")
            
            return bool(self.transactions_data or self.actors_data)
            
        except Exception as e:
            self.logger.error(f"Failed to load Elliptic++ datasets: {e}")
            return False
    
    def lookup_transaction(self, tx_id: str) -> Optional[EllipticTransaction]:
        """Look up specific transaction by ID"""
        
        if not self.transactions_data:
            return None
        
        try:
            tx_df = self.transactions_data['features']
            tx_record = tx_df[tx_df['txId'] == tx_id]
            
            if tx_record.empty:
                return None
            
            record = tx_record.iloc[0]
            
            # Extract features (skip txId and class columns)
            feature_cols = [col for col in tx_df.columns 
                           if col not in ['txId', 'class', 'time_step']]
            features = record[feature_cols].values.tolist()
            
            # Map class to label
            label = self.LABEL_MAPPING.get(record.get('class'), 'unknown')
            
            return EllipticTransaction(
                tx_id=tx_id,
                time_step=record.get('time_step', 0),
                features=features,
                label=label,
                confidence=1.0 if label != 'unknown' else 0.5
            )
            
        except Exception as e:
            self.logger.error(f"Transaction lookup failed for {tx_id}: {e}")
            return None
    
    def lookup_actor(self, address: str) -> Optional[EllipticActor]:
        """Look up specific actor (wallet address)"""
        
        if not self.actors_data:
            return None
        
        try:
            actor_df = self.actors_data['features'] 
            actor_record = actor_df[actor_df['address'] == address]
            
            if actor_record.empty:
                return None
            
            record = actor_record.iloc[0]
            
            # Extract features (skip address and class columns)
            feature_cols = [col for col in actor_df.columns 
                           if col not in ['address', 'class', 'time_step']]
            features = record[feature_cols].values.tolist()
            
            # Map class to label
            label = self.LABEL_MAPPING.get(record.get('class'), 'unknown')
            
            return EllipticActor(
                address=address,
                time_step=record.get('time_step', 0),
                features=features,
                label=label,
                confidence=1.0 if label != 'unknown' else 0.5
            )
            
        except Exception as e:
            self.logger.error(f"Actor lookup failed for {address}: {e}")
            return None
    
    def analyze_address_network(self, address: str, max_hops: int = 2) -> Optional[EllipticIntelligence]:
        """
        Analyze address and its network connections using graph structure
        """
        
        try:
            # Direct actor lookup
            primary_actor = self.lookup_actor(address)
            found_actors = [primary_actor] if primary_actor else []
            found_transactions = []
            
            # Graph analysis using edges
            connected_addresses = self._get_connected_addresses(address, max_hops)
            
            # Look up connected actors
            for connected_addr in connected_addresses:
                connected_actor = self.lookup_actor(connected_addr)
                if connected_actor:
                    found_actors.append(connected_actor)
            
            # Risk assessment
            risk_assessment = self._assess_network_risk(found_actors, found_transactions)
            
            # Temporal analysis
            temporal_analysis = self._analyze_temporal_patterns(found_actors, found_transactions)
            
            intelligence = EllipticIntelligence(
                query_address=address,
                found_transactions=found_transactions,
                found_actors=found_actors,
                graph_connections={'connected_addresses': connected_addresses},
                risk_assessment=risk_assessment,
                temporal_analysis=temporal_analysis
            )
            
            return intelligence
            
        except Exception as e:
            self.logger.error(f"Network analysis failed for {address}: {e}")
            return None
    
    def _get_connected_addresses(self, address: str, max_hops: int) -> List[str]:
        """Get connected addresses using graph edges"""
        
        connected = set()
        
        try:
            if 'actors' in self.graph_edges:
                edges_df = self.graph_edges['actors']
                
                # Simple 1-hop connections
                outgoing = edges_df[edges_df['source'] == address]['target'].tolist()
                incoming = edges_df[edges_df['target'] == address]['source'].tolist()
                
                connected.update(outgoing + incoming)
                
                # Multi-hop (simplified implementation)
                if max_hops > 1:
                    for hop_addr in list(connected)[:10]:  # Limit to prevent explosion
                        second_hop = edges_df[edges_df['source'] == hop_addr]['target'].tolist()
                        connected.update(second_hop[:5])  # Limit connections
            
        except Exception as e:
            self.logger.debug(f"Graph traversal error: {e}")
        
        return list(connected)[:50]  # Limit total connections
    
    def _assess_network_risk(self, actors: List[EllipticActor], 
                            transactions: List[EllipticTransaction]) -> Dict[str, Any]:
        """Assess risk based on network analysis"""
        
        illicit_count = sum(1 for actor in actors if actor.label == 'illicit')
        licit_count = sum(1 for actor in actors if actor.label == 'licit')
        unknown_count = sum(1 for actor in actors if actor.label == 'unknown')
        
        total_count = len(actors)
        
        if total_count == 0:
            return {
                'risk_score': 0.0,
                'risk_level': 'unknown',
                'confidence': 0.0,
                'illicit_connections': 0,
                'network_size': 0
            }
        
        # Risk calculation
        risk_score = 0.0
        
        if illicit_count > 0:
            # Direct illicit connections are high risk
            risk_score = 0.8 + (illicit_count / total_count) * 0.2
        elif licit_count > unknown_count:
            # Mostly legitimate connections
            risk_score = 0.1 + (unknown_count / total_count) * 0.2
        else:
            # Mostly unknown connections
            risk_score = 0.3 + (unknown_count / total_count) * 0.3
        
        # Network size factor
        if total_count > 20:
            risk_score += 0.1  # Large networks are inherently riskier
        
        risk_score = min(1.0, risk_score)
        
        # Risk level mapping
        if risk_score >= 0.8:
            risk_level = 'critical'
        elif risk_score >= 0.6:
            risk_level = 'high'
        elif risk_score >= 0.3:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        confidence = 1.0 - (unknown_count / total_count) if total_count > 0 else 0.0
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'confidence': confidence,
            'illicit_connections': illicit_count,
            'licit_connections': licit_count,
            'unknown_connections': unknown_count,
            'network_size': total_count
        }
    
    def _analyze_temporal_patterns(self, actors: List[EllipticActor], 
                                  transactions: List[EllipticTransaction]) -> Dict[str, Any]:
        """Analyze temporal patterns in the network"""
        
        if not actors:
            return {}
        
        time_steps = [actor.time_step for actor in actors if actor.time_step > 0]
        
        if not time_steps:
            return {}
        
        return {
            'time_span': max(time_steps) - min(time_steps),
            'earliest_activity': min(time_steps),
            'latest_activity': max(time_steps),
            'activity_distribution': len(set(time_steps))
        }
    
    def lookup_address(self, address: str) -> Optional[Dict[str, Any]]:
        """
        Standard lookup interface for addresses
        """
        
        intelligence = self.analyze_address_network(address)
        
        if not intelligence or not intelligence.found_actors:
            return None
        
        primary_actor = intelligence.found_actors[0]
        risk_assessment = intelligence.risk_assessment
        
        return {
            'address': address,
            'found_elliptic_data': True,
            'timestamp': datetime.utcnow().isoformat(),
            'elliptic_classification': {
                'label': primary_actor.label,
                'confidence': primary_actor.confidence,
                'features_count': len(primary_actor.features),
                'time_step': primary_actor.time_step
            },
            'network_analysis': {
                'connected_actors': len(intelligence.found_actors) - 1,
                'network_size': risk_assessment.get('network_size', 0),
                'illicit_connections': risk_assessment.get('illicit_connections', 0),
                'licit_connections': risk_assessment.get('licit_connections', 0)
            },
            'risk_assessment': risk_assessment,
            'temporal_analysis': intelligence.temporal_analysis
        }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse Elliptic++ data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_elliptic_data'):
            return risk_factors
        
        classification = raw_data.get('elliptic_classification', {})
        risk_assessment = raw_data.get('risk_assessment', {})
        network_analysis = raw_data.get('network_analysis', {})
        
        # Primary classification factor
        label = classification.get('label', 'unknown')
        confidence = classification.get('confidence', 0.0)
        
        if label == 'illicit':
            risk_level = RiskLevel.CRITICAL
            description = "Address classified as ILLICIT by Elliptic++ dataset"
        elif label == 'licit':
            risk_level = RiskLevel.LOW
            description = "Address classified as LICIT by Elliptic++ dataset"
        else:
            risk_level = RiskLevel.MEDIUM
            description = "Address classification UNKNOWN in Elliptic++ dataset"
        
        risk_factors.append(RiskFactor(
            type="elliptic_plus_classification",
            description=description,
            risk_level=risk_level,
            confidence=confidence,
            source=DataSourceType.ACADEMIC,
            raw_data={
                'elliptic_label': label,
                'features_count': classification.get('features_count', 0),
                'time_step': classification.get('time_step', 0)
            }
        ))
        
        # Network analysis factors
        illicit_connections = network_analysis.get('illicit_connections', 0)
        if illicit_connections > 0:
            risk_factors.append(RiskFactor(
                type="illicit_network_connections",
                description=f"Connected to {illicit_connections} known illicit addresses",
                risk_level=RiskLevel.HIGH,
                confidence=0.9,
                source=DataSourceType.ACADEMIC,
                raw_data={'illicit_connection_count': illicit_connections}
            ))
        
        # Large network factor
        network_size = network_analysis.get('network_size', 0)
        if network_size > 10:
            risk_factors.append(RiskFactor(
                type="large_transaction_network",
                description=f"Part of large transaction network ({network_size} connected addresses)",
                risk_level=RiskLevel.MEDIUM if network_size < 50 else RiskLevel.HIGH,
                confidence=0.7,
                source=DataSourceType.ACADEMIC,
                raw_data={'network_size': network_size}
            ))
        
        return risk_factors
    
    def get_training_data(self, include_unknown: bool = False) -> Dict[str, Any]:
        """
        Extract training data for ML models
        """
        
        training_data = {
            'transactions': [],
            'actors': [],
            'metadata': {
                'dataset_source': 'elliptic_plus',
                'total_transactions': 0,
                'total_actors': 0,
                'illicit_transactions': 0,
                'illicit_actors': 0,
                'feature_count_tx': 0,
                'feature_count_actor': 0
            }
        }
        
        try:
            # Process transaction data
            if self.transactions_data:
                tx_df = self.transactions_data['features']
                
                # Filter based on labels
                if include_unknown:
                    filtered_tx = tx_df
                else:
                    filtered_tx = tx_df[tx_df['class'].isin([1, 2])]  # Only illicit and licit
                
                training_data['transactions'] = []
                illicit_count = 0
                
                for _, row in filtered_tx.iterrows():
                    label = self.LABEL_MAPPING.get(row['class'], 'unknown')
                    if label == 'illicit':
                        illicit_count += 1
                    
                    # Extract features
                    feature_cols = [col for col in tx_df.columns 
                                   if col not in ['txId', 'class', 'time_step']]
                    features = row[feature_cols].values.tolist()
                    
                    training_data['transactions'].append({
                        'id': row['txId'],
                        'features': features,
                        'label': label,
                        'time_step': row.get('time_step', 0)
                    })
                
                training_data['metadata']['total_transactions'] = len(training_data['transactions'])
                training_data['metadata']['illicit_transactions'] = illicit_count
                training_data['metadata']['feature_count_tx'] = len(feature_cols)
            
            # Process actor data
            if self.actors_data:
                actor_df = self.actors_data['features']
                
                # Filter based on labels
                if include_unknown:
                    filtered_actors = actor_df
                else:
                    filtered_actors = actor_df[actor_df['class'].isin([1, 2])]  # Only illicit and licit
                
                training_data['actors'] = []
                illicit_count = 0
                
                for _, row in filtered_actors.iterrows():
                    label = self.LABEL_MAPPING.get(row['class'], 'unknown')
                    if label == 'illicit':
                        illicit_count += 1
                    
                    # Extract features
                    feature_cols = [col for col in actor_df.columns 
                                   if col not in ['address', 'class', 'time_step']]
                    features = row[feature_cols].values.tolist()
                    
                    training_data['actors'].append({
                        'address': row['address'],
                        'features': features,
                        'label': label,
                        'time_step': row.get('time_step', 0)
                    })
                
                training_data['metadata']['total_actors'] = len(training_data['actors'])
                training_data['metadata']['illicit_actors'] = illicit_count
                training_data['metadata']['feature_count_actor'] = len(feature_cols)
            
            self.logger.info("Training data extracted",
                           transactions=training_data['metadata']['total_transactions'],
                           actors=training_data['metadata']['total_actors'])
            
            return training_data
            
        except Exception as e:
            self.logger.error(f"Training data extraction failed: {e}")
            return training_data
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get Elliptic++ processor statistics"""
        
        stats = {
            'configured': self.is_configured(),
            'datasets_loaded': bool(self.transactions_data or self.actors_data),
            'data_directory': self.data_dir,
            'auto_download_enabled': self.enable_auto_download
        }
        
        if self.transactions_data:
            stats.update({
                'transaction_count': self.transactions_data['count'],
                'transaction_features': len(self.transactions_data['features'].columns) - 3  # Exclude ID, class, time_step
            })
        
        if self.actors_data:
            stats.update({
                'actor_count': self.actors_data['count'],
                'actor_features': len(self.actors_data['features'].columns) - 3  # Exclude address, class, time_step
            })
        
        if self.graph_edges:
            stats['graph_edges'] = {k: len(v) for k, v in self.graph_edges.items()}
        
        return stats