"""
Elliptic2 Dataset Processor - Integration with Elliptic's advanced subgraph
money laundering detection dataset (2024).

Focuses on subgraph representation learning for money laundering pattern detection:
- Subgraph-level money laundering classification
- Advanced graph neural network compatibility
- MIT-IBM Watson AI Lab research integration
- Enhanced blockchain forensic capabilities
"""

import pandas as pd
import numpy as np
import os
import requests
import json
import networkx as nx
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field
import logging
import pickle

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin


@dataclass
class SubgraphPattern:
    """Represents a money laundering subgraph pattern"""
    subgraph_id: str
    nodes: List[str]
    edges: List[Tuple[str, str]]
    label: str  # 'money_laundering', 'legitimate', 'unknown'
    confidence: float
    pattern_type: str  # 'layering', 'placement', 'integration', etc.
    features: Dict[str, float] = field(default_factory=dict)
    temporal_span: int = 0


@dataclass
class MoneyLaunderingIntelligence:
    """Comprehensive money laundering intelligence from Elliptic2"""
    query_address: str
    detected_patterns: List[SubgraphPattern]
    risk_classification: str
    ml_features: Dict[str, float]
    graph_analysis: Dict[str, Any]
    temporal_analysis: Dict[str, Any]


class Elliptic2Processor(BaseDataCollector, LoggingMixin):
    """
    Processor for Elliptic2 dataset - specialized for money laundering
    subgraph detection and pattern analysis.
    """
    
    # Dataset configuration
    DATASET_URL = "http://elliptic.co/elliptic2"
    
    DATASET_FILES = {
        'nodes': 'nodes.csv',
        'edges': 'edges.csv',
        'background_nodes': 'background_nodes.csv',
        'background_edges': 'background_edges.csv',
        'connected_components': 'connected_components.csv'
    }
    
    # Money laundering pattern types
    ML_PATTERN_TYPES = {
        'layering': 'Complex transaction chains to obscure money trail',
        'placement': 'Initial injection of illicit funds into system',
        'integration': 'Reintroduction of cleaned funds into legitimate economy',
        'structuring': 'Breaking large amounts into smaller transactions',
        'smurfing': 'Multiple small transactions across different accounts',
        'mixing': 'Combining illicit and legitimate funds'
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # Configuration
        self.data_dir = config.get('elliptic2_data_dir', './data/elliptic2')
        self.enable_auto_download = config.get('elliptic2_auto_download', True)
        
        # Analysis parameters
        self.max_subgraph_size = config.get('max_subgraph_size', 50)
        self.min_pattern_confidence = config.get('min_pattern_confidence', 0.7)
        
        # Ensure data directory exists
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Dataset containers
        self.nodes_data = None
        self.edges_data = None
        self.background_nodes = None
        self.background_edges = None
        self.connected_components = None
        
        # Graph representation
        self.transaction_graph = None
        
        # Load datasets if available
        self._load_datasets()
        
        self.logger.info("Elliptic2 processor initialized",
                        nodes=len(self.nodes_data) if self.nodes_data is not None else 0,
                        edges=len(self.edges_data) if self.edges_data is not None else 0)
    
    @property
    def source_name(self) -> str:
        return "elliptic2"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.ACADEMIC
    
    def is_configured(self) -> bool:
        """Check if Elliptic2 datasets are available"""
        required_files = [
            os.path.join(self.data_dir, filename) 
            for filename in self.DATASET_FILES.values()
        ]
        return all(os.path.exists(f) for f in required_files)
    
    def download_datasets(self) -> bool:
        """Download Elliptic2 datasets"""
        
        if not self.enable_auto_download:
            self.logger.warning("Auto-download disabled. Please download datasets manually.")
            return False
        
        self.logger.info("Elliptic2 dataset download instructions:")
        self.logger.info("1. Visit: http://elliptic.co/elliptic2")
        self.logger.info("2. Download the dataset files to: " + self.data_dir)
        self.logger.info("3. Required files:")
        
        for file_type, filename in self.DATASET_FILES.items():
            self.logger.info(f"   - {filename}")
        
        return False
    
    def _load_datasets(self) -> bool:
        """Load Elliptic2 datasets from CSV files"""
        
        try:
            # Load main nodes and edges
            nodes_path = os.path.join(self.data_dir, self.DATASET_FILES['nodes'])
            edges_path = os.path.join(self.data_dir, self.DATASET_FILES['edges'])
            
            if os.path.exists(nodes_path) and os.path.exists(edges_path):
                self.logger.info("Loading Elliptic2 core datasets...")
                
                self.nodes_data = pd.read_csv(nodes_path)
                self.edges_data = pd.read_csv(edges_path)
                
                # Build graph representation
                self._build_transaction_graph()
                
                self.logger.info(f"Loaded {len(self.nodes_data)} nodes and {len(self.edges_data)} edges")
            
            # Load background data
            bg_nodes_path = os.path.join(self.data_dir, self.DATASET_FILES['background_nodes'])
            bg_edges_path = os.path.join(self.data_dir, self.DATASET_FILES['background_edges'])
            
            if os.path.exists(bg_nodes_path) and os.path.exists(bg_edges_path):
                self.background_nodes = pd.read_csv(bg_nodes_path)
                self.background_edges = pd.read_csv(bg_edges_path)
                
                self.logger.info(f"Loaded background context: {len(self.background_nodes)} nodes, {len(self.background_edges)} edges")
            
            # Load connected components
            components_path = os.path.join(self.data_dir, self.DATASET_FILES['connected_components'])
            if os.path.exists(components_path):
                self.connected_components = pd.read_csv(components_path)
                self.logger.info(f"Loaded {len(self.connected_components)} connected components")
            
            return self.nodes_data is not None
            
        except Exception as e:
            self.logger.error(f"Failed to load Elliptic2 datasets: {e}")
            return False
    
    def _build_transaction_graph(self):
        """Build NetworkX graph from transaction data"""
        
        if self.nodes_data is None or self.edges_data is None:
            return
        
        try:
            self.transaction_graph = nx.DiGraph()
            
            # Add nodes with attributes
            for _, node_row in self.nodes_data.iterrows():
                node_attrs = {col: node_row[col] for col in self.nodes_data.columns 
                             if col != 'node_id'}
                self.transaction_graph.add_node(node_row['node_id'], **node_attrs)
            
            # Add edges
            for _, edge_row in self.edges_data.iterrows():
                self.transaction_graph.add_edge(
                    edge_row['source'], 
                    edge_row['target'],
                    weight=edge_row.get('weight', 1.0)
                )
            
            self.logger.info(f"Built transaction graph: {self.transaction_graph.number_of_nodes()} nodes, {self.transaction_graph.number_of_edges()} edges")
            
        except Exception as e:
            self.logger.error(f"Graph construction failed: {e}")
            self.transaction_graph = None
    
    def detect_ml_patterns(self, address: str, max_depth: int = 3) -> List[SubgraphPattern]:
        """
        Detect money laundering patterns around a given address
        """
        
        if not self.transaction_graph or address not in self.transaction_graph:
            return []
        
        patterns = []
        
        try:
            # Extract local subgraph around address
            subgraph_nodes = self._extract_local_subgraph(address, max_depth)
            
            if len(subgraph_nodes) < 2:
                return []
            
            # Analyze subgraph for ML patterns
            subgraph = self.transaction_graph.subgraph(subgraph_nodes)
            
            # Pattern detection algorithms
            patterns.extend(self._detect_layering_patterns(subgraph, address))
            patterns.extend(self._detect_structuring_patterns(subgraph, address))
            patterns.extend(self._detect_mixing_patterns(subgraph, address))
            
            # Filter by confidence threshold
            patterns = [p for p in patterns if p.confidence >= self.min_pattern_confidence]
            
            self.logger.debug(f"Detected {len(patterns)} ML patterns for {address}")
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"ML pattern detection failed for {address}: {e}")
            return []
    
    def _extract_local_subgraph(self, center_node: str, max_depth: int) -> Set[str]:
        """Extract local subgraph around center node"""
        
        if not self.transaction_graph:
            return set()
        
        visited = set()
        queue = [(center_node, 0)]
        visited.add(center_node)
        
        while queue:
            node, depth = queue.pop(0)
            
            if depth >= max_depth:
                continue
            
            # Add neighbors
            for neighbor in self.transaction_graph.neighbors(node):
                if neighbor not in visited and len(visited) < self.max_subgraph_size:
                    visited.add(neighbor)
                    queue.append((neighbor, depth + 1))
            
            # Add predecessors for directed graph
            for predecessor in self.transaction_graph.predecessors(node):
                if predecessor not in visited and len(visited) < self.max_subgraph_size:
                    visited.add(predecessor)
                    queue.append((predecessor, depth + 1))
        
        return visited
    
    def _detect_layering_patterns(self, subgraph: nx.DiGraph, center_node: str) -> List[SubgraphPattern]:
        """Detect layering (transaction chain) patterns"""
        
        patterns = []
        
        try:
            # Find long paths from/to center node
            for target in subgraph.nodes():
                if target == center_node:
                    continue
                
                try:
                    # Check for paths of length 3+ (indicating layering)
                    paths = list(nx.all_simple_paths(subgraph, center_node, target, cutoff=6))
                    
                    for path in paths:
                        if len(path) >= 4:  # Minimum layering chain length
                            # Calculate pattern strength
                            confidence = self._calculate_layering_confidence(subgraph, path)
                            
                            if confidence >= self.min_pattern_confidence:
                                pattern = SubgraphPattern(
                                    subgraph_id=f"layering_{center_node}_{target}_{len(path)}",
                                    nodes=path,
                                    edges=[(path[i], path[i+1]) for i in range(len(path)-1)],
                                    label='money_laundering',
                                    confidence=confidence,
                                    pattern_type='layering',
                                    features={
                                        'chain_length': len(path),
                                        'complexity_score': confidence,
                                        'center_node': center_node
                                    }
                                )
                                patterns.append(pattern)
                
                except nx.NetworkXNoPath:
                    continue
            
        except Exception as e:
            self.logger.debug(f"Layering detection error: {e}")
        
        return patterns[:5]  # Limit patterns
    
    def _detect_structuring_patterns(self, subgraph: nx.DiGraph, center_node: str) -> List[SubgraphPattern]:
        """Detect structuring patterns (many small transactions)"""
        
        patterns = []
        
        try:
            # Look for high out-degree (many outgoing transactions)
            out_degree = subgraph.out_degree(center_node)
            
            if out_degree >= 5:  # Threshold for structuring
                outgoing_nodes = list(subgraph.successors(center_node))
                
                # Check if amounts are similar (if available)
                confidence = min(0.9, 0.5 + (out_degree / 20))
                
                pattern = SubgraphPattern(
                    subgraph_id=f"structuring_{center_node}_{out_degree}",
                    nodes=[center_node] + outgoing_nodes,
                    edges=[(center_node, successor) for successor in outgoing_nodes],
                    label='money_laundering',
                    confidence=confidence,
                    pattern_type='structuring',
                    features={
                        'transaction_count': out_degree,
                        'fan_out_ratio': out_degree / max(1, subgraph.in_degree(center_node))
                    }
                )
                patterns.append(pattern)
        
        except Exception as e:
            self.logger.debug(f"Structuring detection error: {e}")
        
        return patterns
    
    def _detect_mixing_patterns(self, subgraph: nx.DiGraph, center_node: str) -> List[SubgraphPattern]:
        """Detect mixing patterns (combining flows)"""
        
        patterns = []
        
        try:
            # Look for nodes with high in-degree and high out-degree (mixing points)
            in_degree = subgraph.in_degree(center_node)
            out_degree = subgraph.out_degree(center_node)
            
            if in_degree >= 3 and out_degree >= 3:
                # This looks like a mixing point
                incoming_nodes = list(subgraph.predecessors(center_node))
                outgoing_nodes = list(subgraph.successors(center_node))
                
                confidence = min(0.9, 0.4 + (min(in_degree, out_degree) / 10))
                
                pattern = SubgraphPattern(
                    subgraph_id=f"mixing_{center_node}_{in_degree}_{out_degree}",
                    nodes=incoming_nodes + [center_node] + outgoing_nodes,
                    edges=([(pred, center_node) for pred in incoming_nodes] + 
                          [(center_node, succ) for succ in outgoing_nodes]),
                    label='money_laundering',
                    confidence=confidence,
                    pattern_type='mixing',
                    features={
                        'in_degree': in_degree,
                        'out_degree': out_degree,
                        'mixing_ratio': min(in_degree, out_degree) / max(in_degree, out_degree)
                    }
                )
                patterns.append(pattern)
        
        except Exception as e:
            self.logger.debug(f"Mixing detection error: {e}")
        
        return patterns
    
    def _calculate_layering_confidence(self, subgraph: nx.DiGraph, path: List[str]) -> float:
        """Calculate confidence score for layering pattern"""
        
        base_confidence = 0.6
        
        # Longer chains are more suspicious
        length_bonus = min(0.3, (len(path) - 3) * 0.05)
        
        # Check for timing patterns (if available)
        timing_bonus = 0.0
        
        # Check for amount patterns (if available) 
        amount_bonus = 0.0
        
        return min(1.0, base_confidence + length_bonus + timing_bonus + amount_bonus)
    
    def analyze_address(self, address: str) -> Optional[MoneyLaunderingIntelligence]:
        """
        Comprehensive money laundering analysis for an address
        """
        
        if not self.transaction_graph:
            return None
        
        try:
            # Detect ML patterns
            patterns = self.detect_ml_patterns(address)
            
            # Risk classification
            risk_classification = self._classify_address_risk(patterns)
            
            # Extract ML features
            ml_features = self._extract_ml_features(address, patterns)
            
            # Graph analysis
            graph_analysis = self._analyze_graph_properties(address)
            
            # Temporal analysis
            temporal_analysis = self._analyze_temporal_patterns(address)
            
            intelligence = MoneyLaunderingIntelligence(
                query_address=address,
                detected_patterns=patterns,
                risk_classification=risk_classification,
                ml_features=ml_features,
                graph_analysis=graph_analysis,
                temporal_analysis=temporal_analysis
            )
            
            return intelligence
            
        except Exception as e:
            self.logger.error(f"Address analysis failed for {address}: {e}")
            return None
    
    def _classify_address_risk(self, patterns: List[SubgraphPattern]) -> str:
        """Classify address risk based on detected patterns"""
        
        if not patterns:
            return 'low_risk'
        
        # Count high-confidence ML patterns
        high_conf_patterns = [p for p in patterns if p.confidence >= 0.8]
        
        if len(high_conf_patterns) >= 2:
            return 'high_risk'
        elif len(patterns) >= 3 or len(high_conf_patterns) >= 1:
            return 'medium_risk'
        else:
            return 'low_risk'
    
    def _extract_ml_features(self, address: str, patterns: List[SubgraphPattern]) -> Dict[str, float]:
        """Extract machine learning features"""
        
        features = {
            'pattern_count': len(patterns),
            'max_pattern_confidence': max([p.confidence for p in patterns]) if patterns else 0.0,
            'avg_pattern_confidence': np.mean([p.confidence for p in patterns]) if patterns else 0.0,
            'layering_patterns': len([p for p in patterns if p.pattern_type == 'layering']),
            'structuring_patterns': len([p for p in patterns if p.pattern_type == 'structuring']),
            'mixing_patterns': len([p for p in patterns if p.pattern_type == 'mixing'])
        }
        
        if self.transaction_graph and address in self.transaction_graph:
            # Graph-based features
            features.update({
                'node_degree': self.transaction_graph.degree(address),
                'in_degree': self.transaction_graph.in_degree(address),
                'out_degree': self.transaction_graph.out_degree(address),
                'clustering_coefficient': nx.clustering(self.transaction_graph.to_undirected(), address)
            })
        
        return features
    
    def _analyze_graph_properties(self, address: str) -> Dict[str, Any]:
        """Analyze graph properties around address"""
        
        if not self.transaction_graph or address not in self.transaction_graph:
            return {}
        
        try:
            # Local subgraph analysis
            subgraph_nodes = self._extract_local_subgraph(address, 2)
            local_subgraph = self.transaction_graph.subgraph(subgraph_nodes)
            
            return {
                'local_nodes': len(subgraph_nodes),
                'local_edges': local_subgraph.number_of_edges(),
                'local_density': nx.density(local_subgraph),
                'connected_components': nx.number_connected_components(local_subgraph.to_undirected()),
                'average_clustering': nx.average_clustering(local_subgraph.to_undirected())
            }
        
        except Exception as e:
            self.logger.debug(f"Graph analysis error: {e}")
            return {}
    
    def _analyze_temporal_patterns(self, address: str) -> Dict[str, Any]:
        """Analyze temporal patterns (placeholder for time-based analysis)"""
        
        # This would be implemented with actual temporal data
        return {
            'temporal_analysis_available': False,
            'note': 'Requires temporal features in dataset'
        }
    
    def lookup_address(self, address: str) -> Optional[Dict[str, Any]]:
        """
        Standard lookup interface for addresses
        """
        
        intelligence = self.analyze_address(address)
        
        if not intelligence:
            return None
        
        return {
            'address': address,
            'found_elliptic2_data': True,
            'timestamp': datetime.utcnow().isoformat(),
            'money_laundering_analysis': {
                'risk_classification': intelligence.risk_classification,
                'detected_patterns': len(intelligence.detected_patterns),
                'pattern_types': list(set(p.pattern_type for p in intelligence.detected_patterns)),
                'max_confidence': max([p.confidence for p in intelligence.detected_patterns]) if intelligence.detected_patterns else 0.0
            },
            'ml_features': intelligence.ml_features,
            'graph_analysis': intelligence.graph_analysis,
            'risk_assessment': self._create_risk_assessment(intelligence)
        }
    
    def _create_risk_assessment(self, intelligence: MoneyLaunderingIntelligence) -> Dict[str, Any]:
        """Create risk assessment from ML intelligence"""
        
        risk_classification = intelligence.risk_classification
        pattern_count = len(intelligence.detected_patterns)
        max_confidence = max([p.confidence for p in intelligence.detected_patterns]) if intelligence.detected_patterns else 0.0
        
        # Map risk classification to numeric score
        risk_score_mapping = {
            'high_risk': 0.8 + (max_confidence * 0.2),
            'medium_risk': 0.5 + (max_confidence * 0.3),
            'low_risk': 0.1 + (max_confidence * 0.2)
        }
        
        risk_score = risk_score_mapping.get(risk_classification, 0.1)
        
        return {
            'risk_score': min(1.0, risk_score),
            'risk_level': risk_classification,
            'confidence': max_confidence,
            'primary_concerns': [p.pattern_type for p in intelligence.detected_patterns[:3]],
            'pattern_based_analysis': True
        }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse Elliptic2 data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_elliptic2_data'):
            return risk_factors
        
        ml_analysis = raw_data.get('money_laundering_analysis', {})
        risk_assessment = raw_data.get('risk_assessment', {})
        
        # Main ML pattern factor
        risk_classification = ml_analysis.get('risk_classification', 'low_risk')
        pattern_count = ml_analysis.get('detected_patterns', 0)
        pattern_types = ml_analysis.get('pattern_types', [])
        
        if risk_classification == 'high_risk':
            risk_level = RiskLevel.CRITICAL
        elif risk_classification == 'medium_risk':
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.MEDIUM
        
        description = f"Money laundering pattern analysis: {pattern_count} suspicious patterns detected"
        if pattern_types:
            description += f" ({', '.join(pattern_types)})"
        
        risk_factors.append(RiskFactor(
            type="money_laundering_patterns",
            description=description,
            risk_level=risk_level,
            confidence=risk_assessment.get('confidence', 0.7),
            source=DataSourceType.ACADEMIC,
            raw_data={
                'pattern_count': pattern_count,
                'pattern_types': pattern_types,
                'risk_classification': risk_classification
            }
        ))
        
        # Specific pattern type factors
        if 'layering' in pattern_types:
            risk_factors.append(RiskFactor(
                type="layering_pattern_detected",
                description="Layering pattern detected: complex transaction chains to obscure money trail",
                risk_level=RiskLevel.HIGH,
                confidence=0.85,
                source=DataSourceType.ACADEMIC,
                raw_data={'pattern_type': 'layering'}
            ))
        
        if 'structuring' in pattern_types:
            risk_factors.append(RiskFactor(
                type="structuring_pattern_detected", 
                description="Structuring pattern detected: breaking large amounts into smaller transactions",
                risk_level=RiskLevel.HIGH,
                confidence=0.8,
                source=DataSourceType.ACADEMIC,
                raw_data={'pattern_type': 'structuring'}
            ))
        
        return risk_factors
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get Elliptic2 processor statistics"""
        
        stats = {
            'configured': self.is_configured(),
            'datasets_loaded': self.nodes_data is not None,
            'data_directory': self.data_dir,
            'auto_download_enabled': self.enable_auto_download,
            'graph_built': self.transaction_graph is not None
        }
        
        if self.nodes_data is not None:
            stats['node_count'] = len(self.nodes_data)
        
        if self.edges_data is not None:
            stats['edge_count'] = len(self.edges_data)
        
        if self.transaction_graph:
            stats.update({
                'graph_nodes': self.transaction_graph.number_of_nodes(),
                'graph_edges': self.transaction_graph.number_of_edges(),
                'graph_density': nx.density(self.transaction_graph)
            })
        
        if self.background_nodes is not None:
            stats['background_nodes'] = len(self.background_nodes)
        
        if self.connected_components is not None:
            stats['connected_components'] = len(self.connected_components)
        
        stats['supported_patterns'] = list(self.ML_PATTERN_TYPES.keys())
        
        return stats