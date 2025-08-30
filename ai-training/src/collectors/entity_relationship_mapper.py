"""
Entity Relationship Mapper - creates and analyzes relationships between cryptocurrency
addresses, entities, and services to understand fund flows and entity interactions.

Uses graph analysis to identify clusters, suspicious patterns, and relationship risks.
"""

import networkx as nx
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
import logging
from collections import defaultdict, deque

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin


class RelationshipType(Enum):
    """Types of relationships between entities"""
    DIRECT_TRANSACTION = "direct_transaction"
    CLUSTER_MEMBER = "cluster_member"
    SAME_ENTITY = "same_entity"
    SERVICE_USER = "service_user"
    EXCHANGE_DEPOSIT = "exchange_deposit"
    MIXER_OUTPUT = "mixer_output"
    FUNDING_RELATIONSHIP = "funding_relationship"
    CONSOLIDATION = "consolidation"
    SPLIT_TRANSACTION = "split_transaction"
    UNKNOWN = "unknown"


class RiskPropagation(Enum):
    """How risk propagates through relationships"""
    DIRECT = "direct"           # Full risk propagation
    PARTIAL = "partial"         # Reduced risk propagation
    MINIMAL = "minimal"         # Very limited risk propagation
    NONE = "none"              # No risk propagation


@dataclass
class EntityRelationship:
    """Represents a relationship between two entities or addresses"""
    source: str
    target: str
    relationship_type: RelationshipType
    confidence: float
    strength: float  # Relationship strength (e.g., transaction volume)
    risk_propagation: RiskPropagation
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    transaction_count: int = 0
    total_value: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EntityCluster:
    """Represents a cluster of related entities"""
    cluster_id: str
    members: Set[str]
    cluster_type: str  # e.g., 'exchange', 'mixer', 'individual'
    confidence: float
    risk_score: float
    primary_entity: Optional[str] = None
    creation_date: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PathAnalysis:
    """Analysis of a path between entities"""
    source: str
    target: str
    path: List[str]
    path_length: int
    total_risk_score: float
    risk_propagation_factor: float
    relationship_types: List[RelationshipType]
    suspicious_patterns: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


class EntityRelationshipMapper(BaseDataCollector, LoggingMixin):
    """
    Maps and analyzes relationships between cryptocurrency entities, addresses,
    and services to understand fund flows and identify suspicious patterns.
    """
    
    # Risk propagation factors for different relationship types
    RISK_PROPAGATION_FACTORS = {
        RelationshipType.DIRECT_TRANSACTION: 0.8,
        RelationshipType.CLUSTER_MEMBER: 0.9,
        RelationshipType.SAME_ENTITY: 1.0,
        RelationshipType.SERVICE_USER: 0.3,
        RelationshipType.EXCHANGE_DEPOSIT: 0.2,
        RelationshipType.MIXER_OUTPUT: 0.6,
        RelationshipType.FUNDING_RELATIONSHIP: 0.7,
        RelationshipType.CONSOLIDATION: 0.8,
        RelationshipType.SPLIT_TRANSACTION: 0.5,
        RelationshipType.UNKNOWN: 0.1
    }
    
    # Suspicious patterns to detect
    SUSPICIOUS_PATTERNS = [
        'rapid_mixing_sequence',
        'layering_pattern',
        'round_number_transactions',
        'high_frequency_micro_transactions',
        'cross_chain_bridge_abuse',
        'exchange_hopping',
        'privacy_coin_conversion',
        'darknet_funding_path'
    ]
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # Graph storage
        self.relationship_graph = nx.DiGraph()
        self.clusters = {}  # cluster_id -> EntityCluster
        self.address_to_cluster = {}  # address -> cluster_id
        
        # Configuration
        self.max_path_length = config.get('max_path_length', 6)
        self.min_relationship_confidence = config.get('min_relationship_confidence', 0.5)
        self.risk_propagation_decay = config.get('risk_propagation_decay', 0.1)
        self.enable_clustering = config.get('enable_clustering', True)
        
        # Analysis caches
        self.path_cache = {}
        self.risk_analysis_cache = {}
        
        self.logger.info(
            "Entity Relationship Mapper initialized",
            max_path_length=self.max_path_length,
            clustering_enabled=self.enable_clustering
        )
    
    @property
    def source_name(self) -> str:
        return "entity_relationship_mapper"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.BEHAVIORAL_ANALYSIS
    
    def add_relationship(self, relationship: EntityRelationship) -> bool:
        """Add a relationship to the graph"""
        try:
            # Validate relationship
            if relationship.confidence < self.min_relationship_confidence:
                return False
            
            # Add nodes if they don't exist
            if not self.relationship_graph.has_node(relationship.source):
                self.relationship_graph.add_node(relationship.source, 
                                                entity_type='address',
                                                first_seen=relationship.first_seen)
            
            if not self.relationship_graph.has_node(relationship.target):
                self.relationship_graph.add_node(relationship.target,
                                                entity_type='address',
                                                first_seen=relationship.first_seen)
            
            # Add or update edge
            edge_data = {
                'relationship_type': relationship.relationship_type,
                'confidence': relationship.confidence,
                'strength': relationship.strength,
                'risk_propagation': relationship.risk_propagation,
                'first_seen': relationship.first_seen,
                'last_seen': relationship.last_seen,
                'transaction_count': relationship.transaction_count,
                'total_value': relationship.total_value,
                'metadata': relationship.metadata
            }
            
            self.relationship_graph.add_edge(relationship.source, relationship.target, **edge_data)
            
            # Update clustering if enabled
            if self.enable_clustering:
                self._update_clusters(relationship)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add relationship: {e}")
            return False
    
    def _update_clusters(self, relationship: EntityRelationship):
        """Update entity clusters based on new relationship"""
        source_cluster = self.address_to_cluster.get(relationship.source)
        target_cluster = self.address_to_cluster.get(relationship.target)
        
        # Both addresses are new - create new cluster if relationship is strong
        if not source_cluster and not target_cluster:
            if (relationship.relationship_type in [RelationshipType.CLUSTER_MEMBER, RelationshipType.SAME_ENTITY] and
                relationship.confidence > 0.8):
                self._create_cluster([relationship.source, relationship.target], relationship)
        
        # One address is in a cluster - add the other if appropriate
        elif source_cluster and not target_cluster:
            if self._should_add_to_cluster(relationship, source_cluster):
                self._add_to_cluster(relationship.target, source_cluster)
        
        elif target_cluster and not source_cluster:
            if self._should_add_to_cluster(relationship, target_cluster):
                self._add_to_cluster(relationship.source, target_cluster)
        
        # Both addresses are in different clusters - consider merging
        elif source_cluster and target_cluster and source_cluster != target_cluster:
            if self._should_merge_clusters(relationship, source_cluster, target_cluster):
                self._merge_clusters(source_cluster, target_cluster)
    
    def _create_cluster(self, members: List[str], relationship: EntityRelationship):
        """Create a new entity cluster"""
        cluster_id = f"cluster_{len(self.clusters) + 1}_{int(datetime.now().timestamp())}"
        
        cluster = EntityCluster(
            cluster_id=cluster_id,
            members=set(members),
            cluster_type='unknown',
            confidence=relationship.confidence,
            risk_score=0.0,
            creation_date=datetime.now(timezone.utc)
        )
        
        self.clusters[cluster_id] = cluster
        
        for member in members:
            self.address_to_cluster[member] = cluster_id
        
        self.logger.debug(f"Created cluster {cluster_id} with {len(members)} members")
    
    def _should_add_to_cluster(self, relationship: EntityRelationship, cluster_id: str) -> bool:
        """Determine if address should be added to cluster"""
        return (relationship.relationship_type in [RelationshipType.CLUSTER_MEMBER, RelationshipType.SAME_ENTITY] and
                relationship.confidence > 0.7)
    
    def _add_to_cluster(self, address: str, cluster_id: str):
        """Add address to existing cluster"""
        if cluster_id in self.clusters:
            self.clusters[cluster_id].members.add(address)
            self.clusters[cluster_id].last_updated = datetime.now(timezone.utc)
            self.address_to_cluster[address] = cluster_id
    
    def _should_merge_clusters(self, relationship: EntityRelationship, cluster1: str, cluster2: str) -> bool:
        """Determine if two clusters should be merged"""
        return (relationship.relationship_type == RelationshipType.SAME_ENTITY and
                relationship.confidence > 0.9)
    
    def _merge_clusters(self, cluster1_id: str, cluster2_id: str):
        """Merge two clusters"""
        if cluster1_id in self.clusters and cluster2_id in self.clusters:
            cluster1 = self.clusters[cluster1_id]
            cluster2 = self.clusters[cluster2_id]
            
            # Merge members
            cluster1.members.update(cluster2.members)
            cluster1.confidence = min(cluster1.confidence, cluster2.confidence)
            cluster1.last_updated = datetime.now(timezone.utc)
            
            # Update address mappings
            for address in cluster2.members:
                self.address_to_cluster[address] = cluster1_id
            
            # Remove old cluster
            del self.clusters[cluster2_id]
            
            self.logger.debug(f"Merged cluster {cluster2_id} into {cluster1_id}")
    
    def find_paths(self, source: str, target: str, max_length: Optional[int] = None) -> List[PathAnalysis]:
        """Find paths between two entities"""
        if max_length is None:
            max_length = self.max_path_length
        
        # Check cache
        cache_key = f"{source}_{target}_{max_length}"
        if cache_key in self.path_cache:
            return self.path_cache[cache_key]
        
        try:
            paths = []
            
            # Find all simple paths up to max_length
            if self.relationship_graph.has_node(source) and self.relationship_graph.has_node(target):
                for path in nx.all_simple_paths(self.relationship_graph, source, target, cutoff=max_length):
                    path_analysis = self._analyze_path(path)
                    paths.append(path_analysis)
            
            # Sort by risk score (highest first)
            paths.sort(key=lambda p: p.total_risk_score, reverse=True)
            
            # Cache result
            self.path_cache[cache_key] = paths[:10]  # Limit to top 10 paths
            
            return paths
            
        except Exception as e:
            self.logger.error(f"Error finding paths from {source} to {target}: {e}")
            return []
    
    def _analyze_path(self, path: List[str]) -> PathAnalysis:
        """Analyze a path between entities"""
        if len(path) < 2:
            return PathAnalysis(path[0], path[0], path, 0, 0.0, 0.0, [], [])
        
        relationship_types = []
        total_risk = 0.0
        risk_propagation = 1.0
        suspicious_patterns = []
        
        # Analyze each edge in the path
        for i in range(len(path) - 1):
            source_node = path[i]
            target_node = path[i + 1]
            
            if self.relationship_graph.has_edge(source_node, target_node):
                edge_data = self.relationship_graph[source_node][target_node]
                rel_type = edge_data.get('relationship_type', RelationshipType.UNKNOWN)
                relationship_types.append(rel_type)
                
                # Calculate risk propagation
                propagation_factor = self.RISK_PROPAGATION_FACTORS.get(rel_type, 0.1)
                risk_propagation *= propagation_factor
                
                # Apply distance decay
                distance_factor = 1.0 - (i * self.risk_propagation_decay)
                risk_propagation *= max(0.1, distance_factor)
        
        # Detect suspicious patterns
        suspicious_patterns = self._detect_path_patterns(path, relationship_types)
        
        # Calculate total risk score
        base_risk = 0.5  # Base risk for any connection
        pattern_risk = len(suspicious_patterns) * 0.1
        total_risk = (base_risk + pattern_risk) * risk_propagation
        
        return PathAnalysis(
            source=path[0],
            target=path[-1],
            path=path,
            path_length=len(path) - 1,
            total_risk_score=min(1.0, total_risk),
            risk_propagation_factor=risk_propagation,
            relationship_types=relationship_types,
            suspicious_patterns=suspicious_patterns
        )
    
    def _detect_path_patterns(self, path: List[str], relationship_types: List[RelationshipType]) -> List[str]:
        """Detect suspicious patterns in a path"""
        patterns = []
        
        # Mixing pattern detection
        if RelationshipType.MIXER_OUTPUT in relationship_types:
            patterns.append('mixing_detected')
        
        # Layering pattern (multiple hops through services)
        service_hops = sum(1 for rt in relationship_types 
                          if rt in [RelationshipType.SERVICE_USER, RelationshipType.EXCHANGE_DEPOSIT])
        if service_hops >= 3:
            patterns.append('layering_pattern')
        
        # Rapid sequence pattern
        if len(path) > 4:
            patterns.append('complex_routing')
        
        return patterns
    
    def calculate_entity_risk(self, entity: str, visited: Optional[Set[str]] = None) -> float:
        """Calculate risk score for an entity based on its relationships"""
        if visited is None:
            visited = set()
        
        if entity in visited:
            return 0.0
        
        visited.add(entity)
        
        # Check cache
        if entity in self.risk_analysis_cache:
            return self.risk_analysis_cache[entity]
        
        try:
            if not self.relationship_graph.has_node(entity):
                return 0.0
            
            base_risk = 0.0
            relationship_risk = 0.0
            
            # Analyze direct relationships
            for neighbor in self.relationship_graph.neighbors(entity):
                if neighbor not in visited:
                    edge_data = self.relationship_graph[entity][neighbor]
                    rel_type = edge_data.get('relationship_type', RelationshipType.UNKNOWN)
                    confidence = edge_data.get('confidence', 0.0)
                    
                    # Get propagation factor
                    propagation = self.RISK_PROPAGATION_FACTORS.get(rel_type, 0.1)
                    
                    # Recursively calculate neighbor risk (with depth limit)
                    if len(visited) < 3:  # Limit recursion depth
                        neighbor_risk = self.calculate_entity_risk(neighbor, visited.copy())
                        relationship_risk += neighbor_risk * propagation * confidence
            
            # Normalize and combine risks
            total_risk = min(1.0, base_risk + (relationship_risk * 0.3))
            
            # Cache result
            self.risk_analysis_cache[entity] = total_risk
            
            return total_risk
            
        except Exception as e:
            self.logger.error(f"Error calculating risk for entity {entity}: {e}")
            return 0.0
    
    def lookup_address(self, address: str) -> Optional[Dict[str, Any]]:
        """
        Look up relationship data for an address.
        
        Args:
            address: Address to analyze
            
        Returns:
            Dictionary containing relationship analysis
        """
        try:
            result = {
                'address': address,
                'found_relationship_data': False,
                'timestamp': datetime.utcnow().isoformat(),
                'cluster_info': None,
                'relationship_summary': {
                    'direct_connections': 0,
                    'total_connections': 0,
                    'risk_score': 0.0,
                    'suspicious_patterns': []
                },
                'high_risk_connections': [],
                'entity_paths': []
            }
            
            if not self.relationship_graph.has_node(address):
                return result
            
            result['found_relationship_data'] = True
            
            # Cluster information
            cluster_id = self.address_to_cluster.get(address)
            if cluster_id and cluster_id in self.clusters:
                cluster = self.clusters[cluster_id]
                result['cluster_info'] = {
                    'cluster_id': cluster_id,
                    'cluster_type': cluster.cluster_type,
                    'member_count': len(cluster.members),
                    'confidence': cluster.confidence,
                    'risk_score': cluster.risk_score
                }
            
            # Relationship analysis
            direct_neighbors = list(self.relationship_graph.neighbors(address))
            total_connections = len(direct_neighbors)
            
            # Calculate risk score
            risk_score = self.calculate_entity_risk(address)
            
            # Identify high-risk connections
            high_risk_connections = []
            suspicious_patterns = []
            
            for neighbor in direct_neighbors:
                neighbor_risk = self.calculate_entity_risk(neighbor)
                if neighbor_risk > 0.7:
                    edge_data = self.relationship_graph[address][neighbor]
                    high_risk_connections.append({
                        'connected_address': neighbor,
                        'relationship_type': edge_data.get('relationship_type', RelationshipType.UNKNOWN).value,
                        'risk_score': neighbor_risk,
                        'confidence': edge_data.get('confidence', 0.0)
                    })
            
            result['relationship_summary'] = {
                'direct_connections': total_connections,
                'total_connections': total_connections,  # Could include multi-hop later
                'risk_score': risk_score,
                'suspicious_patterns': suspicious_patterns
            }
            
            result['high_risk_connections'] = high_risk_connections[:10]  # Top 10
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing relationships for {address}: {e}")
            return None
    
    def analyze_address(self, address: str) -> Optional[WalletAnalysis]:
        """
        Analyze address relationships and return structured analysis.
        
        Args:
            address: Address to analyze
            
        Returns:
            WalletAnalysis containing relationship assessment
        """
        try:
            # Look up relationship data
            data = self.lookup_address(address)
            
            if not data or not data.get('found_relationship_data'):
                return None
            
            # Parse into risk factors
            risk_factors = self.parse_risk_factors(data, address)
            
            # Create wallet analysis
            rel_summary = data.get('relationship_summary', {})
            risk_score = rel_summary.get('risk_score', 0.0)
            
            # Determine if flagged based on high-risk connections
            high_risk_connections = data.get('high_risk_connections', [])
            is_flagged = len(high_risk_connections) > 0 or risk_score > 0.6
            
            # Create summary
            connection_count = rel_summary.get('direct_connections', 0)
            cluster_info = data.get('cluster_info')
            
            if cluster_info:
                summary = f"Entity relationships: {connection_count} connections, member of {cluster_info['cluster_type']} cluster"
            else:
                summary = f"Entity relationships: {connection_count} direct connections analyzed"
            
            analysis = WalletAnalysis(
                address=address,
                analysis_timestamp=datetime.now(timezone.utc),
                data_sources=[self.source_name],
                risk_factors=risk_factors,
                overall_risk_score=risk_score,
                risk_level=self._score_to_risk_level(risk_score),
                confidence_score=0.7,  # Medium confidence for relationship analysis
                is_flagged=is_flagged,
                summary=summary,
                raw_data=data
            )
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing relationships for {address}: {e}")
            return None
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse relationship data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_relationship_data'):
            return risk_factors
        
        rel_summary = raw_data.get('relationship_summary', {})
        high_risk_connections = raw_data.get('high_risk_connections', [])
        cluster_info = raw_data.get('cluster_info')
        
        # High-risk connection risk factors
        for connection in high_risk_connections:
            connected_addr = connection.get('connected_address', '')
            risk_score = connection.get('risk_score', 0.0)
            rel_type = connection.get('relationship_type', 'unknown')
            confidence = connection.get('confidence', 0.0)
            
            risk_level = self._score_to_risk_level(risk_score)
            
            risk_factors.append(RiskFactor(
                type=f"high_risk_relationship_{rel_type}",
                description=f"Connected to high-risk address via {rel_type.replace('_', ' ')}",
                risk_level=risk_level,
                confidence=confidence,
                source=DataSourceType.BEHAVIORAL_ANALYSIS,
                raw_data={
                    'connected_address': connected_addr,
                    'relationship_type': rel_type,
                    'connection_risk_score': risk_score
                }
            ))
        
        # Cluster membership risk factor
        if cluster_info:
            cluster_risk = cluster_info.get('risk_score', 0.0)
            cluster_type = cluster_info.get('cluster_type', 'unknown')
            member_count = cluster_info.get('member_count', 0)
            
            risk_factors.append(RiskFactor(
                type=f"cluster_membership_{cluster_type}",
                description=f"Member of {cluster_type} cluster with {member_count} addresses",
                risk_level=self._score_to_risk_level(cluster_risk),
                confidence=cluster_info.get('confidence', 0.0),
                source=DataSourceType.BEHAVIORAL_ANALYSIS,
                raw_data=cluster_info
            ))
        
        # Overall relationship risk
        overall_risk = rel_summary.get('risk_score', 0.0)
        connection_count = rel_summary.get('direct_connections', 0)
        
        if overall_risk > 0.3 and connection_count > 0:
            risk_factors.append(RiskFactor(
                type="entity_relationship_risk",
                description=f"Relationship analysis indicates elevated risk ({connection_count} connections)",
                risk_level=self._score_to_risk_level(overall_risk),
                confidence=0.7,
                source=DataSourceType.BEHAVIORAL_ANALYSIS,
                raw_data=rel_summary
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
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get entity relationship mapper statistics"""
        total_nodes = self.relationship_graph.number_of_nodes()
        total_edges = self.relationship_graph.number_of_edges()
        total_clusters = len(self.clusters)
        
        # Relationship type distribution
        relationship_types = defaultdict(int)
        for _, _, edge_data in self.relationship_graph.edges(data=True):
            rel_type = edge_data.get('relationship_type', RelationshipType.UNKNOWN)
            relationship_types[rel_type.value] += 1
        
        # Cluster size distribution
        cluster_sizes = [len(cluster.members) for cluster in self.clusters.values()]
        avg_cluster_size = sum(cluster_sizes) / len(cluster_sizes) if cluster_sizes else 0
        
        return {
            'total_entities': total_nodes,
            'total_relationships': total_edges,
            'total_clusters': total_clusters,
            'avg_cluster_size': avg_cluster_size,
            'relationship_type_distribution': dict(relationship_types),
            'cache_entries': {
                'path_cache': len(self.path_cache),
                'risk_cache': len(self.risk_analysis_cache)
            }
        }