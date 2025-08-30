"""
GraphSense TagPacks Integration - downloads and processes GraphSense entity attribution data
for mapping cryptocurrency addresses to known entities, exchanges, and services.

GraphSense provides public TagPacks containing attribution data for millions of addresses
across multiple blockchain networks with entity categories and confidence scores.
"""

import json
import csv
import requests
import gzip
import zipfile
import os
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
import logging

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin


@dataclass
class EntityTag:
    """Represents an entity tag from GraphSense TagPacks"""
    address: str
    entity: str
    category: str
    source: str
    confidence: float
    last_active: Optional[datetime] = None
    first_seen: Optional[datetime] = None
    is_cluster_representative: bool = False
    cluster_size: Optional[int] = None


@dataclass
class EntityAttribution:
    """Comprehensive entity attribution for an address"""
    address: str
    primary_entity: Optional[str] = None
    entity_type: Optional[str] = None
    categories: List[str] = None
    confidence_score: float = 0.0
    attribution_sources: List[str] = None
    risk_indicators: List[str] = None
    related_entities: List[str] = None
    cluster_info: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.categories is None:
            self.categories = []
        if self.attribution_sources is None:
            self.attribution_sources = []
        if self.risk_indicators is None:
            self.risk_indicators = []
        if self.related_entities is None:
            self.related_entities = []


class GraphSenseTagPacksClient(BaseDataCollector, LoggingMixin):
    """
    Client for downloading and processing GraphSense TagPacks data.
    Provides entity attribution for cryptocurrency addresses.
    """
    
    # GraphSense TagPacks URLs (public repository)
    TAGPACK_URLS = {
        'bitcoin': 'https://github.com/graphsense/tagpack-tool/releases/download/tagpacks/btc_tagpack.json.gz',
        'ethereum': 'https://github.com/graphsense/tagpack-tool/releases/download/tagpacks/eth_tagpack.json.gz',
        'litecoin': 'https://github.com/graphsense/tagpack-tool/releases/download/tagpacks/ltc_tagpack.json.gz',
        'bitcoin_cash': 'https://github.com/graphsense/tagpack-tool/releases/download/tagpacks/bch_tagpack.json.gz'
    }
    
    # Risk categorization of entity types
    RISK_CATEGORIES = {
        'high_risk': {
            'darknet', 'mixer', 'ransomware', 'scam', 'terrorism', 'sanctions',
            'child_exploitation', 'drugs', 'weapons', 'fraud', 'money_laundering'
        },
        'medium_risk': {
            'gambling', 'adult', 'p2p_exchange', 'atm', 'unregulated_exchange',
            'privacy_coin_exchange', 'defi_risky'
        },
        'low_risk': {
            'exchange', 'wallet_service', 'payment_processor', 'mining_pool',
            'defi_protocol', 'institutional', 'merchant'
        },
        'neutral': {
            'individual', 'unknown', 'other'
        }
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        
        # Data storage
        self.tagpack_data = {}  # Network -> {address -> EntityTag}
        self.entity_database = {}  # Entity name -> EntityInfo
        
        # Configuration
        self.tagpack_dir = config.get('tagpack_dir', os.path.join(cache_dir or './cache', 'tagpacks'))
        self.supported_networks = config.get('supported_networks', ['bitcoin', 'ethereum'])
        self.auto_update = config.get('auto_update_tagpacks', True)
        self.max_cache_age_days = config.get('max_tagpack_cache_age_days', 7)
        
        # Ensure directories exist
        os.makedirs(self.tagpack_dir, exist_ok=True)
        
        # Load existing tagpacks
        self._load_existing_tagpacks()
        
        # Auto-update if enabled
        if self.auto_update:
            self._update_tagpacks()
        
        self.logger.info(
            "GraphSense TagPacks client initialized",
            supported_networks=self.supported_networks,
            loaded_addresses=sum(len(data) for data in self.tagpack_data.values())
        )
    
    @property
    def source_name(self) -> str:
        return "graphsense_tagpacks"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.GOVERNMENT
    
    def _load_existing_tagpacks(self):
        """Load any existing tagpack files from disk"""
        for network in self.supported_networks:
            tagpack_file = os.path.join(self.tagpack_dir, f"{network}_tagpack.json")
            
            if os.path.exists(tagpack_file):
                try:
                    # Check file age
                    file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(tagpack_file))
                    
                    if file_age.days > self.max_cache_age_days:
                        self.logger.info(f"TagPack {network} is {file_age.days} days old, will update")
                        continue
                    
                    with open(tagpack_file, 'r') as f:
                        data = json.load(f)
                        self._process_tagpack_data(network, data)
                        
                    self.logger.info(f"Loaded {network} tagpack: {len(self.tagpack_data.get(network, {}))} addresses")
                    
                except Exception as e:
                    self.logger.warning(f"Failed to load existing {network} tagpack: {e}")
    
    def _update_tagpacks(self):
        """Download and update tagpack data from GraphSense"""
        for network in self.supported_networks:
            if network in self.tagpack_data and len(self.tagpack_data[network]) > 0:
                # Skip if we already have recent data
                continue
                
            try:
                self.logger.info(f"Downloading {network} tagpack from GraphSense")
                self._download_tagpack(network)
            except Exception as e:
                self.logger.error(f"Failed to download {network} tagpack: {e}")
    
    def _download_tagpack(self, network: str):
        """Download tagpack for a specific network"""
        if network not in self.TAGPACK_URLS:
            raise ValueError(f"Unsupported network: {network}")
        
        url = self.TAGPACK_URLS[network]
        tagpack_file = os.path.join(self.tagpack_dir, f"{network}_tagpack.json")
        
        # Download with compression support
        response = requests.get(url, stream=True, timeout=300)
        response.raise_for_status()
        
        # Handle gzipped content
        if url.endswith('.gz'):
            data = gzip.decompress(response.content).decode('utf-8')
        else:
            data = response.text
        
        # Parse and process JSON data
        tagpack_data = json.loads(data)
        
        # Save to disk
        with open(tagpack_file, 'w') as f:
            json.dump(tagpack_data, f, indent=2)
        
        # Process into memory
        self._process_tagpack_data(network, tagpack_data)
        
        self.logger.info(
            f"Downloaded and processed {network} tagpack",
            addresses=len(self.tagpack_data.get(network, {}))
        )
    
    def _process_tagpack_data(self, network: str, data: Dict[str, Any]):
        """Process tagpack JSON data into EntityTag objects"""
        if network not in self.tagpack_data:
            self.tagpack_data[network] = {}
        
        # Handle different tagpack formats
        if 'tags' in data:
            tags_data = data['tags']
        elif isinstance(data, list):
            tags_data = data
        else:
            tags_data = data
        
        for item in tags_data:
            try:
                # Parse entity tag
                address = item.get('address', '').lower()
                entity = item.get('entity', item.get('label', 'unknown'))
                category = item.get('category', item.get('tag_type', 'other'))
                source = item.get('source', 'graphsense')
                confidence = float(item.get('confidence', item.get('score', 0.8)))
                
                # Parse dates if available
                last_active = None
                first_seen = None
                
                if 'last_active' in item:
                    last_active = datetime.fromisoformat(item['last_active'].replace('Z', '+00:00'))
                if 'first_seen' in item:
                    first_seen = datetime.fromisoformat(item['first_seen'].replace('Z', '+00:00'))
                
                # Cluster information
                is_cluster_rep = item.get('is_cluster_representative', False)
                cluster_size = item.get('cluster_size')
                
                tag = EntityTag(
                    address=address,
                    entity=entity,
                    category=category,
                    source=source,
                    confidence=confidence,
                    last_active=last_active,
                    first_seen=first_seen,
                    is_cluster_representative=is_cluster_rep,
                    cluster_size=cluster_size
                )
                
                self.tagpack_data[network][address] = tag
                
                # Build entity database
                if entity not in self.entity_database:
                    self.entity_database[entity] = {
                        'name': entity,
                        'category': category,
                        'networks': set(),
                        'address_count': 0,
                        'first_seen': first_seen,
                        'risk_level': self._categorize_risk(category)
                    }
                
                self.entity_database[entity]['networks'].add(network)
                self.entity_database[entity]['address_count'] += 1
                
                if first_seen and (not self.entity_database[entity]['first_seen'] or 
                                 first_seen < self.entity_database[entity]['first_seen']):
                    self.entity_database[entity]['first_seen'] = first_seen
                
            except Exception as e:
                self.logger.warning(f"Failed to process tag item: {e}")
                continue
    
    def _categorize_risk(self, category: str) -> str:
        """Categorize entity type by risk level"""
        category_lower = category.lower()
        
        for risk_level, categories in self.RISK_CATEGORIES.items():
            if any(cat in category_lower for cat in categories):
                return risk_level
        
        return 'neutral'
    
    def lookup_address(self, address: str, network: str = None) -> Optional[Dict[str, Any]]:
        """
        Look up entity attribution for a cryptocurrency address.
        
        Args:
            address: The cryptocurrency address to look up
            network: Optional network specification (bitcoin, ethereum, etc.)
            
        Returns:
            Dictionary containing attribution data
        """
        address_lower = address.lower()
        found_attributions = []
        
        # Search across networks if not specified
        networks_to_search = [network] if network else self.tagpack_data.keys()
        
        for net in networks_to_search:
            if net in self.tagpack_data and address_lower in self.tagpack_data[net]:
                tag = self.tagpack_data[net][address_lower]
                found_attributions.append({
                    'network': net,
                    'entity': tag.entity,
                    'category': tag.category,
                    'source': tag.source,
                    'confidence': tag.confidence,
                    'last_active': tag.last_active.isoformat() if tag.last_active else None,
                    'first_seen': tag.first_seen.isoformat() if tag.first_seen else None,
                    'is_cluster_representative': tag.is_cluster_representative,
                    'cluster_size': tag.cluster_size,
                    'risk_level': self._categorize_risk(tag.category)
                })
        
        if not found_attributions:
            return None
        
        # Build comprehensive result
        result = {
            'address': address,
            'found_graphsense_data': True,
            'timestamp': datetime.utcnow().isoformat(),
            'attribution_count': len(found_attributions),
            'attributions': found_attributions,
            'primary_attribution': found_attributions[0] if found_attributions else None,
            'risk_assessment': self._assess_address_risk(found_attributions)
        }
        
        return result
    
    def _assess_address_risk(self, attributions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall risk based on entity attributions"""
        if not attributions:
            return {'risk_score': 0.0, 'risk_level': 'unknown', 'primary_concerns': []}
        
        # Calculate weighted risk score
        risk_scores = []
        confidence_weights = []
        risk_indicators = []
        
        for attr in attributions:
            risk_level = attr['risk_level']
            confidence = attr['confidence']
            category = attr['category']
            
            # Convert risk level to numeric score
            score_map = {
                'high_risk': 0.9,
                'medium_risk': 0.6,
                'low_risk': 0.2,
                'neutral': 0.1
            }
            
            risk_score = score_map.get(risk_level, 0.1)
            risk_scores.append(risk_score)
            confidence_weights.append(confidence)
            
            if risk_level in ['high_risk', 'medium_risk']:
                risk_indicators.append(f"{category}_{attr['entity']}")
        
        # Weighted average
        if confidence_weights:
            total_weight = sum(confidence_weights)
            weighted_score = sum(s * w for s, w in zip(risk_scores, confidence_weights)) / total_weight
        else:
            weighted_score = sum(risk_scores) / len(risk_scores)
        
        # Determine overall risk level
        if weighted_score >= 0.8:
            overall_risk = 'critical'
        elif weighted_score >= 0.6:
            overall_risk = 'high'
        elif weighted_score >= 0.3:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        return {
            'risk_score': weighted_score,
            'risk_level': overall_risk,
            'confidence': sum(confidence_weights) / len(confidence_weights) if confidence_weights else 0,
            'primary_concerns': list(set(risk_indicators)),
            'attribution_sources': list(set(attr['source'] for attr in attributions))
        }
    
    def get_entity_info(self, entity_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific entity"""
        if entity_name not in self.entity_database:
            return None
        
        entity_info = self.entity_database[entity_name].copy()
        entity_info['networks'] = list(entity_info['networks'])
        
        if entity_info['first_seen']:
            entity_info['first_seen'] = entity_info['first_seen'].isoformat()
        
        return entity_info
    
    def search_entities(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search for entities by name or category"""
        query_lower = query.lower()
        matches = []
        
        for entity_name, entity_info in self.entity_database.items():
            if (query_lower in entity_name.lower() or 
                query_lower in entity_info['category'].lower()):
                
                matches.append({
                    'entity': entity_name,
                    'category': entity_info['category'],
                    'networks': list(entity_info['networks']),
                    'address_count': entity_info['address_count'],
                    'risk_level': entity_info['risk_level']
                })
        
        # Sort by address count (popularity) and limit
        matches.sort(key=lambda x: x['address_count'], reverse=True)
        return matches[:limit]
    
    def analyze_address(self, address: str) -> Optional[WalletAnalysis]:
        """
        Analyze an address for entity attribution and return structured analysis.
        
        Args:
            address: Cryptocurrency address to analyze
            
        Returns:
            WalletAnalysis containing entity attribution assessment
        """
        try:
            # Look up attribution data
            data = self.lookup_address(address)
            
            if not data or not data.get('found_graphsense_data'):
                return None
            
            # Parse into risk factors
            risk_factors = self.parse_risk_factors(data, address)
            
            # Create wallet analysis
            risk_assessment = data.get('risk_assessment', {})
            primary_attribution = data.get('primary_attribution', {})
            
            risk_score = risk_assessment.get('risk_score', 0.0)
            is_flagged = risk_assessment.get('risk_level') in ['high', 'critical']
            
            # Create summary
            if primary_attribution:
                entity = primary_attribution.get('entity', 'Unknown')
                category = primary_attribution.get('category', 'other')
                summary = f"Entity attribution: {entity} ({category})"
            else:
                summary = f"GraphSense attribution: {len(data.get('attributions', []))} matches found"
            
            analysis = WalletAnalysis(
                address=address,
                analysis_timestamp=datetime.now(timezone.utc),
                data_sources=[self.source_name],
                risk_factors=risk_factors,
                overall_risk_score=risk_score,
                risk_level=self._score_to_risk_level(risk_score),
                confidence_score=risk_assessment.get('confidence', 0.0),
                is_flagged=is_flagged,
                summary=summary,
                raw_data=data
            )
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing address {address}: {e}")
            return None
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse GraphSense attribution data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_graphsense_data'):
            return risk_factors
        
        attributions = raw_data.get('attributions', [])
        risk_assessment = raw_data.get('risk_assessment', {})
        
        for attribution in attributions:
            entity = attribution.get('entity', 'Unknown')
            category = attribution.get('category', 'other')
            confidence = attribution.get('confidence', 0.0)
            risk_level_str = attribution.get('risk_level', 'neutral')
            network = attribution.get('network', 'unknown')
            
            # Convert to RiskLevel enum
            risk_level_map = {
                'critical': RiskLevel.CRITICAL,
                'high_risk': RiskLevel.HIGH,
                'medium_risk': RiskLevel.MEDIUM,
                'low_risk': RiskLevel.LOW,
                'neutral': RiskLevel.LOW
            }
            
            risk_level = risk_level_map.get(risk_level_str, RiskLevel.LOW)
            
            # Create risk factor
            description = f"Address attributed to {entity} ({category}) on {network}"
            
            # Add special handling for high-risk entities
            if risk_level_str == 'high_risk':
                description = f"⚠️ HIGH RISK: {description}"
            
            risk_factor = RiskFactor(
                type=f"entity_attribution_{category}",
                description=description,
                risk_level=risk_level,
                confidence=confidence,
                source=DataSourceType.GOVERNMENT,
                raw_data={
                    'entity': entity,
                    'category': category,
                    'network': network,
                    'source': attribution.get('source'),
                    'cluster_info': {
                        'is_representative': attribution.get('is_cluster_representative'),
                        'cluster_size': attribution.get('cluster_size')
                    }
                }
            )
            
            risk_factors.append(risk_factor)
        
        # Add summary risk factor if multiple attributions
        if len(attributions) > 1:
            primary_concerns = risk_assessment.get('primary_concerns', [])
            overall_risk_score = risk_assessment.get('risk_score', 0)
            
            risk_factors.append(RiskFactor(
                type="multi_source_entity_attribution",
                description=f"Multiple entity attributions: {', '.join([a['entity'] for a in attributions[:3]])}",
                risk_level=self._score_to_risk_level(overall_risk_score),
                confidence=risk_assessment.get('confidence', 0.0),
                source=DataSourceType.GOVERNMENT,
                raw_data={
                    'attribution_count': len(attributions),
                    'primary_concerns': primary_concerns,
                    'networks': list(set(a['network'] for a in attributions))
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
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get GraphSense TagPacks statistics"""
        total_addresses = sum(len(data) for data in self.tagpack_data.values())
        total_entities = len(self.entity_database)
        
        network_stats = {}
        for network, data in self.tagpack_data.items():
            risk_distribution = {}
            for tag in data.values():
                risk_level = self._categorize_risk(tag.category)
                risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1
            
            network_stats[network] = {
                'address_count': len(data),
                'risk_distribution': risk_distribution
            }
        
        return {
            'total_addresses': total_addresses,
            'total_entities': total_entities,
            'supported_networks': self.supported_networks,
            'network_statistics': network_stats,
            'cache_directory': self.tagpack_dir
        }