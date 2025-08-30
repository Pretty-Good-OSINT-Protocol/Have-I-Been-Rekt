"""
Ransomwhere Dataset Processor - processes ransomware payment data.

Integrates with Ransomwhere dataset to:
- Download and parse ransomware payment addresses
- Categorize by malware family (Ryuk, Conti, etc.)
- Track payment amounts and timing
- Provide attribution to specific campaigns
- Create searchable database of ransom wallets
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
import requests
import json
import csv
import os
from pathlib import Path
import re
from decimal import Decimal

from ..data_collector import BaseDataCollector
from ..utils.logging import get_logger


@dataclass
class RansomwareAddress:
    """Ransomware payment address record"""
    
    address: str
    cryptocurrency: str  # BTC, ETH, etc.
    malware_family: str  # Ryuk, Conti, LockBit, etc.
    campaign_id: Optional[str]
    first_seen: datetime
    last_seen: datetime
    payment_count: int
    total_amount: Decimal
    total_amount_usd: Optional[Decimal]
    victim_count: Optional[int]
    status: str  # active, inactive, seized
    source_confidence: float
    attribution_notes: str


@dataclass
class RansomwareFamily:
    """Information about a ransomware family"""
    
    name: str
    aliases: List[str]
    first_seen: datetime
    last_activity: datetime
    total_addresses: int
    total_payments_usd: Decimal
    victim_count: int
    target_sectors: List[str]
    payment_methods: List[str]
    average_demand_usd: Optional[Decimal]
    description: str


@dataclass
class RansomwareIntelligence:
    """Comprehensive ransomware intelligence report"""
    
    address: str
    is_ransomware_address: bool
    malware_families: List[str]
    campaign_attribution: List[str]
    payment_history: Dict[str, Any]
    threat_assessment: Dict[str, Any]
    related_addresses: Set[str]
    analysis_timestamp: datetime


class RansomwhereProcessor(BaseDataCollector):
    """
    Ransomwhere dataset processor for ransomware payment analysis.
    
    Processes multiple data sources:
    - Ransomwhere public dataset
    - Community-contributed addresses
    - Law enforcement takedown data
    - Blockchain analytics correlations
    """
    
    RANSOMWHERE_API = "https://ransomwhe.re/api/v1"
    DATASET_URL = "https://raw.githubusercontent.com/cryptoinsight/ransomwhere/master/addresses.json"
    
    # Major ransomware families
    RANSOMWARE_FAMILIES = {
        'ryuk': {
            'aliases': ['ryuk', 'wizard spider'],
            'target_sectors': ['healthcare', 'government', 'education'],
            'payment_method': 'bitcoin'
        },
        'conti': {
            'aliases': ['conti', 'wizard spider'],
            'target_sectors': ['healthcare', 'manufacturing', 'retail'],
            'payment_method': 'bitcoin'
        },
        'lockbit': {
            'aliases': ['lockbit', 'lockbit 2.0', 'lockbit 3.0'],
            'target_sectors': ['financial', 'legal', 'technology'],
            'payment_method': 'bitcoin'
        },
        'revil': {
            'aliases': ['revil', 'sodinokibi', 'gold southfield'],
            'target_sectors': ['msp', 'supply_chain', 'enterprise'],
            'payment_method': 'bitcoin'
        },
        'darkside': {
            'aliases': ['darkside', 'carbon spider'],
            'target_sectors': ['energy', 'oil_gas', 'infrastructure'],
            'payment_method': 'bitcoin'
        },
        'maze': {
            'aliases': ['maze', 'egregor'],
            'target_sectors': ['government', 'healthcare', 'education'],
            'payment_method': 'bitcoin'
        }
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: str):
        super().__init__(config, cache_dir, "ransomwhere_processor")
        
        self.logger = get_logger(f"{__name__}.RansomwhereProcessor")
        
        # Load configuration
        crime_config = config.get('historical_crime_data', {})
        ransomware_config = crime_config.get('ransomware', {})
        
        self.dataset_path = ransomware_config.get('dataset_path', 'data/ransomware/')
        self.auto_update = ransomware_config.get('auto_update', True)
        self.include_seized = ransomware_config.get('include_seized_addresses', True)
        self.min_confidence = ransomware_config.get('min_confidence_threshold', 0.7)
        
        # Create data directory
        os.makedirs(self.dataset_path, exist_ok=True)
        
        # Rate limiting for API calls
        rate_config = config.get('rate_limiting', {})
        self.request_delay = rate_config.get('ransomwhere_delay_seconds', 1.0)
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Have-I-Been-Rekt-Ransomware-Analyzer/1.0'
        })
        
        # In-memory database
        self.ransomware_addresses = {}
        self.malware_families = {}
        
        # Initialize dataset
        self._initialize_dataset()
        
        self.logger.info(f"Initialized Ransomwhere Processor ({len(self.ransomware_addresses)} addresses loaded)")
    
    def _initialize_dataset(self):
        """Initialize ransomware dataset"""
        
        try:
            # Try to load existing dataset
            dataset_file = Path(self.dataset_path) / 'ransomware_addresses.json'
            
            if dataset_file.exists():
                self.logger.info("Loading existing ransomware dataset")
                self._load_dataset_from_file(str(dataset_file))
            else:
                self.logger.info("No existing dataset found")
            
            # Update dataset if auto-update is enabled
            if self.auto_update:
                self.logger.info("Auto-updating ransomware dataset")
                self._update_dataset()
            
        except Exception as e:
            self.logger.error(f"Error initializing dataset: {e}")
    
    def _load_dataset_from_file(self, file_path: str):
        """Load dataset from local file"""
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Parse addresses
            for addr_data in data.get('addresses', []):
                self._parse_address_record(addr_data)
            
            # Parse families
            for family_data in data.get('families', []):
                self._parse_family_record(family_data)
                
        except Exception as e:
            self.logger.error(f"Error loading dataset from file: {e}")
    
    def _parse_address_record(self, addr_data: Dict[str, Any]):
        """Parse and store address record"""
        
        try:
            address = RansomwareAddress(
                address=addr_data.get('address', ''),
                cryptocurrency=addr_data.get('cryptocurrency', 'BTC'),
                malware_family=addr_data.get('malware_family', 'unknown'),
                campaign_id=addr_data.get('campaign_id'),
                first_seen=datetime.fromisoformat(addr_data.get('first_seen', '2020-01-01T00:00:00Z')),
                last_seen=datetime.fromisoformat(addr_data.get('last_seen', '2020-01-01T00:00:00Z')),
                payment_count=addr_data.get('payment_count', 0),
                total_amount=Decimal(str(addr_data.get('total_amount', '0'))),
                total_amount_usd=Decimal(str(addr_data.get('total_amount_usd', '0'))) if addr_data.get('total_amount_usd') else None,
                victim_count=addr_data.get('victim_count'),
                status=addr_data.get('status', 'unknown'),
                source_confidence=addr_data.get('source_confidence', 0.5),
                attribution_notes=addr_data.get('attribution_notes', '')
            )
            
            self.ransomware_addresses[address.address] = address
            
        except Exception as e:
            self.logger.error(f"Error parsing address record: {e}")
    
    def _parse_family_record(self, family_data: Dict[str, Any]):
        """Parse and store malware family record"""
        
        try:
            family = RansomwareFamily(
                name=family_data.get('name', ''),
                aliases=family_data.get('aliases', []),
                first_seen=datetime.fromisoformat(family_data.get('first_seen', '2020-01-01T00:00:00Z')),
                last_activity=datetime.fromisoformat(family_data.get('last_activity', '2020-01-01T00:00:00Z')),
                total_addresses=family_data.get('total_addresses', 0),
                total_payments_usd=Decimal(str(family_data.get('total_payments_usd', '0'))),
                victim_count=family_data.get('victim_count', 0),
                target_sectors=family_data.get('target_sectors', []),
                payment_methods=family_data.get('payment_methods', ['bitcoin']),
                average_demand_usd=Decimal(str(family_data.get('average_demand_usd', '0'))) if family_data.get('average_demand_usd') else None,
                description=family_data.get('description', '')
            )
            
            self.malware_families[family.name] = family
            
        except Exception as e:
            self.logger.error(f"Error parsing family record: {e}")
    
    def _update_dataset(self) -> bool:
        """Update dataset from remote sources"""
        
        try:
            self.logger.info("Updating ransomware dataset from remote sources")
            
            # Try to fetch from Ransomwhere API
            success = self._fetch_from_api()
            
            if not success:
                # Fallback to static dataset
                success = self._fetch_static_dataset()
            
            if success:
                # Save updated dataset
                self._save_dataset()
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error updating dataset: {e}")
            return False
    
    def _fetch_from_api(self) -> bool:
        """Fetch data from Ransomwhere API"""
        
        try:
            # Note: This is a placeholder - actual Ransomwhere API may have different endpoints
            response = self.session.get(f"{self.RANSOMWHERE_API}/addresses", timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for addr_data in data.get('addresses', []):
                    self._parse_address_record(addr_data)
                
                return True
            else:
                self.logger.warning(f"Ransomwhere API returned status {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error fetching from Ransomwhere API: {e}")
            return False
    
    def _fetch_static_dataset(self) -> bool:
        """Fetch static dataset from GitHub"""
        
        try:
            response = self.session.get(self.DATASET_URL, timeout=30)
            
            if response.status_code == 200:
                # Parse CSV or JSON format
                content = response.text
                
                # Try JSON first
                try:
                    data = json.loads(content)
                    for addr_data in data:
                        self._normalize_and_parse_record(addr_data)
                    return True
                except json.JSONDecodeError:
                    # Try CSV format
                    return self._parse_csv_dataset(content)
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error fetching static dataset: {e}")
            return False
    
    def _normalize_and_parse_record(self, raw_data: Dict[str, Any]):
        """Normalize and parse a raw dataset record"""
        
        try:
            # Normalize common field variations
            address = raw_data.get('address') or raw_data.get('wallet') or raw_data.get('btc_address')
            if not address:
                return
            
            malware_family = (raw_data.get('malware') or 
                            raw_data.get('family') or 
                            raw_data.get('ransomware') or 
                            'unknown').lower()
            
            # Map known family aliases
            for family, info in self.RANSOMWARE_FAMILIES.items():
                if malware_family in info['aliases']:
                    malware_family = family
                    break
            
            # Create standardized record
            normalized = {
                'address': address,
                'cryptocurrency': self._detect_cryptocurrency(address),
                'malware_family': malware_family,
                'campaign_id': raw_data.get('campaign'),
                'first_seen': self._parse_date(raw_data.get('first_seen') or raw_data.get('date')),
                'last_seen': self._parse_date(raw_data.get('last_seen') or raw_data.get('date')),
                'payment_count': self._parse_int(raw_data.get('payments') or raw_data.get('tx_count'), 1),
                'total_amount': self._parse_decimal(raw_data.get('amount') or raw_data.get('btc_amount'), '0'),
                'total_amount_usd': self._parse_decimal(raw_data.get('amount_usd'), None),
                'victim_count': self._parse_int(raw_data.get('victims'), None),
                'status': raw_data.get('status', 'active'),
                'source_confidence': self._parse_float(raw_data.get('confidence'), 0.8),
                'attribution_notes': raw_data.get('notes', '')
            }
            
            self._parse_address_record(normalized)
            
        except Exception as e:
            self.logger.error(f"Error normalizing record: {e}")
    
    def _parse_csv_dataset(self, csv_content: str) -> bool:
        """Parse CSV format dataset"""
        
        try:
            lines = csv_content.strip().split('\n')
            if len(lines) < 2:
                return False
            
            # Detect CSV format
            reader = csv.DictReader(lines)
            
            for row in reader:
                self._normalize_and_parse_record(row)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error parsing CSV dataset: {e}")
            return False
    
    def _detect_cryptocurrency(self, address: str) -> str:
        """Detect cryptocurrency type from address format"""
        
        if address.startswith('1') or address.startswith('3') or address.startswith('bc1'):
            return 'BTC'
        elif address.startswith('0x') and len(address) == 42:
            return 'ETH'
        elif address.startswith('L'):
            return 'LTC'
        else:
            return 'BTC'  # Default assumption
    
    def _parse_date(self, date_str: Optional[str]) -> datetime:
        """Parse date string to datetime"""
        
        if not date_str:
            return datetime(2020, 1, 1, tzinfo=timezone.utc)
        
        try:
            # Try various date formats
            for fmt in ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S']:
                try:
                    return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
            
            # Default fallback
            return datetime(2020, 1, 1, tzinfo=timezone.utc)
            
        except Exception:
            return datetime(2020, 1, 1, tzinfo=timezone.utc)
    
    def _parse_int(self, value: Any, default: Optional[int]) -> Optional[int]:
        """Parse integer value"""
        try:
            return int(float(value)) if value else default
        except (ValueError, TypeError):
            return default
    
    def _parse_decimal(self, value: Any, default: Optional[str]) -> Optional[Decimal]:
        """Parse decimal value"""
        try:
            return Decimal(str(value)) if value else (Decimal(default) if default else None)
        except (ValueError, TypeError):
            return Decimal(default) if default else None
    
    def _parse_float(self, value: Any, default: float) -> float:
        """Parse float value"""
        try:
            return float(value) if value else default
        except (ValueError, TypeError):
            return default
    
    def _save_dataset(self):
        """Save dataset to local file"""
        
        try:
            dataset_file = Path(self.dataset_path) / 'ransomware_addresses.json'
            
            # Prepare data for serialization
            data = {
                'addresses': [],
                'families': [],
                'metadata': {
                    'last_updated': datetime.now(timezone.utc).isoformat(),
                    'total_addresses': len(self.ransomware_addresses),
                    'total_families': len(self.malware_families)
                }
            }
            
            # Convert addresses to serializable format
            for address in self.ransomware_addresses.values():
                addr_dict = {
                    'address': address.address,
                    'cryptocurrency': address.cryptocurrency,
                    'malware_family': address.malware_family,
                    'campaign_id': address.campaign_id,
                    'first_seen': address.first_seen.isoformat(),
                    'last_seen': address.last_seen.isoformat(),
                    'payment_count': address.payment_count,
                    'total_amount': str(address.total_amount),
                    'total_amount_usd': str(address.total_amount_usd) if address.total_amount_usd else None,
                    'victim_count': address.victim_count,
                    'status': address.status,
                    'source_confidence': address.source_confidence,
                    'attribution_notes': address.attribution_notes
                }
                data['addresses'].append(addr_dict)
            
            # Convert families to serializable format
            for family in self.malware_families.values():
                family_dict = {
                    'name': family.name,
                    'aliases': family.aliases,
                    'first_seen': family.first_seen.isoformat(),
                    'last_activity': family.last_activity.isoformat(),
                    'total_addresses': family.total_addresses,
                    'total_payments_usd': str(family.total_payments_usd),
                    'victim_count': family.victim_count,
                    'target_sectors': family.target_sectors,
                    'payment_methods': family.payment_methods,
                    'average_demand_usd': str(family.average_demand_usd) if family.average_demand_usd else None,
                    'description': family.description
                }
                data['families'].append(family_dict)
            
            # Save to file
            with open(dataset_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.logger.info(f"Dataset saved to {dataset_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving dataset: {e}")
    
    def lookup_ransomware_address(self, address: str) -> Optional[RansomwareIntelligence]:
        """
        Lookup ransomware intelligence for an address.
        
        Args:
            address: Cryptocurrency address to check
            
        Returns:
            RansomwareIntelligence if address is associated with ransomware
        """
        
        # Direct lookup
        ransomware_data = self.ransomware_addresses.get(address)
        
        if not ransomware_data:
            return None
        
        # Build intelligence report
        malware_families = [ransomware_data.malware_family]
        campaign_attribution = []
        if ransomware_data.campaign_id:
            campaign_attribution.append(ransomware_data.campaign_id)
        
        # Payment history
        payment_history = {
            'total_payments': ransomware_data.payment_count,
            'total_amount': str(ransomware_data.total_amount),
            'total_amount_usd': str(ransomware_data.total_amount_usd) if ransomware_data.total_amount_usd else None,
            'first_payment': ransomware_data.first_seen.isoformat(),
            'last_payment': ransomware_data.last_seen.isoformat()
        }
        
        # Threat assessment
        threat_assessment = self._assess_ransomware_threat(ransomware_data)
        
        # Find related addresses (same campaign/family)
        related_addresses = set()
        for addr, data in self.ransomware_addresses.items():
            if (addr != address and 
                (data.malware_family == ransomware_data.malware_family or
                 data.campaign_id == ransomware_data.campaign_id)):
                related_addresses.add(addr)
        
        intelligence = RansomwareIntelligence(
            address=address,
            is_ransomware_address=True,
            malware_families=malware_families,
            campaign_attribution=campaign_attribution,
            payment_history=payment_history,
            threat_assessment=threat_assessment,
            related_addresses=related_addresses,
            analysis_timestamp=datetime.now(timezone.utc)
        )
        
        return intelligence
    
    def _assess_ransomware_threat(self, ransomware_data: RansomwareAddress) -> Dict[str, Any]:
        """Assess threat level for ransomware address"""
        
        threat_score = 0.7  # Base score for confirmed ransomware
        
        # Adjust based on malware family
        family_info = self.RANSOMWARE_FAMILIES.get(ransomware_data.malware_family, {})
        if 'healthcare' in family_info.get('target_sectors', []):
            threat_score += 0.1  # Higher threat for healthcare targeting
        
        # Adjust based on activity level
        if ransomware_data.payment_count > 10:
            threat_score += 0.1
        
        if ransomware_data.total_amount_usd and ransomware_data.total_amount_usd > 100000:
            threat_score += 0.1
        
        # Adjust based on recency
        days_since_last_activity = (datetime.now(timezone.utc) - ransomware_data.last_seen).days
        if days_since_last_activity < 30:
            threat_score += 0.1
        elif days_since_last_activity > 365:
            threat_score -= 0.2
        
        # Determine threat level
        if threat_score >= 0.9:
            threat_level = 'critical'
        elif threat_score >= 0.7:
            threat_level = 'high'
        elif threat_score >= 0.5:
            threat_level = 'medium'
        else:
            threat_level = 'low'
        
        return {
            'threat_level': threat_level,
            'threat_score': min(threat_score, 1.0),
            'malware_family': ransomware_data.malware_family,
            'target_sectors': family_info.get('target_sectors', []),
            'status': ransomware_data.status,
            'confidence': ransomware_data.source_confidence,
            'days_since_activity': days_since_last_activity
        }
    
    def get_family_statistics(self) -> Dict[str, Any]:
        """Get statistics by malware family"""
        
        family_stats = {}
        
        for family_name in self.RANSOMWARE_FAMILIES.keys():
            family_addresses = [addr for addr in self.ransomware_addresses.values() 
                             if addr.malware_family == family_name]
            
            if family_addresses:
                total_usd = sum(addr.total_amount_usd or Decimal('0') for addr in family_addresses)
                
                family_stats[family_name] = {
                    'address_count': len(family_addresses),
                    'total_payments_usd': str(total_usd),
                    'average_payment_usd': str(total_usd / len(family_addresses)),
                    'most_recent_activity': max(addr.last_seen for addr in family_addresses).isoformat(),
                    'status_distribution': {}
                }
                
                # Status distribution
                statuses = {}
                for addr in family_addresses:
                    statuses[addr.status] = statuses.get(addr.status, 0) + 1
                family_stats[family_name]['status_distribution'] = statuses
        
        return family_stats
    
    def lookup_address(self, address: str) -> Dict[str, Any]:
        """
        Main interface for ransomware address analysis.
        
        Args:
            address: Cryptocurrency address to analyze
            
        Returns:
            Dictionary containing ransomware analysis results
        """
        
        try:
            self.logger.info(f"Analyzing ransomware association: {address[:10]}...")
            
            intelligence = self.lookup_ransomware_address(address)
            
            if not intelligence:
                return {
                    'found_ransomware_data': False,
                    'is_ransomware_address': False
                }
            
            # Build result dictionary
            result = {
                'found_ransomware_data': True,
                'is_ransomware_address': intelligence.is_ransomware_address,
                'malware_families': intelligence.malware_families,
                'campaign_attribution': intelligence.campaign_attribution,
                'payment_history': intelligence.payment_history,
                'threat_assessment': intelligence.threat_assessment,
                'related_addresses_count': len(intelligence.related_addresses),
                'analysis_timestamp': intelligence.analysis_timestamp.isoformat()
            }
            
            self.logger.info(f"Ransomware analysis completed: {address[:10]}... (families: {intelligence.malware_families})")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in ransomware analysis for {address}: {e}")
            return {
                'found_ransomware_data': False,
                'error': str(e)
            }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List:
        """Parse ransomware data into risk factors for ML training"""
        
        # Import here to avoid circular imports
        from ..data_collector import RiskFactor, RiskLevel, DataSourceType
        
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_ransomware_data'):
            return risk_factors
        
        if raw_data.get('is_ransomware_address'):
            threat_assessment = raw_data.get('threat_assessment', {})
            threat_level_str = threat_assessment.get('threat_level', 'medium')
            threat_score = threat_assessment.get('threat_score', 0.7)
            malware_family = threat_assessment.get('malware_family', 'unknown')
            
            # Map threat level to RiskLevel enum
            threat_level_map = {
                'low': RiskLevel.MEDIUM,  # Ransomware is always at least medium risk
                'medium': RiskLevel.HIGH,
                'high': RiskLevel.HIGH,
                'critical': RiskLevel.CRITICAL
            }
            
            risk_level = threat_level_map.get(threat_level_str, RiskLevel.HIGH)
            
            # Main ransomware risk factor
            risk_factors.append(RiskFactor(
                type="ransomware_address",
                description=f"Confirmed ransomware address ({malware_family} family)",
                risk_level=risk_level,
                confidence=threat_assessment.get('confidence', 0.9),
                source=DataSourceType.CRIME_DATABASE,
                raw_data={'malware_family': malware_family, 'threat_score': threat_score}
            ))
            
            # Payment volume risk
            payment_history = raw_data.get('payment_history', {})
            total_payments = payment_history.get('total_payments', 0)
            
            if total_payments > 5:
                risk_factors.append(RiskFactor(
                    type="high_volume_ransomware",
                    description=f"High-volume ransomware address ({total_payments} payments)",
                    risk_level=RiskLevel.CRITICAL,
                    confidence=0.95,
                    source=DataSourceType.CRIME_DATABASE,
                    raw_data={'payment_count': total_payments}
                ))
        
        return risk_factors
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get Ransomwhere processor statistics"""
        
        return {
            'total_addresses': len(self.ransomware_addresses),
            'total_families': len(set(addr.malware_family for addr in self.ransomware_addresses.values())),
            'family_distribution': self.get_family_statistics(),
            'dataset_path': self.dataset_path,
            'auto_update_enabled': self.auto_update,
            'min_confidence_threshold': self.min_confidence,
            'cache_entries': len(self.cache) if hasattr(self.cache, '__len__') else 'unknown'
        }