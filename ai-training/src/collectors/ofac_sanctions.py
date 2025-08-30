"""
OFAC (Office of Foreign Assets Control) Sanctions Data Collector.
Parses the official U.S. Treasury SDN (Specially Designated Nationals) list 
to extract sanctioned cryptocurrency addresses and entities.
"""

import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
import logging

import requests

from ..data_collector import BaseDataCollector, RiskFactor, RiskLevel, DataSourceType
from ..utils.logging import LoggingMixin


@dataclass
class SanctionedEntity:
    """Represents a sanctioned entity from OFAC SDN list"""
    uid: str
    entity_type: str  # Individual, Entity, Vessel, Aircraft
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    title: Optional[str] = None
    programs: List[str] = None
    addresses: List[str] = None  # Physical addresses
    crypto_addresses: List[str] = None  # Cryptocurrency addresses
    remarks: Optional[str] = None
    date_of_birth: Optional[str] = None
    place_of_birth: Optional[str] = None
    
    def __post_init__(self):
        if self.programs is None:
            self.programs = []
        if self.addresses is None:
            self.addresses = []
        if self.crypto_addresses is None:
            self.crypto_addresses = []
    
    @property
    def display_name(self) -> str:
        """Get display name for entity"""
        if self.entity_type == "Individual" and self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.title:
            return self.title
        else:
            return f"Entity {self.uid}"
    
    @property
    def primary_program(self) -> str:
        """Get primary sanctions program"""
        return self.programs[0] if self.programs else "Unknown"


class OFACSanctionsCollector(BaseDataCollector, LoggingMixin):
    """Collector for OFAC sanctions data"""
    
    # OFAC SDN XML URL
    SDN_URL = "https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml"
    
    # Crypto address patterns
    CRYPTO_PATTERNS = {
        'bitcoin': [
            r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',  # Legacy addresses
            r'\bbc1[a-z0-9]{39,59}\b',  # Bech32 addresses
        ],
        'ethereum': [
            r'\b0x[a-fA-F0-9]{40}\b',  # Ethereum addresses
        ],
        'litecoin': [
            r'\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b',  # Litecoin addresses
        ],
        'monero': [
            r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',  # Monero addresses
        ],
        'zcash': [
            r'\bt1[a-zA-Z0-9]{33}\b',  # Zcash transparent addresses
            r'\bzs1[a-z0-9]{75}\b',   # Zcash shielded addresses
        ]
    }
    
    def __init__(self, config: Dict[str, Any], cache_dir: Optional[str] = None, 
                 logger: Optional[logging.Logger] = None):
        super().__init__(config, cache_dir, logger)
        self.sanctioned_entities: Dict[str, SanctionedEntity] = {}
        self.crypto_address_index: Dict[str, str] = {}  # address -> entity_uid
        self.last_update: Optional[datetime] = None
        
    @property
    def source_name(self) -> str:
        return "ofac_sanctions"
    
    @property
    def data_source_type(self) -> DataSourceType:
        return DataSourceType.SANCTIONS
    
    def should_update(self) -> bool:
        """Check if data should be updated based on configured interval"""
        if not self.last_update:
            return True
        
        source_config = self.config.get('data_sources', {}).get(self.source_name, {})
        update_interval = source_config.get('update_interval_hours', 24)
        
        return datetime.utcnow() - self.last_update > timedelta(hours=update_interval)
    
    def download_sdn_data(self) -> Optional[str]:
        """Download latest SDN XML data from OFAC"""
        try:
            self.logger.info("Downloading OFAC SDN data", url=self.SDN_URL)
            
            response = self.make_request(
                url=self.SDN_URL,
                timeout=120  # Large file, allow more time
            )
            
            if response and 'text' in response:
                xml_content = response['text']
                self.logger.info(
                    "SDN data downloaded successfully", 
                    size_kb=len(xml_content) // 1024
                )
                return xml_content
            else:
                self.logger.error("Failed to download SDN data")
                return None
                
        except Exception as e:
            self.logger.error("Error downloading SDN data", error=str(e))
            return None
    
    def extract_crypto_addresses(self, text: str) -> List[Dict[str, str]]:
        """Extract cryptocurrency addresses from text using regex patterns"""
        found_addresses = []
        
        for crypto_type, patterns in self.CRYPTO_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    found_addresses.append({
                        'address': match,
                        'type': crypto_type,
                        'source_text': text[:200] + '...' if len(text) > 200 else text
                    })
        
        return found_addresses
    
    def parse_sdn_xml(self, xml_content: str) -> List[SanctionedEntity]:
        """Parse SDN XML and extract entities with crypto addresses"""
        entities = []
        
        try:
            root = ET.fromstring(xml_content)
            
            # Find all SDN entries
            for sdn_entry in root.findall('.//{http://tempuri.org/sdnList.xsd}sdnEntry'):
                entity = self._parse_sdn_entry(sdn_entry)
                if entity:
                    entities.append(entity)
            
            self.logger.info(
                "Parsed SDN XML successfully",
                total_entities=len(entities),
                entities_with_crypto=len([e for e in entities if e.crypto_addresses])
            )
            
        except ET.ParseError as e:
            self.logger.error("XML parsing error", error=str(e))
        except Exception as e:
            self.logger.error("Error parsing SDN XML", error=str(e))
        
        return entities
    
    def _parse_sdn_entry(self, sdn_entry) -> Optional[SanctionedEntity]:
        """Parse individual SDN entry"""
        try:
            # Extract basic info
            uid = self._get_element_text(sdn_entry, 'uid')
            if not uid:
                return None
            
            entity = SanctionedEntity(
                uid=uid,
                entity_type=self._get_element_text(sdn_entry, 'sdnType') or 'Unknown',
                first_name=self._get_element_text(sdn_entry, 'firstName'),
                last_name=self._get_element_text(sdn_entry, 'lastName'),
                title=self._get_element_text(sdn_entry, 'title')
            )
            
            # Extract programs
            program_list = sdn_entry.find('.//{http://tempuri.org/sdnList.xsd}programList')
            if program_list is not None:
                for program in program_list.findall('.//{http://tempuri.org/sdnList.xsd}program'):
                    if program.text:
                        entity.programs.append(program.text.strip())
            
            # Extract addresses and look for crypto addresses
            address_list = sdn_entry.find('.//{http://tempuri.org/sdnList.xsd}addressList')
            if address_list is not None:
                for address in address_list.findall('.//{http://tempuri.org/sdnList.xsd}address'):
                    # Get full address text
                    address_lines = []
                    for field in ['address1', 'address2', 'address3', 'city', 'stateOrProvince', 'country']:
                        value = self._get_element_text(address, field)
                        if value:
                            address_lines.append(value)
                    
                    full_address = ', '.join(address_lines)
                    if full_address:
                        entity.addresses.append(full_address)
                    
                    # Check address remarks for crypto addresses
                    remarks = self._get_element_text(address, 'addressRemarks')
                    if remarks:
                        crypto_addresses = self.extract_crypto_addresses(remarks)
                        for crypto_addr in crypto_addresses:
                            entity.crypto_addresses.append(crypto_addr['address'])
            
            # Extract date of birth
            dob_list = sdn_entry.find('.//{http://tempuri.org/sdnList.xsd}dateOfBirthList')
            if dob_list is not None:
                dob_item = dob_list.find('.//{http://tempuri.org/sdnList.xsd}dateOfBirthItem')
                if dob_item is not None:
                    entity.date_of_birth = self._get_element_text(dob_item, 'dateOfBirth')
            
            # Extract place of birth  
            pob_list = sdn_entry.find('.//{http://tempuri.org/sdnList.xsd}placeOfBirthList')
            if pob_list is not None:
                pob_item = pob_list.find('.//{http://tempuri.org/sdnList.xsd}placeOfBirthItem')
                if pob_item is not None:
                    entity.place_of_birth = self._get_element_text(pob_item, 'placeOfBirth')
            
            return entity
            
        except Exception as e:
            self.logger.error("Error parsing SDN entry", uid=uid if 'uid' in locals() else 'unknown', error=str(e))
            return None
    
    def _get_element_text(self, parent, tag_name: str) -> Optional[str]:
        """Helper to get text content of XML element"""
        element = parent.find(f'.//{{{http://tempuri.org/sdnList.xsd}}}{tag_name}')
        return element.text.strip() if element is not None and element.text else None
    
    def update_data(self) -> bool:
        """Download and parse latest OFAC data"""
        if not self.should_update():
            self.logger.info("OFAC data is up to date, skipping update")
            return True
        
        # Download SDN data
        xml_content = self.download_sdn_data()
        if not xml_content:
            return False
        
        # Parse entities
        entities = self.parse_sdn_xml(xml_content)
        if not entities:
            self.logger.error("No entities parsed from SDN data")
            return False
        
        # Update internal data structures
        self.sanctioned_entities.clear()
        self.crypto_address_index.clear()
        
        crypto_count = 0
        for entity in entities:
            self.sanctioned_entities[entity.uid] = entity
            
            # Index crypto addresses
            for crypto_addr in entity.crypto_addresses:
                self.crypto_address_index[crypto_addr.lower()] = entity.uid
                crypto_count += 1
        
        self.last_update = datetime.utcnow()
        
        self.logger.info(
            "OFAC data updated successfully",
            total_entities=len(entities),
            crypto_addresses=crypto_count,
            update_time=self.last_update.isoformat()
        )
        
        # Cache the processed data
        cache_data = {
            'entities': {uid: {
                'uid': entity.uid,
                'entity_type': entity.entity_type,
                'display_name': entity.display_name,
                'programs': entity.programs,
                'crypto_addresses': entity.crypto_addresses,
                'date_of_birth': entity.date_of_birth,
                'place_of_birth': entity.place_of_birth
            } for uid, entity in self.sanctioned_entities.items()},
            'crypto_index': self.crypto_address_index,
            'last_update': self.last_update.isoformat()
        }
        self.cache_result('ofac_data', cache_data)
        
        return True
    
    def load_cached_data(self) -> bool:
        """Load previously cached OFAC data"""
        cached_data = self.get_cached_result('ofac_data')
        if not cached_data:
            return False
        
        try:
            # Reconstruct entities from cached data
            self.sanctioned_entities.clear()
            entities_data = cached_data.get('entities', {})
            
            for uid, entity_data in entities_data.items():
                entity = SanctionedEntity(
                    uid=entity_data['uid'],
                    entity_type=entity_data['entity_type'],
                    programs=entity_data.get('programs', []),
                    crypto_addresses=entity_data.get('crypto_addresses', []),
                    date_of_birth=entity_data.get('date_of_birth'),
                    place_of_birth=entity_data.get('place_of_birth')
                )
                self.sanctioned_entities[uid] = entity
            
            self.crypto_address_index = cached_data.get('crypto_index', {})
            
            # Parse last update time
            last_update_str = cached_data.get('last_update')
            if last_update_str:
                self.last_update = datetime.fromisoformat(last_update_str)
            
            self.logger.info(
                "Loaded cached OFAC data",
                entities=len(self.sanctioned_entities),
                crypto_addresses=len(self.crypto_address_index),
                cache_age_hours=(datetime.utcnow() - self.last_update).total_seconds() / 3600 if self.last_update else None
            )
            
            return True
            
        except Exception as e:
            self.logger.error("Error loading cached OFAC data", error=str(e))
            return False
    
    def ensure_data_loaded(self) -> bool:
        """Ensure OFAC data is loaded and up to date"""
        # Try loading cached data first
        if self.load_cached_data() and not self.should_update():
            return True
        
        # Update data if needed
        return self.update_data()
    
    def collect_address_data(self, address: str) -> Optional[Dict[str, Any]]:
        """Check if address is sanctioned"""
        # Ensure data is loaded
        if not self.ensure_data_loaded():
            self.logger.error("Failed to load OFAC data")
            return None
        
        # Normalize address for lookup
        normalized_address = address.lower().strip()
        
        # Check if address is sanctioned
        entity_uid = self.crypto_address_index.get(normalized_address)
        if not entity_uid:
            return {
                'address': address,
                'sanctioned': False,
                'entity': None,
                'source': self.source_name
            }
        
        # Get entity details
        entity = self.sanctioned_entities.get(entity_uid)
        if not entity:
            self.logger.warning("Entity not found for sanctioned address", 
                              address=address, entity_uid=entity_uid)
            return None
        
        return {
            'address': address,
            'sanctioned': True,
            'entity': {
                'uid': entity.uid,
                'name': entity.display_name,
                'type': entity.entity_type,
                'programs': entity.programs,
                'primary_program': entity.primary_program,
                'date_of_birth': entity.date_of_birth,
                'place_of_birth': entity.place_of_birth
            },
            'source': self.source_name,
            'last_updated': self.last_update.isoformat() if self.last_update else None
        }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List[RiskFactor]:
        """Parse OFAC data into risk factors"""
        risk_factors = []
        
        if not raw_data or not raw_data.get('sanctioned'):
            # No sanctions found - this is clean
            return risk_factors
        
        entity = raw_data.get('entity', {})
        primary_program = entity.get('primary_program', 'Unknown')
        entity_name = entity.get('name', 'Unknown Entity')
        
        # Create critical risk factor for sanctions
        risk_factors.append(RiskFactor(
            source=self.source_name,
            factor_type="sanctions",
            severity=RiskLevel.CRITICAL,
            weight=1.0,  # Maximum weight for sanctions
            description=f"Address sanctioned by OFAC under {primary_program} program",
            reference_url="https://ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists",
            confidence=1.0,  # Official government data
            report_count=1
        ))
        
        self.logger.warning(
            "CRITICAL: Sanctioned address detected",
            address=address,
            entity_name=entity_name,
            program=primary_program,
            entity_uid=entity.get('uid')
        )
        
        return risk_factors
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about loaded OFAC data"""
        if not self.ensure_data_loaded():
            return {'error': 'Failed to load data'}
        
        program_counts = {}
        entity_type_counts = {}
        
        for entity in self.sanctioned_entities.values():
            # Count by primary program
            primary_program = entity.primary_program
            program_counts[primary_program] = program_counts.get(primary_program, 0) + 1
            
            # Count by entity type
            entity_type_counts[entity.entity_type] = entity_type_counts.get(entity.entity_type, 0) + 1
        
        return {
            'total_entities': len(self.sanctioned_entities),
            'crypto_addresses': len(self.crypto_address_index),
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'program_breakdown': program_counts,
            'entity_type_breakdown': entity_type_counts,
            'top_programs': sorted(program_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        }
    
    def search_entities(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search sanctioned entities by name or other criteria"""
        if not self.ensure_data_loaded():
            return []
        
        query_lower = query.lower()
        results = []
        
        for entity in self.sanctioned_entities.values():
            # Check if query matches entity name or programs
            if (query_lower in entity.display_name.lower() or 
                any(query_lower in program.lower() for program in entity.programs)):
                
                results.append({
                    'uid': entity.uid,
                    'name': entity.display_name,
                    'type': entity.entity_type,
                    'programs': entity.programs,
                    'crypto_addresses': entity.crypto_addresses,
                    'date_of_birth': entity.date_of_birth,
                    'place_of_birth': entity.place_of_birth
                })
                
                if len(results) >= limit:
                    break
        
        return results