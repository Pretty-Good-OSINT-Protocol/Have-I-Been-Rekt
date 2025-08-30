"""
Comprehensive tests for sanctions integration (OFAC + Chainalysis).
"""

import pytest
from unittest.mock import Mock, patch, mock_open
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET

from src.collectors.ofac_sanctions import OFACSanctionsCollector, SanctionedEntity
from src.collectors.chainalysis_client import ChainanalysisClient, ChainanalysisScreeningResult
from src.collectors.sanctions_aggregator import SanctionsAggregator
from src.data_collector import RiskLevel, RiskFactor


class TestOFACSanctionsCollector:
    """Test OFAC sanctions data collection and parsing"""
    
    @pytest.fixture
    def ofac_collector(self, test_config, temp_dir):
        """Create OFAC collector for testing"""
        return OFACSanctionsCollector(
            test_config,
            cache_dir=temp_dir
        )
    
    @pytest.fixture
    def sample_sdn_xml(self):
        """Sample OFAC SDN XML data"""
        return '''<?xml version="1.0" encoding="UTF-8"?>
        <sdnList xmlns="http://tempuri.org/sdnList.xsd">
            <sdnEntry>
                <uid>12345</uid>
                <firstName>Test</firstName>
                <lastName>Subject</lastName>
                <sdnType>Individual</sdnType>
                <programList>
                    <program>DPRK</program>
                    <program>CYBER2</program>
                </programList>
                <addressList>
                    <address>
                        <address1>123 Main St</address1>
                        <city>Pyongyang</city>
                        <country>North Korea</country>
                        <addressRemarks>Digital Currency Address - BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa; ETH 0x1234567890123456789012345678901234567890</addressRemarks>
                    </address>
                </addressList>
                <dateOfBirthList>
                    <dateOfBirthItem>
                        <dateOfBirth>01 Jan 1970</dateOfBirth>
                    </dateOfBirthItem>
                </dateOfBirthList>
            </sdnEntry>
            <sdnEntry>
                <uid>67890</uid>
                <title>Evil Corp</title>
                <sdnType>Entity</sdnType>
                <programList>
                    <program>CYBER2</program>
                </programList>
                <addressList>
                    <address>
                        <addressRemarks>Ethereum Address: 0xabcdefabcdefabcdefabcdefabcdefabcdefabcd</addressRemarks>
                    </address>
                </addressList>
            </sdnEntry>
        </sdnList>'''
    
    def test_crypto_address_extraction(self, ofac_collector):
        """Test crypto address pattern matching"""
        test_texts = [
            "Digital Currency Address - BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "ETH 0x1234567890123456789012345678901234567890",
            "Monero address: 4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRJ5z7gixFHRUGGjEPhw4JtsE6KbFi1qySjQoAL4YC",
            "Litecoin: LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1"
        ]
        
        for text in test_texts:
            addresses = ofac_collector.extract_crypto_addresses(text)
            assert len(addresses) > 0, f"Failed to extract address from: {text}"
            
            for addr_info in addresses:
                assert 'address' in addr_info
                assert 'type' in addr_info
                assert len(addr_info['address']) > 20  # Reasonable length check
    
    def test_sdn_xml_parsing(self, ofac_collector, sample_sdn_xml):
        """Test parsing of OFAC SDN XML"""
        entities = ofac_collector.parse_sdn_xml(sample_sdn_xml)
        
        assert len(entities) == 2
        
        # Check first entity (individual)
        entity1 = entities[0]
        assert entity1.uid == "12345"
        assert entity1.entity_type == "Individual"
        assert entity1.display_name == "Test Subject"
        assert "DPRK" in entity1.programs
        assert len(entity1.crypto_addresses) >= 2  # BTC and ETH addresses
        
        # Check second entity (organization)
        entity2 = entities[1]
        assert entity2.uid == "67890" 
        assert entity2.entity_type == "Entity"
        assert entity2.title == "Evil Corp"
        assert "CYBER2" in entity2.programs
        assert len(entity2.crypto_addresses) >= 1  # ETH address
    
    def test_address_lookup(self, ofac_collector, sample_sdn_xml):
        """Test address lookup functionality"""
        # Mock XML download
        with patch.object(ofac_collector, 'download_sdn_data', return_value=sample_sdn_xml):
            success = ofac_collector.update_data()
            assert success
        
        # Test sanctioned address lookup
        sanctioned_address = "0x1234567890123456789012345678901234567890"
        result = ofac_collector.collect_address_data(sanctioned_address)
        
        assert result is not None
        assert result['sanctioned'] is True
        assert result['entity']['name'] == "Test Subject"
        assert result['entity']['primary_program'] == "DPRK"
        
        # Test clean address lookup
        clean_address = "0x9999999999999999999999999999999999999999"
        result = ofac_collector.collect_address_data(clean_address)
        
        assert result is not None
        assert result['sanctioned'] is False
        assert result['entity'] is None
    
    def test_risk_factor_parsing(self, ofac_collector, sample_sdn_xml):
        """Test risk factor generation for sanctioned addresses"""
        # Set up collector with test data
        with patch.object(ofac_collector, 'download_sdn_data', return_value=sample_sdn_xml):
            ofac_collector.update_data()
        
        # Test sanctioned address
        sanctioned_address = "0x1234567890123456789012345678901234567890"
        raw_data = ofac_collector.collect_address_data(sanctioned_address)
        risk_factors = ofac_collector.parse_risk_factors(raw_data, sanctioned_address)
        
        assert len(risk_factors) == 1
        factor = risk_factors[0]
        assert factor.source == "ofac_sanctions"
        assert factor.factor_type == "sanctions"
        assert factor.severity == RiskLevel.CRITICAL
        assert factor.weight == 1.0
        assert factor.confidence == 1.0
        assert "DPRK" in factor.description
        
        # Test clean address
        clean_address = "0x9999999999999999999999999999999999999999"
        raw_data = ofac_collector.collect_address_data(clean_address)
        risk_factors = ofac_collector.parse_risk_factors(raw_data, clean_address)
        
        assert len(risk_factors) == 0  # No risk factors for clean address
    
    def test_caching_functionality(self, ofac_collector, sample_sdn_xml, temp_dir):
        """Test data caching and retrieval"""
        # First update - should download and cache
        with patch.object(ofac_collector, 'download_sdn_data', return_value=sample_sdn_xml) as mock_download:
            success = ofac_collector.update_data()
            assert success
            assert mock_download.called
        
        # Second call - should load from cache
        with patch.object(ofac_collector, 'download_sdn_data') as mock_download:
            loaded = ofac_collector.load_cached_data()
            assert loaded
            assert not mock_download.called
        
        # Verify cached data is correct
        assert len(ofac_collector.sanctioned_entities) == 2
        assert len(ofac_collector.crypto_address_index) >= 3
    
    def test_statistics_generation(self, ofac_collector, sample_sdn_xml):
        """Test statistics generation"""
        # Set up with test data
        with patch.object(ofac_collector, 'download_sdn_data', return_value=sample_sdn_xml):
            ofac_collector.update_data()
        
        stats = ofac_collector.get_statistics()
        
        assert 'total_entities' in stats
        assert 'crypto_addresses' in stats
        assert 'last_update' in stats
        assert 'program_breakdown' in stats
        assert 'top_programs' in stats
        
        assert stats['total_entities'] == 2
        assert stats['crypto_addresses'] >= 3
        assert 'DPRK' in stats['program_breakdown']
        assert 'CYBER2' in stats['program_breakdown']


class TestChainanalysisClient:
    """Test Chainalysis API client"""
    
    @pytest.fixture
    def chainalysis_client(self, test_config, temp_dir):
        """Create Chainalysis client for testing"""
        return ChainanalysisClient(
            test_config,
            cache_dir=temp_dir
        )
    
    @pytest.fixture
    def mock_chainalysis_responses(self):
        """Mock Chainalysis API responses"""
        return {
            'clean': {
                "address": "0x1234567890123456789012345678901234567890",
                "category": "unknown",
                "categoryId": "unknown"
            },
            'sanctioned': {
                "address": "0x0123456789abcdef0123456789abcdef01234567",
                "category": "sanctions",
                "categoryId": "sanctions",
                "description": "OFAC SDN",
                "url": "https://ofac.treasury.gov"
            },
            'high_risk': {
                "address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                "category": "scam",
                "categoryId": "scam",
                "clusterName": "Fake ICO Scam",
                "description": "Known scam address"
            }
        }
    
    def test_screening_result_parsing(self, chainalysis_client, mock_chainalysis_responses):
        """Test parsing of Chainalysis API responses"""
        # Test clean address
        clean_response = mock_chainalysis_responses['clean']
        result = chainalysis_client._parse_screening_response(
            "0x1234567890123456789012345678901234567890",
            clean_response
        )
        
        assert result.address == "0x1234567890123456789012345678901234567890"
        assert result.is_sanctioned is False
        assert result.category == "unknown"
        assert result.risk_score == 0.0
        
        # Test sanctioned address
        sanctioned_response = mock_chainalysis_responses['sanctioned']
        result = chainalysis_client._parse_screening_response(
            "0x0123456789abcdef0123456789abcdef01234567",
            sanctioned_response
        )
        
        assert result.is_sanctioned is True
        assert result.risk_score == 1.0
        assert result.confidence == 1.0
        assert "OFAC" in result.description
        
        # Test high-risk address
        scam_response = mock_chainalysis_responses['high_risk']
        result = chainalysis_client._parse_screening_response(
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            scam_response
        )
        
        assert result.is_sanctioned is False
        assert result.is_high_risk is True
        assert result.risk_score == 0.8  # High risk category
        assert result.cluster_name == "Fake ICO Scam"
    
    def test_address_screening(self, chainalysis_client, mock_requests, mock_chainalysis_responses):
        """Test address screening workflow"""
        test_address = "0x1234567890123456789012345678901234567890"
        
        # Mock API response
        mock_requests.get(
            f"{chainalysis_client.BASE_URL}{chainalysis_client.SCREENING_ENDPOINT}/{test_address}",
            json=mock_chainalysis_responses['clean']
        )
        
        result = chainalysis_client.screen_address(test_address)
        
        assert result is not None
        assert isinstance(result, ChainanalysisScreeningResult)
        assert result.address == test_address
        assert result.category == "unknown"
    
    def test_risk_factor_generation(self, chainalysis_client, mock_chainalysis_responses):
        """Test risk factor generation from Chainalysis data"""
        # Test sanctioned address risk factors
        sanctioned_data = {
            'screening_result': mock_chainalysis_responses['sanctioned'],
            'is_sanctioned': True,
            'category': 'sanctions',
            'category_id': 'sanctions',
            'risk_score': 1.0,
            'confidence': 1.0
        }
        
        risk_factors = chainalysis_client.parse_risk_factors(
            sanctioned_data, 
            "0x0123456789abcdef0123456789abcdef01234567"
        )
        
        assert len(risk_factors) == 1
        factor = risk_factors[0]
        assert factor.source == "chainalysis"
        assert factor.factor_type == "sanctions"
        assert factor.severity == RiskLevel.CRITICAL
        assert factor.weight == 0.9
        
        # Test high-risk non-sanctioned address
        scam_data = {
            'screening_result': mock_chainalysis_responses['high_risk'],
            'is_sanctioned': False,
            'category': 'scam',
            'category_id': 'scam',
            'risk_score': 0.8,
            'confidence': 0.9
        }
        
        risk_factors = chainalysis_client.parse_risk_factors(
            scam_data,
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        )
        
        assert len(risk_factors) == 1
        factor = risk_factors[0]
        assert factor.factor_type == "criminal_activity"
        assert factor.severity == RiskLevel.HIGH
    
    def test_api_key_validation(self, chainalysis_client, mock_requests, mock_chainalysis_responses):
        """Test API key validation"""
        # Mock successful validation
        test_address = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        mock_requests.get(
            f"{chainalysis_client.BASE_URL}{chainalysis_client.SCREENING_ENDPOINT}/{test_address}",
            json=mock_chainalysis_responses['clean']
        )
        
        is_valid = chainalysis_client.validate_api_key()
        assert is_valid is True
        
        # Test with no API key
        chainalysis_client.api_key = None
        is_valid = chainalysis_client.validate_api_key()
        assert is_valid is False
    
    def test_batch_screening(self, chainalysis_client, mock_requests, mock_chainalysis_responses):
        """Test batch address screening"""
        test_addresses = [
            "0x1234567890123456789012345678901234567890",
            "0x0123456789abcdef0123456789abcdef01234567"
        ]
        
        # Mock responses for each address
        for i, address in enumerate(test_addresses):
            response_key = 'clean' if i == 0 else 'sanctioned'
            mock_requests.get(
                f"{chainalysis_client.BASE_URL}{chainalysis_client.SCREENING_ENDPOINT}/{address}",
                json=mock_chainalysis_responses[response_key]
            )
        
        results = chainalysis_client.batch_screen_addresses(test_addresses)
        
        assert len(results) == 2
        assert all(addr in results for addr in test_addresses)
        assert results[test_addresses[0]].is_sanctioned is False
        assert results[test_addresses[1]].is_sanctioned is True


class TestSanctionsAggregator:
    """Test sanctions data aggregation"""
    
    @pytest.fixture
    def sanctions_aggregator(self, test_config, temp_dir):
        """Create sanctions aggregator for testing"""
        return SanctionsAggregator(
            test_config,
            cache_dir=temp_dir
        )
    
    def test_aggregator_initialization(self, sanctions_aggregator):
        """Test aggregator initialization and source detection"""
        assert sanctions_aggregator.source_name == "sanctions_aggregator"
        assert hasattr(sanctions_aggregator, 'ofac_collector')
        assert hasattr(sanctions_aggregator, 'chainalysis_client')
        assert hasattr(sanctions_aggregator, 'available_sources')
        
        # Should always have OFAC available
        assert 'ofac' in sanctions_aggregator.available_sources
    
    @patch('src.collectors.ofac_sanctions.OFACSanctionsCollector.collect_address_data')
    @patch('src.collectors.chainalysis_client.ChainanalysisClient.collect_address_data')
    def test_comprehensive_screening(self, mock_chainalysis, mock_ofac, sanctions_aggregator):
        """Test comprehensive address screening using both sources"""
        test_address = "0x1234567890123456789012345678901234567890"
        
        # Mock OFAC response (clean)
        mock_ofac.return_value = {
            'address': test_address,
            'sanctioned': False,
            'entity': None,
            'source': 'ofac_sanctions'
        }
        
        # Mock Chainalysis response (high risk)
        mock_chainalysis.return_value = {
            'address': test_address,
            'is_sanctioned': False,
            'category': 'scam',
            'risk_score': 0.8,
            'confidence': 0.9,
            'source': 'chainalysis'
        }
        
        result = sanctions_aggregator.collect_address_data(test_address)
        
        assert result is not None
        assert result['address'] == test_address
        assert result['sanctions_found'] is False  # Neither source found sanctions
        assert 'ofac' in result['sources_checked']
        assert result['ofac_result'] is not None
        assert result['chainalysis_result'] is not None
        
        # Check aggregated risk
        aggregated_risk = result['aggregated_risk']
        assert aggregated_risk['is_sanctioned'] is False
        assert aggregated_risk['risk_score'] > 0  # Should reflect Chainalysis risk
        assert aggregated_risk['confidence'] > 0
    
    @patch('src.collectors.ofac_sanctions.OFACSanctionsCollector.collect_address_data')
    def test_sanctions_detection(self, mock_ofac, sanctions_aggregator):
        """Test detection of sanctioned addresses"""
        test_address = "0x0123456789abcdef0123456789abcdef01234567"
        
        # Mock OFAC response (sanctioned)
        mock_ofac.return_value = {
            'address': test_address,
            'sanctioned': True,
            'entity': {
                'uid': '12345',
                'name': 'Test Subject',
                'type': 'Individual',
                'programs': ['DPRK'],
                'primary_program': 'DPRK'
            },
            'source': 'ofac_sanctions'
        }
        
        result = sanctions_aggregator.collect_address_data(test_address)
        
        assert result['sanctions_found'] is True
        assert result['aggregated_risk']['is_sanctioned'] is True
        assert result['aggregated_risk']['risk_score'] == 1.0  # Maximum risk
        assert 'ofac' in result['aggregated_risk']['sources']
        assert 'OFAC sanctions' in result['aggregated_risk']['primary_concern']
    
    def test_risk_factor_aggregation(self, sanctions_aggregator):
        """Test aggregation of risk factors from multiple sources"""
        test_address = "0x1234567890123456789012345678901234567890"
        
        # Mock aggregated data
        raw_data = {
            'address': test_address,
            'ofac_result': {
                'sanctioned': False,
                'entity': None
            },
            'chainalysis_result': {
                'is_sanctioned': False,
                'category': 'scam',
                'category_id': 'scam',
                'risk_score': 0.8,
                'confidence': 0.9
            },
            'sources_checked': ['ofac', 'chainalysis'],
            'aggregated_risk': {
                'risk_score': 0.8,
                'confidence': 0.9,
                'primary_concern': 'High-risk category (scam)'
            }
        }
        
        # Mock the individual collectors' parse methods
        with patch.object(sanctions_aggregator.ofac_collector, 'parse_risk_factors', return_value=[]):
            with patch.object(sanctions_aggregator.chainalysis_client, 'parse_risk_factors') as mock_chainalysis_parse:
                
                # Mock Chainalysis risk factor
                mock_chainalysis_parse.return_value = [
                    RiskFactor(
                        source="chainalysis",
                        factor_type="criminal_activity",
                        severity=RiskLevel.HIGH,
                        weight=0.9,
                        description="Address categorized as scam",
                        confidence=0.9
                    )
                ]
                
                risk_factors = sanctions_aggregator.parse_risk_factors(raw_data, test_address)
                
                # Should have Chainalysis factor plus multi-source summary
                assert len(risk_factors) >= 1
                
                # Check for multi-source summary factor
                summary_factors = [f for f in risk_factors if f.factor_type == "multi_source_analysis"]
                assert len(summary_factors) == 1
                
                summary_factor = summary_factors[0]
                assert summary_factor.source == "sanctions_aggregator"
                assert summary_factor.severity == RiskLevel.HIGH
                assert "Multi-source analysis" in summary_factor.description
    
    def test_coverage_statistics(self, sanctions_aggregator):
        """Test coverage statistics generation"""
        with patch.object(sanctions_aggregator.ofac_collector, 'get_statistics') as mock_ofac_stats:
            with patch.object(sanctions_aggregator.chainalysis_client, 'get_usage_stats') as mock_chainalysis_stats:
                
                mock_ofac_stats.return_value = {
                    'total_entities': 100,
                    'crypto_addresses': 50,
                    'last_update': '2024-01-01T00:00:00Z'
                }
                
                mock_chainalysis_stats.return_value = {
                    'cached_screenings': 25,
                    'api_key_configured': True,
                    'api_key_valid': True
                }
                
                stats = sanctions_aggregator.get_coverage_stats()
                
                assert 'available_sources' in stats
                assert 'coverage_percentage' in stats
                assert 'source_details' in stats
                assert 'ofac' in stats['source_details']
                
                if 'chainalysis' in sanctions_aggregator.available_sources:
                    assert 'chainalysis' in stats['source_details']