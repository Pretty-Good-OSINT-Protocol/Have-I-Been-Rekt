#!/usr/bin/env python3
"""
Comprehensive unit tests for community scam database collectors.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from datetime import datetime, timezone
import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from collectors.cryptoscamdb_collector import CryptoScamDBCollector, ScamReport
from collectors.chainabuse_scraper import ChainabuseScraper, ChainabuseReport  
from collectors.scamsearch_client import ScamSearchClient, ScamSearchEntry
from collectors.community_scam_aggregator import CommunityScamAggregator
from utils.config import get_config


class TestCryptoScamDBCollector:
    """Test CryptoScamDB GitHub API integration"""
    
    @pytest.fixture
    def mock_config(self):
        return {
            'community_scam_sources': {
                'cryptoscamdb': {
                    'enabled': True,
                    'github_token': 'test_token',
                    'cache_ttl_hours': 24
                }
            },
            'rate_limiting': {
                'github_requests_per_hour': 5000,
                'default_delay_seconds': 0.1
            }
        }
    
    @pytest.fixture
    def collector(self, mock_config):
        with patch('diskcache.Cache'):
            return CryptoScamDBCollector(mock_config, "/tmp/test_cache")
    
    @patch('requests.get')
    def test_fetch_github_file_success(self, mock_get, collector):
        """Test successful GitHub file fetching"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'content': 'eyJ0ZXN0IjogInZhbHVlIn0=',  # base64 encoded {"test": "value"}
            'encoding': 'base64'
        }
        mock_get.return_value = mock_response
        
        result = collector._fetch_github_file("test/path.json")
        
        assert result == {"test": "value"}
        mock_get.assert_called_once()
    
    @patch('requests.get')
    def test_fetch_github_file_404(self, mock_get, collector):
        """Test GitHub file not found"""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        result = collector._fetch_github_file("nonexistent/file.json")
        
        assert result is None
    
    def test_parse_addresses_from_entry(self, collector):
        """Test crypto address extraction from scam entries"""
        entry = {
            "addresses": {
                "BTC": ["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"],
                "ETH": ["0x742d35Cc6634C0532925a3b8D"]
            },
            "description": "Contains BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and ETH 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        }
        
        addresses = collector._parse_addresses_from_entry(entry)
        
        expected = {
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "0x742d35Cc6634C0532925a3b8D",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        }
        assert addresses == expected
    
    def test_build_scam_report(self, collector):
        """Test ScamReport creation from raw data"""
        raw_data = {
            "id": "test123",
            "name": "Test Scam",
            "category": "fake_exchange",
            "subcategory": "phishing_site",
            "description": "A test scam description",
            "addresses": {
                "BTC": ["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"]
            },
            "url": "https://example-scam.com"
        }
        
        report = collector._build_scam_report(raw_data)
        
        assert isinstance(report, ScamReport)
        assert report.scam_id == "test123"
        assert report.category == "fake_exchange"
        assert report.subcategory == "phishing_site"
        assert len(report.crypto_addresses) == 1
        assert "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" in report.crypto_addresses


class TestChainabuseScraper:
    """Test Chainabuse ethical web scraping"""
    
    @pytest.fixture
    def mock_config(self):
        return {
            'community_scam_sources': {
                'chainabuse': {
                    'enabled': True,
                    'ethical_scraping': True,
                    'base_delay_seconds': 1.0,
                    'max_retries': 3
                }
            }
        }
    
    @pytest.fixture  
    def scraper(self, mock_config):
        with patch('diskcache.Cache'):
            return ChainabuseScraper(mock_config, "/tmp/test_cache")
    
    @patch('requests.get')
    def test_check_robots_txt_allowed(self, mock_get, scraper):
        """Test robots.txt compliance checking"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "User-agent: *\nDisallow: /private/\nAllow: /address/"
        mock_get.return_value = mock_response
        
        allowed = scraper._check_robots_txt("https://chainabuse.com/address/test")
        
        assert allowed is True
    
    @patch('requests.get')
    def test_check_robots_txt_disallowed(self, mock_get, scraper):
        """Test robots.txt blocking detection"""
        mock_response = Mock()
        mock_response.status_code = 200  
        mock_response.text = "User-agent: *\nDisallow: /address/"
        mock_get.return_value = mock_response
        
        allowed = scraper._check_robots_txt("https://chainabuse.com/address/test")
        
        assert allowed is False
    
    def test_parse_abuse_page_content(self, scraper):
        """Test parsing of abuse report page content"""
        html_content = """
        <div class="abuse-report">
            <h3>Bitcoin Scam</h3>
            <p>Type: ponzi_scheme</p>
            <p>Description: Test abuse report description</p>
            <div class="report-date">2023-01-15</div>
        </div>
        """
        
        with patch('bs4.BeautifulSoup') as mock_soup:
            mock_parsed = Mock()
            mock_soup.return_value = mock_parsed
            
            # Mock finding elements
            mock_title = Mock()
            mock_title.get_text.return_value = "Bitcoin Scam"
            mock_parsed.find.return_value = mock_title
            
            mock_elements = [
                Mock(get_text=Mock(return_value="Type: ponzi_scheme")),
                Mock(get_text=Mock(return_value="Description: Test abuse report description"))
            ]
            mock_parsed.find_all.return_value = mock_elements
            
            report = scraper._parse_abuse_page_content(html_content, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
            
            assert isinstance(report, ChainabuseReport)
            assert report.crypto_address == "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"


class TestScamSearchClient:
    """Test ScamSearch.io API integration"""
    
    @pytest.fixture
    def mock_config(self):
        return {
            'community_scam_sources': {
                'scamsearch': {
                    'enabled': True,
                    'api_key': 'test_api_key',
                    'subscription_tier': 'premium',
                    'requests_per_day': 1000
                }
            },
            'rate_limiting': {
                'scamsearch_requests_per_minute': 10
            }
        }
    
    @pytest.fixture
    def client(self, mock_config):
        with patch('diskcache.Cache'):
            return ScamSearchClient(mock_config, "/tmp/test_cache")
    
    @patch('requests.get')
    def test_search_by_crypto_address_success(self, mock_get, client):
        """Test successful crypto address search"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'entries': [
                {
                    'id': 'entry123',
                    'scam_type': 'bitcoin_scam',
                    'description': 'Test bitcoin scam',
                    'crypto_addresses': ['1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'],
                    'verified': True,
                    'date_reported': '2023-01-15',
                    'report_count': 5
                }
            ],
            'total_results': 1
        }
        mock_get.return_value = mock_response
        
        result = client.search_by_crypto_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
        
        assert result['found_in_scamsearch'] is True
        assert result['entry_count'] == 1
        assert len(result['entries']) == 1
        assert result['entries'][0].scam_type == 'bitcoin_scam'
    
    @patch('requests.get')  
    def test_search_by_email_no_results(self, mock_get, client):
        """Test email search with no results"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'entries': [],
            'total_results': 0
        }
        mock_get.return_value = mock_response
        
        result = client.search_by_email("clean@example.com")
        
        assert result['found_in_scamsearch'] is False
        assert result['entry_count'] == 0
        assert len(result['entries']) == 0
    
    def test_build_scam_entry(self, client):
        """Test ScamSearchEntry creation from API data"""
        api_data = {
            'id': 'entry456', 
            'scam_type': 'phishing',
            'description': 'Phishing scam targeting crypto users',
            'crypto_addresses': ['0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'],
            'emails': ['scam@fake.com'],
            'verified': False,
            'date_reported': '2023-02-20',
            'report_count': 12
        }
        
        entry = client._build_scam_entry(api_data)
        
        assert isinstance(entry, ScamSearchEntry)
        assert entry.entry_id == 'entry456'
        assert entry.scam_type == 'phishing'
        assert entry.verified is False
        assert entry.report_count == 12
        assert '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' in entry.crypto_addresses


class TestCommunityScamAggregator:
    """Test community scam data aggregation"""
    
    @pytest.fixture
    def mock_config(self):
        return {
            'community_scam_sources': {
                'cryptoscamdb': {'enabled': True},
                'chainabuse': {'enabled': True},
                'scamsearch': {'enabled': True}
            }
        }
    
    @pytest.fixture
    def aggregator(self, mock_config):
        with patch('diskcache.Cache'):
            with patch('src.collectors.community_scam_aggregator.CryptoScamDBCollector'):
                with patch('src.collectors.community_scam_aggregator.ChainabuseScraper'):
                    with patch('src.collectors.community_scam_aggregator.ScamSearchClient'):
                        return CommunityScamAggregator(mock_config, "/tmp/test_cache")
    
    def test_collect_address_data_integration(self, aggregator):
        """Test multi-source address data collection"""
        # Mock collector responses
        aggregator.cryptoscamdb_collector.lookup_address.return_value = {
            'found_in_database': True,
            'report_count': 3,
            'reports': [{'category': 'phishing', 'description': 'Test report'}]
        }
        
        aggregator.chainabuse_scraper.lookup_address.return_value = {
            'found_in_chainabuse': True,
            'report_count': 2,
            'abuse_types': ['scam']
        }
        
        aggregator.scamsearch_client.search_by_crypto_address.return_value = {
            'found_in_scamsearch': True,
            'entry_count': 1,
            'entries': [Mock(scam_type='bitcoin_scam', report_count=5)]
        }
        
        result = aggregator.collect_address_data("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
        
        assert result['scam_reports_found'] is True
        assert result['sources_checked'] == ['cryptoscamdb', 'chainabuse', 'scamsearch']
        assert 'aggregated_assessment' in result
        assert result['aggregated_assessment']['total_reports'] == 10  # 3+2+5
    
    def test_calculate_risk_score_high_risk(self, aggregator):
        """Test risk score calculation for high-risk address"""
        source_results = {
            'cryptoscamdb': {'found_in_database': True, 'report_count': 15},
            'chainabuse': {'found_in_chainabuse': True, 'report_count': 8}, 
            'scamsearch': {'found_in_scamsearch': True, 'total_reports': 25}
        }
        
        assessment = aggregator._calculate_aggregated_assessment(source_results)
        
        assert assessment['risk_score'] >= 0.8  # High risk
        assert assessment['confidence'] >= 0.9   # High confidence
        assert assessment['total_reports'] == 48
    
    def test_calculate_risk_score_clean_address(self, aggregator):
        """Test risk score for clean address"""
        source_results = {
            'cryptoscamdb': {'found_in_database': False, 'report_count': 0},
            'chainabuse': {'found_in_chainabuse': False, 'report_count': 0},
            'scamsearch': {'found_in_scamsearch': False, 'total_reports': 0}
        }
        
        assessment = aggregator._calculate_aggregated_assessment(source_results)
        
        assert assessment['risk_score'] == 0.0
        assert assessment['confidence'] >= 0.7  # Still confident in clean result
        assert assessment['total_reports'] == 0


def test_integration_example():
    """Example integration test showing full workflow"""
    config = {
        'community_scam_sources': {
            'cryptoscamdb': {'enabled': True, 'github_token': 'test'},
            'chainabuse': {'enabled': True, 'ethical_scraping': True},
            'scamsearch': {'enabled': True, 'api_key': 'test'}
        },
        'rate_limiting': {'default_delay_seconds': 0.01}
    }
    
    with patch('diskcache.Cache'):
        with patch('src.collectors.community_scam_aggregator.CryptoScamDBCollector'):
            with patch('src.collectors.community_scam_aggregator.ChainabuseScraper'):
                with patch('src.collectors.community_scam_aggregator.ScamSearchClient'):
                    aggregator = CommunityScamAggregator(config, "/tmp/test")
                    
                    # Verify all sources are available
                    assert 'cryptoscamdb' in aggregator.available_sources
                    assert 'chainabuse' in aggregator.available_sources
                    assert 'scamsearch' in aggregator.available_sources


if __name__ == "__main__":
    # Run basic validation without pytest
    print("🧪 Running basic community collector validation...")
    
    # Test address parsing
    from src.collectors.cryptoscamdb_collector import CryptoScamDBCollector
    
    mock_config = {
        'community_scam_sources': {
            'cryptoscamdb': {'enabled': True, 'github_token': None}
        }
    }
    
    try:
        with patch('diskcache.Cache'):
            collector = CryptoScamDBCollector(mock_config, "/tmp/test")
            
        # Test address extraction
        test_entry = {
            "description": "Scam with BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and ETH 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        }
        addresses = collector._parse_addresses_from_entry(test_entry)
        assert len(addresses) == 2
        print("✅ Address parsing validation passed")
        
        print("✅ All basic validations passed!")
        
    except Exception as e:
        print(f"❌ Validation error: {e}")