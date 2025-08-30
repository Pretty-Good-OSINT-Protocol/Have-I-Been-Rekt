"""
Pytest configuration and shared fixtures.
"""

import os
import tempfile
import shutil
from typing import Dict, Any
from unittest.mock import Mock, MagicMock

import pytest
import requests_mock

from src.utils.config import AppConfig
from src.data_collector import DataCollectorManager


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def test_config(temp_dir):
    """Create a test configuration"""
    return {
        "api_keys": {
            "chainalysis": "test_chainalysis_key",
            "haveibeenpwned": "test_hibp_key",
            "virustotal": "test_vt_key",
            "etherscan": "test_etherscan_key"
        },
        "rate_limits": {
            "test_source": {
                "calls_per_minute": 60,
                "burst_limit": 5
            },
            "chainalysis": {
                "calls_per_minute": 100,
                "burst_limit": 10
            }
        },
        "cache": {
            "enabled": True,
            "ttl_hours": 1,
            "max_size_mb": 10,
            "directory": os.path.join(temp_dir, "cache")
        },
        "data_sources": {
            "test_source": {
                "enabled": True,
                "base_url": "https://api.test.com"
            },
            "ofac_sanctions": {
                "enabled": True,
                "url": "https://test-ofac.com/sdn.xml"
            }
        },
        "logging": {
            "level": "DEBUG",
            "format": "plain",
            "file": os.path.join(temp_dir, "test.log")
        },
        "risk_scoring": {
            "weights": {
                "sanctions": 1.0,
                "scam_reports": 0.7,
                "honeypot_interaction": 0.8
            },
            "thresholds": {
                "critical": 0.8,
                "high": 0.6,
                "medium": 0.4,
                "low": 0.2
            }
        }
    }


@pytest.fixture
def app_config(test_config):
    """Create AppConfig instance for testing"""
    return AppConfig(**test_config)


@pytest.fixture
def mock_requests():
    """Mock HTTP requests for testing"""
    with requests_mock.Mocker() as m:
        yield m


@pytest.fixture
def sample_wallet_addresses():
    """Sample wallet addresses for testing"""
    return {
        "clean": "0x1234567890123456789012345678901234567890",
        "scam": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "sanctioned": "0x0123456789abcdef0123456789abcdef01234567",
        "mixer": "0xfedcba0987654321fedcba0987654321fedcba09",
        "invalid": "invalid_address_format"
    }


@pytest.fixture
def sample_risk_factors():
    """Sample risk factors for testing"""
    from src.data_collector import RiskFactor, RiskLevel
    from datetime import datetime
    
    return [
        RiskFactor(
            source="test_sanctions",
            factor_type="sanctions",
            severity=RiskLevel.CRITICAL,
            weight=1.0,
            description="Address appears on OFAC sanctions list",
            reference_url="https://test-ofac.com/sdn",
            confidence=1.0
        ),
        RiskFactor(
            source="test_scamdb",
            factor_type="scam_report",
            severity=RiskLevel.HIGH,
            weight=0.7,
            description="Address reported for phishing scam",
            report_count=5,
            first_seen=datetime(2023, 1, 1),
            confidence=0.8
        )
    ]


@pytest.fixture
def mock_collector(test_config):
    """Create a mock data collector for testing"""
    from src.data_collector import BaseDataCollector, DataSourceType
    
    class MockCollector(BaseDataCollector):
        @property
        def source_name(self):
            return "test_source"
        
        @property
        def data_source_type(self):
            return DataSourceType.SCAM_DATABASE
        
        def collect_address_data(self, address):
            if address == "0xscam":
                return {"is_scam": True, "reports": 5}
            elif address == "0xclean":
                return {"is_scam": False, "reports": 0}
            else:
                return None
        
        def parse_risk_factors(self, raw_data, address):
            from src.data_collector import RiskFactor, RiskLevel
            factors = []
            
            if raw_data.get("is_scam"):
                factors.append(RiskFactor(
                    source=self.source_name,
                    factor_type="scam_report",
                    severity=RiskLevel.HIGH,
                    weight=0.7,
                    description="Address reported as scam",
                    report_count=raw_data.get("reports", 1),
                    confidence=0.8
                ))
            
            return factors
    
    return MockCollector(test_config)


@pytest.fixture
def collector_manager(test_config, temp_dir):
    """Create a DataCollectorManager for testing"""
    cache_dir = os.path.join(temp_dir, "cache")
    return DataCollectorManager(test_config, cache_dir)


@pytest.fixture
def mock_api_responses():
    """Mock API responses for various services"""
    return {
        "chainalysis_clean": {
            "address": "0x1234567890123456789012345678901234567890",
            "category": "unknown",
            "categoryId": "unknown",
            "description": None,
            "address": "0x1234567890123456789012345678901234567890"
        },
        "chainalysis_sanctioned": {
            "address": "0x0123456789abcdef0123456789abcdef01234567",
            "category": "sanctions",
            "categoryId": "sanctions",
            "description": "OFAC SDN",
            "url": "https://ofac.treasury.gov"
        },
        "cryptoscamdb_scam": {
            "success": True,
            "result": {
                "entries": [
                    {
                        "type": "scam",
                        "address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                        "coin": "ETH",
                        "url": "https://fake-site.com",
                        "name": "Fake Token Scam",
                        "category": "Scamming"
                    }
                ]
            }
        },
        "hibp_breach": {
            "Name": "Example",
            "Title": "Example Breach",
            "Domain": "example.com",
            "BreachDate": "2023-01-01",
            "AddedDate": "2023-01-15T00:00:00Z",
            "ModifiedDate": "2023-01-15T00:00:00Z",
            "PwnCount": 100000,
            "Description": "Example data breach",
            "LogoPath": "https://example.com/logo.png",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False
        }
    }


@pytest.fixture
def setup_mock_apis(mock_requests, mock_api_responses):
    """Set up mock API endpoints"""
    # Chainalysis API
    mock_requests.get(
        "https://api.chainalysis.com/api/kyt/v1/addresses/0x1234567890123456789012345678901234567890",
        json=mock_api_responses["chainalysis_clean"]
    )
    mock_requests.get(
        "https://api.chainalysis.com/api/kyt/v1/addresses/0x0123456789abcdef0123456789abcdef01234567",
        json=mock_api_responses["chainalysis_sanctioned"]
    )
    
    # CryptoScamDB API
    mock_requests.get(
        "https://api.cryptoscamdb.org/v1/address/0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        json=mock_api_responses["cryptoscamdb_scam"]
    )
    mock_requests.get(
        "https://api.cryptoscamdb.org/v1/address/0x1234567890123456789012345678901234567890",
        json={"success": True, "result": {"entries": []}}
    )
    
    # Have I Been Pwned API
    mock_requests.get(
        "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com",
        json=[mock_api_responses["hibp_breach"]]
    )
    mock_requests.get(
        "https://haveibeenpwned.com/api/v3/breachedaccount/clean@example.com",
        json=[]
    )
    
    return mock_requests


@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch):
    """Set up test environment variables"""
    # Disable external API calls in tests by default
    monkeypatch.setenv("TESTING", "true")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    
    # Mock API keys for testing
    monkeypatch.setenv("CHAINALYSIS_API_KEY", "test_key")
    monkeypatch.setenv("HIBP_API_KEY", "test_key")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test_key")


@pytest.fixture
def disable_rate_limiting(monkeypatch):
    """Disable rate limiting for faster tests"""
    def mock_wait(self):
        pass
    
    monkeypatch.setattr("src.data_collector.RateLimiter.wait_if_needed", mock_wait)


# Test data fixtures
@pytest.fixture
def ofac_sdn_xml():
    """Sample OFAC SDN XML data"""
    return """<?xml version="1.0" encoding="UTF-8"?>
    <sdnList xmlns="http://tempuri.org/sdnList.xsd">
        <sdnEntry>
            <uid>12345</uid>
            <firstName>Test</firstName>
            <lastName>Subject</lastName>
            <sdnType>Individual</sdnType>
            <programList>
                <program>DPRK</program>
            </programList>
            <addressList>
                <address>
                    <addressRemarks>Digital Currency Address - BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</addressRemarks>
                </address>
            </addressList>
        </sdnEntry>
    </sdnList>"""


@pytest.fixture
def graphsense_tagpack():
    """Sample GraphSense TagPack data"""
    return {
        "title": "Test TagPack",
        "description": "Test entity attributions",
        "creator": "test",
        "tags": [
            {
                "address": "0x1234567890123456789012345678901234567890",
                "label": "Test Exchange",
                "source": "manual",
                "category": "exchange",
                "currency": "ETH"
            },
            {
                "address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                "label": "Suspicious Address",
                "source": "investigation", 
                "category": "suspicious",
                "currency": "ETH"
            }
        ]
    }