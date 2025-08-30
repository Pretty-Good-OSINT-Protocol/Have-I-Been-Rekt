"""
Unit tests for the base DataCollector and related classes.
"""

import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from src.data_collector import (
    RiskFactor, RiskLevel, WalletAnalysis, RateLimiter,
    BaseDataCollector, DataCollectorManager, DataSourceType
)


class TestRiskFactor:
    """Test RiskFactor dataclass"""
    
    def test_risk_factor_creation(self):
        factor = RiskFactor(
            source="test",
            factor_type="scam",
            severity=RiskLevel.HIGH,
            weight=0.8,
            description="Test risk factor"
        )
        
        assert factor.source == "test"
        assert factor.severity == RiskLevel.HIGH
        assert factor.weight == 0.8
        assert factor.confidence == 1.0  # default
        assert factor.report_count == 1  # default


class TestWalletAnalysis:
    """Test WalletAnalysis model"""
    
    def test_wallet_analysis_validation(self, sample_risk_factors):
        analysis = WalletAnalysis(
            address="0x1234567890123456789012345678901234567890",
            risk_score=0.7,
            risk_level=RiskLevel.HIGH,
            confidence=0.8,
            risk_factors=sample_risk_factors
        )
        
        assert analysis.address == "0x1234567890123456789012345678901234567890"
        assert analysis.risk_score == 0.7
        assert analysis.risk_level == RiskLevel.HIGH
        assert len(analysis.risk_factors) == 2
    
    def test_address_validation_lowercase(self):
        analysis = WalletAnalysis(
            address="0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
            risk_score=0.5,
            risk_level=RiskLevel.MEDIUM,
            confidence=0.7
        )
        
        # Address should be converted to lowercase
        assert analysis.address == "0xabcdef1234567890abcdef1234567890abcdef12"
    
    def test_empty_address_validation(self):
        with pytest.raises(ValueError, match="Address cannot be empty"):
            WalletAnalysis(
                address="",
                risk_score=0.5,
                risk_level=RiskLevel.MEDIUM,
                confidence=0.7
            )


class TestRateLimiter:
    """Test RateLimiter class"""
    
    def test_rate_limiter_initialization(self):
        limiter = RateLimiter(calls_per_minute=60, burst_limit=10)
        
        assert limiter.calls_per_minute == 60
        assert limiter.burst_limit == 10
        assert limiter.calls_history == []
        assert limiter.burst_count == 0
    
    def test_rate_limiter_allows_initial_calls(self):
        limiter = RateLimiter(calls_per_minute=60, burst_limit=5)
        
        # Should not block initial calls
        start_time = time.time()
        for _ in range(5):
            limiter.wait_if_needed()
        end_time = time.time()
        
        # Should complete quickly (no significant delay)
        assert end_time - start_time < 0.1
        assert len(limiter.calls_history) == 5
    
    @patch('time.sleep')
    def test_rate_limiter_burst_limit(self, mock_sleep):
        limiter = RateLimiter(calls_per_minute=60, burst_limit=2)
        
        # First 2 calls should not trigger sleep
        limiter.wait_if_needed()
        limiter.wait_if_needed()
        assert not mock_sleep.called
        
        # Third call should trigger burst limit sleep
        limiter.wait_if_needed()
        mock_sleep.assert_called_with(1)


class TestBaseDataCollector:
    """Test BaseDataCollector abstract base class"""
    
    def test_collector_initialization(self, test_config, temp_dir):
        collector = self._create_test_collector(test_config, temp_dir)
        
        assert collector.source_name == "test_collector"
        assert collector.data_source_type == DataSourceType.SCAM_DATABASE
        assert collector.config == test_config
        assert collector.cache is not None
    
    def test_cache_key_generation(self, test_config):
        collector = self._create_test_collector(test_config)
        
        key = collector.get_cache_key("0x1234")
        assert key == "test_collector:0x1234"
    
    def test_cache_operations(self, test_config, temp_dir):
        collector = self._create_test_collector(test_config, temp_dir)
        
        test_data = {"risk": "high", "score": 0.8}
        
        # Initially no cached data
        assert collector.get_cached_result("0x1234") is None
        
        # Cache some data
        collector.cache_result("0x1234", test_data)
        
        # Should retrieve cached data
        cached = collector.get_cached_result("0x1234")
        assert cached == test_data
    
    def test_cache_expiration(self, test_config, temp_dir):
        # Set very short TTL for testing
        test_config['cache']['ttl_hours'] = 0.001  # ~3.6 seconds
        collector = self._create_test_collector(test_config, temp_dir)
        
        test_data = {"risk": "high"}
        collector.cache_result("0x1234", test_data)
        
        # Should initially be cached
        assert collector.get_cached_result("0x1234") == test_data
        
        # Wait for expiration and check again
        time.sleep(0.01)  # Wait longer than TTL
        assert collector.get_cached_result("0x1234") is None
    
    def test_make_request_success(self, test_config, mock_requests):
        collector = self._create_test_collector(test_config)
        
        # Mock successful API response
        mock_requests.get(
            "https://api.test.com/data",
            json={"status": "success", "data": "test"}
        )
        
        result = collector.make_request("https://api.test.com/data")
        
        assert result == {"status": "success", "data": "test"}
    
    def test_make_request_failure(self, test_config, mock_requests):
        collector = self._create_test_collector(test_config)
        
        # Mock failed API response
        mock_requests.get("https://api.test.com/data", status_code=500)
        
        result = collector.make_request("https://api.test.com/data")
        
        assert result is None
    
    def test_risk_score_calculation(self, test_config, sample_risk_factors):
        collector = self._create_test_collector(test_config)
        
        # Test with sample risk factors
        risk_score = collector.calculate_risk_score(sample_risk_factors)
        
        # Should be weighted average of factor scores
        # Critical (1.0) * 1.0 + High (0.8) * 0.7 / (1.0 + 0.7)
        expected_score = (1.0 * 1.0 * 1.0 + 0.8 * 0.7 * 0.8) / (1.0 * 1.0 + 0.7 * 0.8)
        assert abs(risk_score - expected_score) < 0.01
    
    def test_risk_level_determination(self, test_config):
        collector = self._create_test_collector(test_config)
        
        assert collector.determine_risk_level(0.9) == RiskLevel.CRITICAL
        assert collector.determine_risk_level(0.7) == RiskLevel.HIGH
        assert collector.determine_risk_level(0.5) == RiskLevel.MEDIUM
        assert collector.determine_risk_level(0.3) == RiskLevel.LOW
        assert collector.determine_risk_level(0.1) == RiskLevel.CLEAN
    
    def test_confidence_calculation(self, test_config, sample_risk_factors):
        collector = self._create_test_collector(test_config)
        
        confidence = collector.calculate_confidence(sample_risk_factors)
        
        # Should be weighted average of factor confidences
        # (1.0 * 1.0 + 0.8 * 0.7) / (1.0 + 0.7)
        expected_confidence = (1.0 * 1.0 + 0.8 * 0.7) / (1.0 + 0.7)
        assert abs(confidence - expected_confidence) < 0.01
    
    def test_analyze_address_workflow(self, test_config, temp_dir):
        collector = self._create_test_collector(test_config, temp_dir)
        
        # Mock the abstract methods
        collector.collect_address_data = Mock(return_value={"scam": True})
        collector.parse_risk_factors = Mock(return_value=[
            RiskFactor(
                source="test",
                factor_type="scam",
                severity=RiskLevel.HIGH,
                weight=0.8,
                description="Test scam"
            )
        ])
        
        result = collector.analyze_address("0x1234")
        
        assert result is not None
        assert result.address == "0x1234"
        assert result.risk_level == RiskLevel.HIGH
        assert len(result.risk_factors) == 1
        assert result.processing_time_ms > 0
        
        # Verify methods were called
        collector.collect_address_data.assert_called_once_with("0x1234")
        collector.parse_risk_factors.assert_called_once_with({"scam": True}, "0x1234")
    
    def _create_test_collector(self, config, cache_dir=None):
        """Helper to create a concrete test collector"""
        
        class TestCollector(BaseDataCollector):
            @property
            def source_name(self):
                return "test_collector"
            
            @property
            def data_source_type(self):
                return DataSourceType.SCAM_DATABASE
            
            def collect_address_data(self, address):
                return {"test": True}
            
            def parse_risk_factors(self, raw_data, address):
                return []
        
        return TestCollector(config, cache_dir)


class TestDataCollectorManager:
    """Test DataCollectorManager class"""
    
    def test_manager_initialization(self, test_config, temp_dir):
        manager = DataCollectorManager(test_config, temp_dir)
        
        assert manager.config == test_config
        assert manager.cache_dir == temp_dir
        assert len(manager.collectors) == 0
    
    def test_collector_registration(self, collector_manager, mock_collector):
        collector_manager.register_collector(mock_collector)
        
        assert "test_source" in collector_manager.collectors
        assert collector_manager.collectors["test_source"] == mock_collector
    
    def test_comprehensive_analysis_single_collector(self, collector_manager, mock_collector):
        collector_manager.register_collector(mock_collector)
        
        # Mock the analyze_address method
        mock_analysis = WalletAnalysis(
            address="0xscam",
            risk_score=0.7,
            risk_level=RiskLevel.HIGH,
            confidence=0.8,
            risk_factors=[
                RiskFactor(
                    source="test_source",
                    factor_type="scam",
                    severity=RiskLevel.HIGH,
                    weight=0.7,
                    description="Test scam"
                )
            ]
        )
        mock_collector.analyze_address = Mock(return_value=mock_analysis)
        
        result = collector_manager.analyze_address_comprehensive("0xscam")
        
        assert result.address == "0xscam"
        assert result.risk_level == RiskLevel.HIGH
        assert len(result.risk_factors) == 1
        assert "test_source" in result.data_sources
    
    def test_comprehensive_analysis_no_data(self, collector_manager, mock_collector):
        collector_manager.register_collector(mock_collector)
        mock_collector.analyze_address = Mock(return_value=None)
        
        result = collector_manager.analyze_address_comprehensive("0xunknown")
        
        assert result.address == "0xunknown"
        assert result.risk_level == RiskLevel.CLEAN
        assert result.risk_score == 0.0
        assert result.confidence == 0.1
        assert len(result.risk_factors) == 0
    
    def test_comprehensive_analysis_collector_failure(self, collector_manager, mock_collector):
        collector_manager.register_collector(mock_collector)
        mock_collector.analyze_address = Mock(side_effect=Exception("API Error"))
        
        result = collector_manager.analyze_address_comprehensive("0xtest")
        
        # Should handle collector failure gracefully
        assert result.address == "0xtest"
        assert result.risk_level == RiskLevel.CLEAN
        assert len(result.data_sources) == 0
    
    def test_aggregate_risk_score_multiple_sources(self, test_config, temp_dir):
        manager = DataCollectorManager(test_config, temp_dir)
        
        risk_factors = [
            RiskFactor(
                source="source1",
                factor_type="sanctions",
                severity=RiskLevel.CRITICAL,
                weight=1.0,
                description="Sanctioned",
                confidence=1.0
            ),
            RiskFactor(
                source="source2",
                factor_type="scam",
                severity=RiskLevel.HIGH,
                weight=0.7,
                description="Scam report",
                confidence=0.8
            )
        ]
        
        risk_score = manager._aggregate_risk_score(risk_factors)
        
        # Should use the maximum weighted score
        assert risk_score == 1.0  # Critical factor with full confidence and weight
    
    def test_aggregate_confidence_multiple_sources(self, test_config, temp_dir):
        manager = DataCollectorManager(test_config, temp_dir)
        
        risk_factors = [
            RiskFactor(source="source1", factor_type="test", severity=RiskLevel.HIGH, 
                      weight=1.0, description="Test", confidence=1.0),
            RiskFactor(source="source2", factor_type="test", severity=RiskLevel.HIGH,
                      weight=1.0, description="Test", confidence=0.8)
        ]
        
        confidence = manager._calculate_aggregate_confidence(risk_factors)
        
        # Should be average confidence plus multi-source bonus
        base_confidence = (1.0 + 0.8) / 2  # 0.9
        multi_source_bonus = 0.1  # 2 sources - 1) * 0.1
        expected = min(1.0, base_confidence + multi_source_bonus)
        
        assert abs(confidence - expected) < 0.01