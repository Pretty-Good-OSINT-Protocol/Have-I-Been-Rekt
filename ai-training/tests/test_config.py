"""
Unit tests for configuration management.
"""

import json
import os
import tempfile
from unittest.mock import patch, mock_open

import pytest

from src.utils.config import (
    ConfigManager, AppConfig, APIKeysConfig, RateLimitConfig,
    CacheConfig, DataSourceConfig, get_config_manager, get_config
)


class TestAPIKeysConfig:
    """Test APIKeysConfig model"""
    
    def test_empty_api_keys(self):
        config = APIKeysConfig()
        
        assert config.chainalysis is None
        assert config.haveibeenpwned is None
        assert config.virustotal is None
    
    def test_api_keys_with_values(self):
        config = APIKeysConfig(
            chainalysis="test_key_1",
            virustotal="test_key_2"
        )
        
        assert config.chainalysis == "test_key_1"
        assert config.virustotal == "test_key_2"
        assert config.haveibeenpwned is None


class TestRateLimitConfig:
    """Test RateLimitConfig model"""
    
    def test_default_rate_limits(self):
        config = RateLimitConfig()
        
        assert config.calls_per_minute == 60
        assert config.burst_limit == 10
    
    def test_custom_rate_limits(self):
        config = RateLimitConfig(calls_per_minute=120, burst_limit=20)
        
        assert config.calls_per_minute == 120
        assert config.burst_limit == 20
    
    def test_invalid_rate_limits(self):
        with pytest.raises(ValueError):
            RateLimitConfig(calls_per_minute=0)
        
        with pytest.raises(ValueError):
            RateLimitConfig(burst_limit=0)


class TestCacheConfig:
    """Test CacheConfig model"""
    
    def test_default_cache_config(self):
        config = CacheConfig()
        
        assert config.enabled is True
        assert config.ttl_hours == 24
        assert config.max_size_mb == 500
        assert config.directory == "./data/cache"
    
    def test_custom_cache_config(self):
        config = CacheConfig(
            enabled=False,
            ttl_hours=12,
            max_size_mb=1000,
            directory="/tmp/cache"
        )
        
        assert config.enabled is False
        assert config.ttl_hours == 12
        assert config.max_size_mb == 1000
        assert config.directory == "/tmp/cache"


class TestAppConfig:
    """Test main AppConfig model"""
    
    def test_default_app_config(self):
        config = AppConfig()
        
        assert isinstance(config.api_keys, APIKeysConfig)
        assert isinstance(config.cache, CacheConfig)
        assert isinstance(config.risk_scoring.weights, dict)
        assert "sanctions" in config.risk_scoring.weights
    
    def test_app_config_with_data(self, test_config):
        config = AppConfig(**test_config)
        
        assert config.api_keys.chainalysis == "test_chainalysis_key"
        assert config.cache.enabled is True
        assert "test_source" in config.rate_limits
        assert isinstance(config.rate_limits["test_source"], RateLimitConfig)
    
    def test_rate_limits_validation(self):
        config_data = {
            "rate_limits": {
                "test_service": {
                    "calls_per_minute": 100,
                    "burst_limit": 15
                }
            }
        }
        
        config = AppConfig(**config_data)
        
        assert "test_service" in config.rate_limits
        assert isinstance(config.rate_limits["test_service"], RateLimitConfig)
        assert config.rate_limits["test_service"].calls_per_minute == 100
    
    def test_data_sources_validation(self):
        config_data = {
            "data_sources": {
                "test_source": {
                    "enabled": True,
                    "base_url": "https://api.test.com"
                }
            }
        }
        
        config = AppConfig(**config_data)
        
        assert "test_source" in config.data_sources
        assert isinstance(config.data_sources["test_source"], DataSourceConfig)
        assert config.data_sources["test_source"].enabled is True


class TestConfigManager:
    """Test ConfigManager class"""
    
    def test_config_manager_initialization(self):
        manager = ConfigManager()
        
        assert manager.config is None
        assert manager.config_path.endswith("config.json")
    
    def test_find_config_file_existing(self, temp_dir):
        config_path = os.path.join(temp_dir, "config.json")
        with open(config_path, 'w') as f:
            json.dump({}, f)
        
        with patch('os.path.exists') as mock_exists:
            mock_exists.side_effect = lambda path: path == config_path
            
            manager = ConfigManager()
            found_path = manager._find_config_file()
            
            # Should find the first existing path
            assert found_path in ["./config/config.json", "./config.json"]
    
    def test_load_config_from_file(self, temp_dir, test_config):
        config_path = os.path.join(temp_dir, "config.json")
        with open(config_path, 'w') as f:
            json.dump(test_config, f)
        
        manager = ConfigManager(config_path)
        config = manager.load_config()
        
        assert isinstance(config, AppConfig)
        assert config.api_keys.chainalysis == "test_chainalysis_key"
        assert config.cache.enabled is True
    
    def test_load_config_file_not_found(self, temp_dir):
        config_path = os.path.join(temp_dir, "nonexistent.json")
        
        manager = ConfigManager(config_path)
        config = manager.load_config()
        
        # Should load default config
        assert isinstance(config, AppConfig)
        assert config.api_keys.chainalysis is None
    
    def test_load_config_invalid_json(self, temp_dir):
        config_path = os.path.join(temp_dir, "invalid.json")
        with open(config_path, 'w') as f:
            f.write("invalid json content")
        
        manager = ConfigManager(config_path)
        
        with pytest.raises(ValueError, match="Failed to load config"):
            manager.load_config()
    
    @patch.dict(os.environ, {
        'CHAINALYSIS_API_KEY': 'env_chainalysis_key',
        'LOG_LEVEL': 'DEBUG',
        'CACHE_ENABLED': 'false',
        'CACHE_TTL_HOURS': '48'
    })
    def test_env_var_overrides(self, temp_dir):
        config_path = os.path.join(temp_dir, "config.json")
        with open(config_path, 'w') as f:
            json.dump({}, f)
        
        manager = ConfigManager(config_path)
        config = manager.load_config()
        
        assert config.api_keys.chainalysis == 'env_chainalysis_key'
        assert config.logging.level == 'DEBUG'
        assert config.cache.enabled is False
        assert config.cache.ttl_hours == 48
    
    def test_get_api_key(self, temp_dir, test_config):
        config_path = os.path.join(temp_dir, "config.json")
        with open(config_path, 'w') as f:
            json.dump(test_config, f)
        
        manager = ConfigManager(config_path)
        
        assert manager.get_api_key('chainalysis') == 'test_chainalysis_key'
        assert manager.get_api_key('nonexistent') is None
    
    def test_is_source_enabled(self, temp_dir, test_config):
        config_path = os.path.join(temp_dir, "config.json")
        with open(config_path, 'w') as f:
            json.dump(test_config, f)
        
        manager = ConfigManager(config_path)
        
        assert manager.is_source_enabled('test_source') is True
        assert manager.is_source_enabled('nonexistent_source') is False
    
    def test_get_rate_limit_config(self, temp_dir, test_config):
        config_path = os.path.join(temp_dir, "config.json")
        with open(config_path, 'w') as f:
            json.dump(test_config, f)
        
        manager = ConfigManager(config_path)
        
        # Existing source
        rate_config = manager.get_rate_limit_config('test_source')
        assert isinstance(rate_config, RateLimitConfig)
        assert rate_config.calls_per_minute == 60
        
        # Non-existing source should return default
        default_config = manager.get_rate_limit_config('nonexistent')
        assert isinstance(default_config, RateLimitConfig)
        assert default_config.calls_per_minute == 60  # default
    
    def test_create_example_config(self, temp_dir):
        output_path = os.path.join(temp_dir, "example_config.json")
        
        manager = ConfigManager()
        manager.create_example_config(output_path)
        
        assert os.path.exists(output_path)
        
        with open(output_path) as f:
            example_config = json.load(f)
        
        assert "api_keys" in example_config
        assert "rate_limits" in example_config
        assert "cache" in example_config
        assert example_config["api_keys"]["chainalysis"] == "your_chainalysis_api_key_here"
    
    def test_validate_configuration_valid(self, temp_dir, test_config):
        config_path = os.path.join(temp_dir, "config.json")
        with open(config_path, 'w') as f:
            json.dump(test_config, f)
        
        manager = ConfigManager(config_path)
        status = manager.validate_configuration()
        
        assert status["valid"] is True
        assert "test_chainalysis_key" in str(status["api_keys_configured"])
        assert "test_source" in status["sources_enabled"]
    
    def test_validate_configuration_missing_api_key(self, temp_dir):
        config_data = {
            "data_sources": {
                "chainalysis": {"enabled": True}
            }
        }
        config_path = os.path.join(temp_dir, "config.json")
        with open(config_path, 'w') as f:
            json.dump(config_data, f)
        
        manager = ConfigManager(config_path)
        status = manager.validate_configuration()
        
        assert status["valid"] is True  # Warnings don't make it invalid
        assert any("chainalysis" in warning for warning in status["warnings"])
    
    @patch('pathlib.Path.mkdir')
    def test_validate_configuration_directory_creation_error(self, mock_mkdir, temp_dir):
        mock_mkdir.side_effect = PermissionError("Cannot create directory")
        
        manager = ConfigManager()
        status = manager.validate_configuration()
        
        assert status["valid"] is False
        assert any("Cannot create cache directory" in error for error in status["errors"])


class TestGlobalFunctions:
    """Test global configuration functions"""
    
    def test_get_config_manager_singleton(self):
        # Reset global manager
        import src.utils.config
        src.utils.config._config_manager = None
        
        manager1 = get_config_manager()
        manager2 = get_config_manager()
        
        assert manager1 is manager2  # Should be the same instance
    
    def test_get_config_with_custom_path(self, temp_dir, test_config):
        config_path = os.path.join(temp_dir, "custom.json")
        with open(config_path, 'w') as f:
            json.dump(test_config, f)
        
        config = get_config(config_path)
        
        assert isinstance(config, AppConfig)
        assert config.api_keys.chainalysis == "test_chainalysis_key"