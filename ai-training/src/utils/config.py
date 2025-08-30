"""
Configuration management for the AI training system.
Handles loading, validation, and environment-specific settings.
"""

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path

from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv


class APIKeysConfig(BaseModel):
    chainalysis: Optional[str] = None
    haveibeenpwned: Optional[str] = None
    virustotal: Optional[str] = None
    etherscan: Optional[str] = None
    bscscan: Optional[str] = None
    infura: Optional[str] = None
    alchemy: Optional[str] = None


class RateLimitConfig(BaseModel):
    calls_per_minute: int = Field(default=60, ge=1)
    burst_limit: int = Field(default=10, ge=1)


class CacheConfig(BaseModel):
    enabled: bool = True
    ttl_hours: int = Field(default=24, ge=1)
    max_size_mb: int = Field(default=500, ge=10)
    directory: str = "./data/cache"


class DataSourceConfig(BaseModel):
    enabled: bool = True
    update_interval_hours: Optional[int] = None
    url: Optional[str] = None
    github_repo: Optional[str] = None
    base_url: Optional[str] = None
    respect_robots: bool = True
    requires_subscription: bool = False
    free_tier: bool = True


class LoggingConfig(BaseModel):
    level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    format: str = "structured"
    file: str = "./logs/collector.log"
    max_size_mb: int = Field(default=100, ge=1)
    backup_count: int = Field(default=5, ge=1)


class RiskScoringConfig(BaseModel):
    weights: Dict[str, float] = Field(default_factory=lambda: {
        "sanctions": 1.0,
        "scam_reports": 0.7,
        "honeypot_interaction": 0.8,
        "mixer_usage": 0.3,
        "breach_exposure": 0.2
    })
    thresholds: Dict[str, float] = Field(default_factory=lambda: {
        "critical": 0.8,
        "high": 0.6,
        "medium": 0.4,
        "low": 0.2
    })


class AppConfig(BaseModel):
    """Main application configuration"""
    api_keys: APIKeysConfig = Field(default_factory=APIKeysConfig)
    rate_limits: Dict[str, RateLimitConfig] = Field(default_factory=dict)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    data_sources: Dict[str, DataSourceConfig] = Field(default_factory=dict)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    risk_scoring: RiskScoringConfig = Field(default_factory=RiskScoringConfig)
    
    # Additional settings
    database: Dict[str, Any] = Field(default_factory=dict)
    ml_training: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('rate_limits', pre=True)
    def validate_rate_limits(cls, v):
        """Convert dict values to RateLimitConfig objects"""
        if isinstance(v, dict):
            return {k: RateLimitConfig(**val) if isinstance(val, dict) else val 
                   for k, val in v.items()}
        return v
    
    @validator('data_sources', pre=True)
    def validate_data_sources(cls, v):
        """Convert dict values to DataSourceConfig objects"""
        if isinstance(v, dict):
            return {k: DataSourceConfig(**val) if isinstance(val, dict) else val 
                   for k, val in v.items()}
        return v


class ConfigManager:
    """Manages application configuration with environment and file support"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config_file()
        self.config: Optional[AppConfig] = None
        self._load_env_vars()
    
    def _find_config_file(self) -> str:
        """Find configuration file in standard locations"""
        possible_paths = [
            "./config/config.json",
            "./config.json",
            "../config/config.json",
            os.path.expanduser("~/.hibr/config.json"),
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Return default path if none found
        return "./config/config.json"
    
    def _load_env_vars(self):
        """Load environment variables from .env file"""
        env_paths = [".env", "../.env", "./config/.env"]
        for path in env_paths:
            if os.path.exists(path):
                load_dotenv(path)
                break
    
    def load_config(self) -> AppConfig:
        """Load and validate configuration"""
        if self.config:
            return self.config
        
        # Start with default config
        config_data = {}
        
        # Load from file if it exists
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    config_data = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                raise ValueError(f"Failed to load config from {self.config_path}: {e}")
        
        # Override with environment variables
        self._apply_env_overrides(config_data)
        
        # Validate and create config object
        try:
            self.config = AppConfig(**config_data)
        except Exception as e:
            raise ValueError(f"Invalid configuration: {e}")
        
        return self.config
    
    def _apply_env_overrides(self, config_data: Dict[str, Any]):
        """Apply environment variable overrides"""
        # API Keys
        if 'api_keys' not in config_data:
            config_data['api_keys'] = {}
        
        env_mappings = {
            'CHAINALYSIS_API_KEY': ['api_keys', 'chainalysis'],
            'HIBP_API_KEY': ['api_keys', 'haveibeenpwned'],
            'VIRUSTOTAL_API_KEY': ['api_keys', 'virustotal'],
            'ETHERSCAN_API_KEY': ['api_keys', 'etherscan'],
            'BSCSCAN_API_KEY': ['api_keys', 'bscscan'],
            'INFURA_PROJECT_ID': ['api_keys', 'infura'],
            'ALCHEMY_API_KEY': ['api_keys', 'alchemy'],
            'LOG_LEVEL': ['logging', 'level'],
            'CACHE_ENABLED': ['cache', 'enabled'],
            'CACHE_TTL_HOURS': ['cache', 'ttl_hours'],
        }
        
        for env_var, config_path in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value:
                # Navigate to the correct nested dict
                current = config_data
                for key in config_path[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                
                # Convert boolean/numeric values
                if env_var == 'CACHE_ENABLED':
                    env_value = env_value.lower() in ('true', '1', 'yes')
                elif env_var == 'CACHE_TTL_HOURS':
                    env_value = int(env_value)
                
                current[config_path[-1]] = env_value
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a specific service"""
        config = self.load_config()
        return getattr(config.api_keys, service, None)
    
    def is_source_enabled(self, source_name: str) -> bool:
        """Check if a data source is enabled"""
        config = self.load_config()
        source_config = config.data_sources.get(source_name)
        return source_config.enabled if source_config else False
    
    def get_rate_limit_config(self, source_name: str) -> RateLimitConfig:
        """Get rate limit configuration for a source"""
        config = self.load_config()
        return config.rate_limits.get(source_name, RateLimitConfig())
    
    def get_data_source_config(self, source_name: str) -> DataSourceConfig:
        """Get configuration for a specific data source"""
        config = self.load_config()
        return config.data_sources.get(source_name, DataSourceConfig())
    
    def create_example_config(self, output_path: str):
        """Create an example configuration file"""
        example_config = {
            "api_keys": {
                "chainalysis": "your_chainalysis_api_key_here",
                "haveibeenpwned": "your_hibp_api_key_here",
                "virustotal": "your_virustotal_api_key_here",
                "etherscan": "your_etherscan_api_key_here",
                "bscscan": "your_bscscan_api_key_here",
                "infura": "your_infura_project_id_here",
                "alchemy": "your_alchemy_api_key_here"
            },
            "rate_limits": {
                "chainalysis": {"calls_per_minute": 100, "burst_limit": 10},
                "cryptoscamdb": {"calls_per_minute": 60, "burst_limit": 5},
                "haveibeenpwned": {"calls_per_minute": 10, "burst_limit": 2},
            },
            "cache": {
                "enabled": True,
                "ttl_hours": 24,
                "max_size_mb": 500,
                "directory": "./data/cache"
            },
            "data_sources": {
                "ofac_sanctions": {
                    "enabled": True,
                    "update_interval_hours": 24
                },
                "cryptoscamdb": {
                    "enabled": True,
                    "github_repo": "CryptoScamDB/api",
                    "update_interval_hours": 6
                }
            },
            "risk_scoring": {
                "weights": {
                    "sanctions": 1.0,
                    "scam_reports": 0.7,
                    "honeypot_interaction": 0.8,
                    "mixer_usage": 0.3
                },
                "thresholds": {
                    "critical": 0.8,
                    "high": 0.6,
                    "medium": 0.4,
                    "low": 0.2
                }
            }
        }
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(example_config, f, indent=2)
    
    def validate_configuration(self) -> Dict[str, Any]:
        """Validate current configuration and return status"""
        config = self.load_config()
        status = {
            "valid": True,
            "warnings": [],
            "errors": [],
            "sources_enabled": [],
            "api_keys_configured": []
        }
        
        # Check API keys
        api_keys = config.api_keys.dict()
        for service, key in api_keys.items():
            if key and key != f"your_{service}_api_key_here":
                status["api_keys_configured"].append(service)
        
        # Check data sources
        for source_name, source_config in config.data_sources.items():
            if source_config.enabled:
                status["sources_enabled"].append(source_name)
                
                # Check if required API keys are present
                if source_name == "chainalysis" and not config.api_keys.chainalysis:
                    status["warnings"].append(f"{source_name} enabled but no API key configured")
                elif source_name == "haveibeenpwned" and not config.api_keys.haveibeenpwned:
                    status["warnings"].append(f"{source_name} enabled but no API key configured")
        
        # Check cache directory
        cache_dir = Path(config.cache.directory)
        if not cache_dir.exists():
            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                status["errors"].append(f"Cannot create cache directory: {e}")
        
        # Check log directory
        log_file = Path(config.logging.file)
        log_dir = log_file.parent
        if not log_dir.exists():
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                status["errors"].append(f"Cannot create log directory: {e}")
        
        if status["errors"]:
            status["valid"] = False
        
        return status


# Global config manager instance
_config_manager = None


def get_config_manager(config_path: Optional[str] = None) -> ConfigManager:
    """Get global config manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager


def get_config(config_path: Optional[str] = None) -> AppConfig:
    """Get application configuration"""
    return get_config_manager(config_path).load_config()