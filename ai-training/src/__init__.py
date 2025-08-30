"""
AI Training module for Have I Been Rekt.
Provides data collection, risk analysis, and ML training capabilities.
"""

__version__ = "0.1.0"
__author__ = "Pretty Good OSINT Protocol"

from .data_collector import (
    RiskLevel, RiskFactor, WalletAnalysis, 
    BaseDataCollector, DataCollectorManager
)
from .utils import get_config, setup_logging, get_logger

__all__ = [
    'RiskLevel',
    'RiskFactor', 
    'WalletAnalysis',
    'BaseDataCollector',
    'DataCollectorManager',
    'get_config',
    'setup_logging',
    'get_logger'
]