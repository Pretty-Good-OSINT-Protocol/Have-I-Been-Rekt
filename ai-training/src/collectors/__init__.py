"""
Data collectors for various threat intelligence sources.
"""

# Sanctions collectors
from .ofac_sanctions import OFACSanctionsCollector, SanctionedEntity
from .chainalysis_client import ChainanalysisClient, ChainanalysisScreeningResult
from .sanctions_aggregator import SanctionsAggregator

# Community scam database collectors
from .cryptoscamdb_collector import CryptoScamDBCollector, ScamReport
from .chainabuse_scraper import ChainabuseScraper, ChainabuseReport
from .scamsearch_client import ScamSearchClient, ScamSearchEntry
from .whale_alert_client import WhaleAlertClient, WhaleTransaction, SuspiciousActivity
from .community_scam_aggregator import CommunityScamAggregator

# Smart contract threat analysis collectors
from .honeypot_detector import HoneypotDetector, HoneypotAnalysis
from .contract_analyzer import ContractAnalyzer, ContractAnalysis
from .rugpull_detector import RugPullDetector, RugPullAnalysis
from .web3_provider import Web3Provider, TransactionData, EventLog
from .smart_contract_aggregator import SmartContractAggregator

__all__ = [
    # Sanctions
    'OFACSanctionsCollector',
    'SanctionedEntity',
    'ChainanalysisClient', 
    'ChainanalysisScreeningResult',
    'SanctionsAggregator',
    
    # Community scam databases
    'CryptoScamDBCollector',
    'ScamReport',
    'ChainabuseScraper',
    'ChainabuseReport',
    'ScamSearchClient',
    'ScamSearchEntry',
    'WhaleAlertClient',
    'WhaleTransaction',
    'SuspiciousActivity',
    'CommunityScamAggregator',
    
    # Smart contract threat analysis
    'HoneypotDetector',
    'HoneypotAnalysis',
    'ContractAnalyzer',
    'ContractAnalysis',
    'RugPullDetector',
    'RugPullAnalysis',
    'Web3Provider',
    'TransactionData',
    'EventLog',
    'SmartContractAggregator'
]