"""
Rug Pull Detection System - monitors and detects rug pull patterns in DeFi projects.

Analyzes:
- Liquidity removal patterns
- Ownership concentration
- Suspicious trading patterns
- Token distribution fairness
- Team token locks and vesting
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
import requests
import time
import statistics
from decimal import Decimal
from urllib.parse import quote

from ..data_collector import BaseDataCollector
from ..utils.logging import get_logger


@dataclass
class LiquidityEvent:
    """Represents a liquidity add/remove event"""
    
    transaction_hash: str
    block_number: int
    timestamp: datetime
    event_type: str  # 'add', 'remove'
    amount_token: float
    amount_eth: float
    amount_usd: float
    user_address: str
    pool_address: str


@dataclass
class TradingPattern:
    """Represents suspicious trading patterns"""
    
    pattern_type: str  # 'volume_spike', 'price_dump', 'coordinated_sells'
    start_time: datetime
    end_time: datetime
    severity: str  # 'low', 'medium', 'high', 'critical'
    indicators: List[str]
    volume_increase: float  # Percentage increase
    price_change: float     # Percentage change
    transactions_involved: int
    unique_addresses: int


@dataclass
class TokenDistribution:
    """Analysis of token distribution patterns"""
    
    total_supply: int
    circulating_supply: int
    top_10_holders_percent: float
    top_100_holders_percent: float
    holder_count: int
    concentration_score: float  # 0-1, higher = more concentrated
    team_tokens_percent: float
    locked_tokens_percent: float
    vesting_schedule: Optional[Dict[str, Any]]


@dataclass
class RugPullAnalysis:
    """Results from rug pull detection analysis"""
    
    contract_address: str
    token_symbol: str
    token_name: str
    rug_pull_probability: float  # 0-1
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    liquidity_analysis: Dict[str, Any]
    trading_patterns: List[TradingPattern]
    distribution_analysis: TokenDistribution
    red_flags: List[str]
    protective_measures: List[str]
    confidence_score: float
    analysis_timestamp: datetime


class RugPullDetector(BaseDataCollector):
    """
    Rug pull detection system for DeFi tokens.
    
    Monitors multiple indicators:
    1. Liquidity removal patterns
    2. Token holder concentration
    3. Trading volume and price patterns
    4. Team token locks and vesting
    5. Historical rug pull signatures
    """
    
    DEX_APIS = {
        'uniswap_v2': 'https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v2',
        'uniswap_v3': 'https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v3',
        'sushiswap': 'https://api.thegraph.com/subgraphs/name/sushiswap/exchange',
        'pancakeswap': 'https://bsc.streamingfast.io/subgraphs/name/pancakeswap/exchange-v2'
    }
    
    # Rug pull indicators
    CRITICAL_LIQUIDITY_REMOVAL = 80  # % of liquidity removed
    HIGH_CONCENTRATION_THRESHOLD = 50  # % held by top 10 holders
    SUSPICIOUS_VOLUME_SPIKE = 1000  # % volume increase
    RAPID_PRICE_DUMP = 50  # % price drop in short time
    
    def __init__(self, config: Dict[str, Any], cache_dir: str):
        super().__init__(config, cache_dir, "rugpull_detector")
        
        self.logger = get_logger(f"{__name__}.RugPullDetector")
        
        # Load configuration
        smart_contract_config = config.get('smart_contract_analysis', {})
        rugpull_config = smart_contract_config.get('rugpull_detection', {})
        
        self.default_dex = rugpull_config.get('default_dex', 'uniswap_v2')
        self.analysis_period_days = rugpull_config.get('analysis_period_days', 7)
        self.min_liquidity_usd = rugpull_config.get('min_liquidity_usd', 10000)
        self.enable_real_time_monitoring = rugpull_config.get('enable_real_time_monitoring', False)
        
        # Thresholds
        self.critical_liquidity_removal = rugpull_config.get('critical_liquidity_removal', 80)
        self.high_concentration_threshold = rugpull_config.get('high_concentration_threshold', 50)
        self.suspicious_volume_spike = rugpull_config.get('suspicious_volume_spike', 1000)
        self.rapid_price_dump = rugpull_config.get('rapid_price_dump', 50)
        
        # Rate limiting for API calls
        rate_config = config.get('rate_limiting', {})
        self.request_delay = rate_config.get('dex_api_delay_seconds', 0.5)
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Have-I-Been-Rekt-RugPull-Detector/1.0',
            'Content-Type': 'application/json'
        })
        
        self.logger.info(f"Initialized Rug Pull Detector (DEX: {self.default_dex})")
    
    def _make_dex_api_request(self, dex: str, query: str) -> Optional[Dict[str, Any]]:
        """Make GraphQL request to DEX API"""
        
        if dex not in self.DEX_APIS:
            self.logger.error(f"Unsupported DEX: {dex}")
            return None
        
        try:
            # Rate limiting
            time.sleep(self.request_delay)
            
            payload = {'query': query}
            
            self.logger.debug(f"Making {dex} API request")
            
            response = self.session.post(self.DEX_APIS[dex], json=payload, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if 'errors' in data:
                self.logger.warning(f"{dex} API errors: {data['errors']}")
                return None
            
            return data.get('data')
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"{dex} API request failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error in {dex} API request: {e}")
            return None
    
    def get_token_liquidity_events(self, contract_address: str, dex: str = None, days: int = None) -> List[LiquidityEvent]:
        """Get liquidity add/remove events for a token"""
        
        if not dex:
            dex = self.default_dex
        
        if not days:
            days = self.analysis_period_days
        
        # Calculate timestamp for filtering
        start_time = int((datetime.now() - timedelta(days=days)).timestamp())
        
        # GraphQL query for liquidity events (simplified for Uniswap V2)
        query = f'''
        {{
          mints(
            where: {{
              pair_in: ["{contract_address.lower()}"]
              timestamp_gte: {start_time}
            }}
            orderBy: timestamp
            orderDirection: desc
            first: 100
          ) {{
            id
            timestamp
            pair {{
              id
              token0 {{
                symbol
              }}
              token1 {{
                symbol
              }}
            }}
            amount0
            amount1
            amountUSD
            to
            transaction {{
              id
              blockNumber
            }}
          }}
          burns(
            where: {{
              pair_in: ["{contract_address.lower()}"]
              timestamp_gte: {start_time}
            }}
            orderBy: timestamp
            orderDirection: desc
            first: 100
          ) {{
            id
            timestamp
            pair {{
              id
              token0 {{
                symbol
              }}
              token1 {{
                symbol
              }}
            }}
            amount0
            amount1
            amountUSD
            to
            transaction {{
              id
              blockNumber
            }}
          }}
        }}
        '''
        
        response = self._make_dex_api_request(dex, query)
        
        if not response:
            return []
        
        events = []
        
        # Process mint events (liquidity additions)
        for mint in response.get('mints', []):
            events.append(LiquidityEvent(
                transaction_hash=mint['transaction']['id'],
                block_number=int(mint['transaction']['blockNumber']),
                timestamp=datetime.fromtimestamp(int(mint['timestamp']), tz=timezone.utc),
                event_type='add',
                amount_token=float(mint.get('amount0', 0)),
                amount_eth=float(mint.get('amount1', 0)),
                amount_usd=float(mint.get('amountUSD', 0)),
                user_address=mint.get('to', ''),
                pool_address=mint['pair']['id']
            ))
        
        # Process burn events (liquidity removals)
        for burn in response.get('burns', []):
            events.append(LiquidityEvent(
                transaction_hash=burn['transaction']['id'],
                block_number=int(burn['transaction']['blockNumber']),
                timestamp=datetime.fromtimestamp(int(burn['timestamp']), tz=timezone.utc),
                event_type='remove',
                amount_token=float(burn.get('amount0', 0)),
                amount_eth=float(burn.get('amount1', 0)),
                amount_usd=float(burn.get('amountUSD', 0)),
                user_address=burn.get('to', ''),
                pool_address=burn['pair']['id']
            ))
        
        # Sort by timestamp
        events.sort(key=lambda x: x.timestamp, reverse=True)
        
        return events
    
    def get_token_trading_data(self, contract_address: str, dex: str = None, days: int = None) -> Dict[str, Any]:
        """Get trading data for pattern analysis"""
        
        if not dex:
            dex = self.default_dex
        
        if not days:
            days = self.analysis_period_days
        
        start_time = int((datetime.now() - timedelta(days=days)).timestamp())
        
        # GraphQL query for trading data
        query = f'''
        {{
          pairDayDatas(
            where: {{
              pair_in: ["{contract_address.lower()}"]
              date_gte: {start_time}
            }}
            orderBy: date
            orderDirection: desc
            first: {days}
          ) {{
            id
            date
            dailyVolumeUSD
            reserveUSD
            token0 {{
              symbol
            }}
            token1 {{
              symbol
            }}
          }}
          swaps(
            where: {{
              pair_in: ["{contract_address.lower()}"]
              timestamp_gte: {start_time}
            }}
            orderBy: timestamp
            orderDirection: desc
            first: 1000
          ) {{
            id
            timestamp
            amount0In
            amount0Out
            amount1In
            amount1Out
            amountUSD
            to
            transaction {{
              id
            }}
          }}
        }}
        '''
        
        response = self._make_dex_api_request(dex, query)
        
        if not response:
            return {}
        
        return {
            'daily_data': response.get('pairDayDatas', []),
            'swaps': response.get('swaps', [])
        }
    
    def analyze_liquidity_patterns(self, events: List[LiquidityEvent]) -> Dict[str, Any]:
        """Analyze liquidity events for rug pull patterns"""
        
        if not events:
            return {
                'total_added_usd': 0,
                'total_removed_usd': 0,
                'removal_percentage': 0,
                'large_removals': [],
                'suspicious_patterns': []
            }
        
        total_added = sum(event.amount_usd for event in events if event.event_type == 'add')
        total_removed = sum(event.amount_usd for event in events if event.event_type == 'remove')
        
        removal_percentage = (total_removed / total_added * 100) if total_added > 0 else 0
        
        # Identify large removals (>10% of total liquidity)
        large_removals = []
        for event in events:
            if event.event_type == 'remove' and total_added > 0:
                removal_percent = (event.amount_usd / total_added * 100)
                if removal_percent > 10:
                    large_removals.append({
                        'transaction_hash': event.transaction_hash,
                        'amount_usd': event.amount_usd,
                        'percentage': removal_percent,
                        'timestamp': event.timestamp.isoformat(),
                        'user_address': event.user_address
                    })
        
        # Detect suspicious patterns
        suspicious_patterns = []
        
        if removal_percentage > self.critical_liquidity_removal:
            suspicious_patterns.append(f'critical_liquidity_removal_{removal_percentage:.1f}%')
        
        # Check for rapid successive removals
        remove_events = [e for e in events if e.event_type == 'remove']
        remove_events.sort(key=lambda x: x.timestamp)
        
        for i in range(len(remove_events) - 1):
            time_diff = (remove_events[i+1].timestamp - remove_events[i].timestamp).total_seconds()
            if time_diff < 3600:  # Within 1 hour
                combined_usd = remove_events[i].amount_usd + remove_events[i+1].amount_usd
                if combined_usd > total_added * 0.3:  # > 30% of total liquidity
                    suspicious_patterns.append('rapid_successive_removals')
                    break
        
        return {
            'total_added_usd': total_added,
            'total_removed_usd': total_removed,
            'removal_percentage': removal_percentage,
            'large_removals': large_removals,
            'suspicious_patterns': suspicious_patterns
        }
    
    def analyze_trading_patterns(self, trading_data: Dict[str, Any]) -> List[TradingPattern]:
        """Analyze trading data for suspicious patterns"""
        
        patterns = []
        
        daily_data = trading_data.get('daily_data', [])
        swaps = trading_data.get('swaps', [])
        
        if not daily_data:
            return patterns
        
        # Analyze volume spikes
        volumes = [float(day.get('dailyVolumeUSD', 0)) for day in daily_data if day.get('dailyVolumeUSD')]
        
        if len(volumes) >= 3:
            avg_volume = statistics.mean(volumes[1:])  # Exclude most recent day
            recent_volume = volumes[0]
            
            if avg_volume > 0 and recent_volume > avg_volume * (self.suspicious_volume_spike / 100):
                volume_increase = (recent_volume / avg_volume - 1) * 100
                
                patterns.append(TradingPattern(
                    pattern_type='volume_spike',
                    start_time=datetime.fromtimestamp(int(daily_data[0]['date']), tz=timezone.utc),
                    end_time=datetime.now(timezone.utc),
                    severity='high' if volume_increase > 2000 else 'medium',
                    indicators=['unusual_volume_spike'],
                    volume_increase=volume_increase,
                    price_change=0,  # Would need price data
                    transactions_involved=len([s for s in swaps if int(s['timestamp']) >= int(daily_data[0]['date'])]),
                    unique_addresses=len(set(s['to'] for s in swaps if int(s['timestamp']) >= int(daily_data[0]['date'])))
                ))
        
        # Analyze large swaps (potential coordinated selling)
        large_swaps = []
        total_volume_24h = float(daily_data[0].get('dailyVolumeUSD', 0)) if daily_data else 0
        
        for swap in swaps:
            swap_usd = float(swap.get('amountUSD', 0))
            if total_volume_24h > 0 and swap_usd > total_volume_24h * 0.05:  # >5% of daily volume
                large_swaps.append(swap)
        
        if len(large_swaps) > 3:  # Multiple large swaps
            earliest_time = min(datetime.fromtimestamp(int(s['timestamp']), tz=timezone.utc) for s in large_swaps)
            latest_time = max(datetime.fromtimestamp(int(s['timestamp']), tz=timezone.utc) for s in large_swaps)
            
            # Check if they occurred within a short timeframe
            if (latest_time - earliest_time).total_seconds() < 7200:  # Within 2 hours
                patterns.append(TradingPattern(
                    pattern_type='coordinated_sells',
                    start_time=earliest_time,
                    end_time=latest_time,
                    severity='high',
                    indicators=['multiple_large_swaps', 'short_timeframe'],
                    volume_increase=0,
                    price_change=0,
                    transactions_involved=len(large_swaps),
                    unique_addresses=len(set(s['to'] for s in large_swaps))
                ))
        
        return patterns
    
    def analyze_token_distribution(self, contract_address: str) -> Optional[TokenDistribution]:
        """Analyze token holder distribution (placeholder implementation)"""
        
        # This would typically require:
        # 1. Querying blockchain explorer for token holders
        # 2. Analyzing top holder percentages
        # 3. Checking for team/dev wallets
        # 4. Verifying token locks and vesting contracts
        
        # Placeholder implementation - in production would use actual data
        return TokenDistribution(
            total_supply=1000000,
            circulating_supply=800000,
            top_10_holders_percent=45.0,
            top_100_holders_percent=80.0,
            holder_count=5000,
            concentration_score=0.6,
            team_tokens_percent=20.0,
            locked_tokens_percent=10.0,
            vesting_schedule=None
        )
    
    def detect_rug_pull(self, contract_address: str, dex: str = None) -> Optional[RugPullAnalysis]:
        """
        Perform comprehensive rug pull analysis.
        
        Args:
            contract_address: Token contract address
            dex: DEX to analyze (defaults to configured default)
            
        Returns:
            RugPullAnalysis with risk assessment
        """
        
        cache_key = f"rugpull_{contract_address}_{dex or self.default_dex}"
        cached_result = self.get_cached_result(cache_key, max_age_hours=1)  # Short cache for fresh analysis
        
        if cached_result:
            cached_result['analysis_timestamp'] = datetime.fromisoformat(cached_result['analysis_timestamp'])
            # Reconstruct nested objects
            patterns = []
            for pattern_data in cached_result.get('trading_patterns', []):
                pattern_data['start_time'] = datetime.fromisoformat(pattern_data['start_time'])
                pattern_data['end_time'] = datetime.fromisoformat(pattern_data['end_time'])
                patterns.append(TradingPattern(**pattern_data))
            cached_result['trading_patterns'] = patterns
            
            if cached_result.get('distribution_analysis'):
                cached_result['distribution_analysis'] = TokenDistribution(**cached_result['distribution_analysis'])
            
            return RugPullAnalysis(**cached_result)
        
        self.logger.info(f"Analyzing rug pull risk: {contract_address}")
        
        try:
            # Get liquidity events
            liquidity_events = self.get_token_liquidity_events(contract_address, dex)
            liquidity_analysis = self.analyze_liquidity_patterns(liquidity_events)
            
            # Get trading data
            trading_data = self.get_token_trading_data(contract_address, dex)
            trading_patterns = self.analyze_trading_patterns(trading_data)
            
            # Analyze token distribution
            distribution = self.analyze_token_distribution(contract_address)
            
            # Calculate rug pull probability and risk level
            probability, risk_level, red_flags = self._calculate_rug_pull_risk(
                liquidity_analysis, trading_patterns, distribution
            )
            
            # Identify protective measures
            protective_measures = self._identify_protective_measures(
                liquidity_analysis, distribution
            )
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(
                liquidity_events, trading_data, distribution
            )
            
            analysis = RugPullAnalysis(
                contract_address=contract_address,
                token_symbol="UNKNOWN",  # Would extract from trading data
                token_name="Unknown Token",
                rug_pull_probability=probability,
                risk_level=risk_level,
                liquidity_analysis=liquidity_analysis,
                trading_patterns=trading_patterns,
                distribution_analysis=distribution,
                red_flags=red_flags,
                protective_measures=protective_measures,
                confidence_score=confidence_score,
                analysis_timestamp=datetime.now(timezone.utc)
            )
            
            # Cache results
            cache_data = analysis.__dict__.copy()
            cache_data['analysis_timestamp'] = cache_data['analysis_timestamp'].isoformat()
            
            # Handle nested objects for caching
            patterns_data = []
            for pattern in analysis.trading_patterns:
                pattern_dict = pattern.__dict__.copy()
                pattern_dict['start_time'] = pattern_dict['start_time'].isoformat()
                pattern_dict['end_time'] = pattern_dict['end_time'].isoformat()
                patterns_data.append(pattern_dict)
            cache_data['trading_patterns'] = patterns_data
            
            if analysis.distribution_analysis:
                cache_data['distribution_analysis'] = analysis.distribution_analysis.__dict__
            
            self.cache_result(cache_key, cache_data)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error in rug pull analysis for {contract_address}: {e}")
            return None
    
    def _calculate_rug_pull_risk(self, liquidity_analysis: Dict[str, Any], 
                                trading_patterns: List[TradingPattern],
                                distribution: Optional[TokenDistribution]) -> Tuple[float, str, List[str]]:
        """Calculate overall rug pull risk probability"""
        
        risk_score = 0.0
        red_flags = []
        
        # Liquidity risk factors
        removal_percentage = liquidity_analysis.get('removal_percentage', 0)
        if removal_percentage > 80:
            risk_score += 0.4
            red_flags.append(f'critical_liquidity_removal_{removal_percentage:.1f}%')
        elif removal_percentage > 50:
            risk_score += 0.2
            red_flags.append(f'high_liquidity_removal_{removal_percentage:.1f}%')
        
        # Large removal events
        large_removals = liquidity_analysis.get('large_removals', [])
        if len(large_removals) > 2:
            risk_score += 0.2
            red_flags.append('multiple_large_liquidity_removals')
        
        # Trading pattern risks
        for pattern in trading_patterns:
            if pattern.pattern_type == 'coordinated_sells':
                risk_score += 0.3
                red_flags.append('coordinated_selling_detected')
            elif pattern.pattern_type == 'volume_spike' and pattern.severity == 'high':
                risk_score += 0.1
                red_flags.append('suspicious_volume_spike')
        
        # Distribution risks
        if distribution:
            if distribution.concentration_score > 0.8:
                risk_score += 0.2
                red_flags.append('high_token_concentration')
            
            if distribution.top_10_holders_percent > 70:
                risk_score += 0.1
                red_flags.append('majority_held_by_few')
            
            if distribution.locked_tokens_percent < 5:
                risk_score += 0.1
                red_flags.append('insufficient_token_locks')
        
        # Determine risk level
        if risk_score >= 0.7:
            risk_level = 'critical'
        elif risk_score >= 0.5:
            risk_level = 'high'
        elif risk_score >= 0.3:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return min(risk_score, 1.0), risk_level, red_flags
    
    def _identify_protective_measures(self, liquidity_analysis: Dict[str, Any], 
                                    distribution: Optional[TokenDistribution]) -> List[str]:
        """Identify protective measures in place"""
        
        protective_measures = []
        
        # Check liquidity stability
        removal_percentage = liquidity_analysis.get('removal_percentage', 0)
        if removal_percentage < 10:
            protective_measures.append('stable_liquidity')
        
        # Check token distribution
        if distribution:
            if distribution.locked_tokens_percent > 20:
                protective_measures.append('significant_token_locks')
            
            if distribution.concentration_score < 0.5:
                protective_measures.append('decentralized_distribution')
            
            if distribution.vesting_schedule:
                protective_measures.append('team_vesting_schedule')
        
        return protective_measures
    
    def _calculate_confidence_score(self, liquidity_events: List[LiquidityEvent],
                                  trading_data: Dict[str, Any],
                                  distribution: Optional[TokenDistribution]) -> float:
        """Calculate confidence in the analysis"""
        
        confidence = 0.3  # Base confidence
        
        # Boost confidence based on data availability
        if len(liquidity_events) > 5:
            confidence += 0.2
        
        if trading_data.get('daily_data') and len(trading_data['daily_data']) >= 7:
            confidence += 0.2
        
        if trading_data.get('swaps') and len(trading_data['swaps']) > 100:
            confidence += 0.1
        
        if distribution and distribution.holder_count > 1000:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def lookup_address(self, address: str, dex: str = None) -> Dict[str, Any]:
        """
        Main interface for rug pull analysis.
        
        Args:
            address: Token contract address
            dex: DEX to analyze
            
        Returns:
            Dictionary containing rug pull analysis results
        """
        
        try:
            self.logger.info(f"Starting rug pull analysis: {address[:10]}...")
            
            analysis = self.detect_rug_pull(address, dex)
            
            if not analysis:
                return {
                    'found_rugpull_data': False,
                    'error': 'Failed to analyze rug pull risk'
                }
            
            # Build result dictionary
            result = {
                'found_rugpull_data': True,
                'rug_pull_probability': analysis.rug_pull_probability,
                'risk_level': analysis.risk_level,
                'confidence_score': analysis.confidence_score,
                'token_info': {
                    'symbol': analysis.token_symbol,
                    'name': analysis.token_name
                },
                'liquidity_analysis': analysis.liquidity_analysis,
                'trading_patterns': [
                    {
                        'type': pattern.pattern_type,
                        'severity': pattern.severity,
                        'indicators': pattern.indicators,
                        'volume_increase': pattern.volume_increase,
                        'transactions_involved': pattern.transactions_involved
                    } for pattern in analysis.trading_patterns
                ],
                'distribution_analysis': analysis.distribution_analysis.__dict__ if analysis.distribution_analysis else None,
                'red_flags': analysis.red_flags,
                'protective_measures': analysis.protective_measures,
                'analysis_timestamp': analysis.analysis_timestamp.isoformat()
            }
            
            self.logger.info(f"Rug pull analysis completed: {address[:10]}... (risk: {analysis.risk_level})")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in rug pull analysis for {address}: {e}")
            return {
                'found_rugpull_data': False,
                'error': str(e)
            }
    
    def parse_risk_factors(self, raw_data: Dict[str, Any], address: str) -> List:
        """Parse rug pull analysis into risk factors for ML training"""
        
        # Import here to avoid circular imports
        from ..data_collector import RiskFactor, RiskLevel, DataSourceType
        
        risk_factors = []
        
        if not raw_data or not raw_data.get('found_rugpull_data'):
            return risk_factors
        
        probability = raw_data.get('rug_pull_probability', 0)
        risk_level_str = raw_data.get('risk_level', 'low')
        confidence = raw_data.get('confidence_score', 0.5)
        
        # Map risk level string to enum
        risk_level_map = {
            'low': RiskLevel.LOW,
            'medium': RiskLevel.MEDIUM,
            'high': RiskLevel.HIGH,
            'critical': RiskLevel.CRITICAL
        }
        
        risk_level = risk_level_map.get(risk_level_str, RiskLevel.MEDIUM)
        
        # Overall rug pull risk
        if probability > 0.3:
            risk_factors.append(RiskFactor(
                type="rug_pull_risk",
                description=f"Rug pull probability: {probability:.2f} ({risk_level_str} risk)",
                risk_level=risk_level,
                confidence=confidence,
                source=DataSourceType.DEFI,
                raw_data={'probability': probability, 'risk_level': risk_level_str}
            ))
        
        # Specific red flags
        red_flags = raw_data.get('red_flags', [])
        for flag in red_flags:
            if 'critical_liquidity' in flag or 'coordinated_selling' in flag:
                flag_risk_level = RiskLevel.CRITICAL
            elif 'high_liquidity' in flag or 'concentration' in flag:
                flag_risk_level = RiskLevel.HIGH
            else:
                flag_risk_level = RiskLevel.MEDIUM
            
            risk_factors.append(RiskFactor(
                type=f"rugpull_{flag}",
                description=f"Rug pull indicator: {flag.replace('_', ' ')}",
                risk_level=flag_risk_level,
                confidence=0.8,
                source=DataSourceType.DEFI,
                raw_data={'red_flag': flag}
            ))
        
        return risk_factors
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rug pull detector statistics"""
        
        return {
            'supported_dexes': list(self.DEX_APIS.keys()),
            'default_dex': self.default_dex,
            'analysis_period_days': self.analysis_period_days,
            'min_liquidity_usd': self.min_liquidity_usd,
            'critical_liquidity_removal_threshold': self.critical_liquidity_removal,
            'high_concentration_threshold': self.high_concentration_threshold,
            'cache_entries': len(self.cache) if hasattr(self.cache, '__len__') else 'unknown'
        }