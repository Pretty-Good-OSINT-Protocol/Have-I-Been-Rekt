# Issue #3: Integrate Community Scam Databases  

## Labels
`dev-task`, `ai-training`, `estimate:10h`, `priority:high`

## Description
Implement data collectors for community-maintained scam databases and threat intelligence sources. These provide the bulk of training data for scam detection.

## Acceptance Criteria

### CryptoScamDB Integration
- [ ] Implement GitHub API client for CryptoScamDB repo
- [ ] Parse scam address lists and domain blacklists
- [ ] Extract metadata (scam type, report date, URLs)
- [ ] Handle multiple data formats (JSON, CSV, TXT)
- [ ] Create incremental update mechanism

### Chainabuse Integration  
- [ ] Implement web scraping client (respectful rate limiting)
- [ ] Parse ~220k community reports across chains
- [ ] Extract report details, addresses, and context
- [ ] Handle pagination and search functionality
- [ ] Add data quality scoring

### Whale Alert / Scam-Alert.io
- [ ] Investigate API availability and access
- [ ] Implement address lookup functionality
- [ ] Parse real-time scam notifications
- [ ] Handle ~130k address blacklist
- [ ] Add confidence scoring

### ScamSearch.io Global Database
- [ ] Implement REST API client
- [ ] Query emails, usernames, crypto addresses  
- [ ] Handle 4M+ scammer entries
- [ ] Cross-reference identity data
- [ ] Manage API quotas and costs

## Technical Implementation

### CryptoScamDB Collector
```python
class CryptoScamDBCollector:
    def fetch_github_data(self) -> Dict[str, List]
    def parse_address_lists(self) -> List[ScamAddress]
    def parse_domain_lists(self) -> List[ScamDomain]
    def get_last_update(self) -> datetime
    def validate_addresses(self, addresses: List[str]) -> List[str]
```

### Chainabuse Scraper
```python
class ChainabuseCollector:
    def search_address(self, address: str) -> List[Report]
    def scrape_recent_reports(self, limit: int) -> List[Report]
    def parse_report_details(self, report_html: str) -> Report
    def respect_rate_limits(self, delay_seconds: float)
```

### Data Schema
```python
ScamReport = {
    "address": "0x...",
    "blockchain": "ethereum", 
    "scam_type": ["phishing", "fake_token"],
    "description": "Fake Uniswap website...",
    "source": "cryptoscamdb",
    "report_date": "2023-12-01",
    "reporter": "anonymous",
    "confidence": 0.8,
    "references": ["https://..."],
    "amount_lost": 1250.0,
    "currency": "USDC"
}
```

## Data Quality Measures
- [ ] Address format validation
- [ ] Duplicate detection and merging
- [ ] Source credibility scoring
- [ ] Report age weighting
- [ ] Cross-source verification

## Rate Limiting & Ethics
- [ ] Respect robots.txt and API terms
- [ ] Implement exponential backoff
- [ ] Add random delays to avoid detection
- [ ] Cache responses to minimize requests
- [ ] Monitor for IP blocking

## Definition of Done
- [ ] All 4 sources fully integrated
- [ ] Data quality validation pipeline working
- [ ] Automated daily/weekly updates
- [ ] Comprehensive test coverage
- [ ] Performance optimizations implemented
- [ ] Ethical scraping practices confirmed

## Estimated Time: 10 hours

## Dependencies: Issue #1 (Infrastructure)

## Related Issues: #4, #7 (Risk Scoring), #8 (ML Training)