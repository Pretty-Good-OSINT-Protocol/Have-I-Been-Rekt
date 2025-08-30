# Issue #2: Integrate Sanctions & Compliance Data Sources

## Labels
`dev-task`, `ai-training`, `estimate:6h`, `priority:critical`

## Description
Implement data collectors for critical sanctions and compliance databases. This is the highest priority component as it provides immediate legal/regulatory risk identification.

## Acceptance Criteria

### OFAC Sanctions Integration
- [ ] Implement OFAC SDN XML parser
- [ ] Create automated OFAC data updater (daily sync)
- [ ] Support for Bitcoin, Ethereum, and other major chains
- [ ] Extract sanctioned addresses, entities, and programs
- [ ] Add OFAC reference URLs and context

### Chainalysis Sanctions API
- [ ] Implement Chainalysis API client
- [ ] Support for real-time address screening
- [ ] Handle API rate limiting and errors
- [ ] Extract risk scores and entity information
- [ ] Parse contextual metadata (names, programs, dates)

### Data Processing
- [ ] Normalize address formats across chains
- [ ] Merge and deduplicate sanctions data
- [ ] Create unified sanctions dataset
- [ ] Implement incremental updates
- [ ] Add data quality validation

## Technical Implementation

### OFAC Data Collector
```python
class OFACSanctionsCollector:
    def fetch_sdn_list(self) -> List[SanctionedEntity]
    def parse_crypto_addresses(self, sdn_data) -> List[Address]
    def get_latest_update(self) -> datetime
    def is_address_sanctioned(self, address: str) -> SanctionResult
```

### Chainalysis API Client
```python
class ChainanalysisClient:
    def screen_address(self, address: str) -> ScreeningResult
    def batch_screen(self, addresses: List[str]) -> List[ScreeningResult]
    def get_entity_info(self, address: str) -> EntityInfo
```

### Data Schema
```python
SanctionedAddress = {
    "address": "0x...",
    "blockchain": "ethereum",
    "source": "ofac",
    "program": "DPRK",
    "entity_name": "Lazarus Group",
    "added_date": "2023-01-01",
    "reference_url": "...",
    "confidence": 1.0
}
```

## Test Data Requirements
- [ ] Mock OFAC XML responses
- [ ] Sample Chainalysis API responses  
- [ ] Known sanctioned addresses for validation
- [ ] Edge cases (invalid addresses, API failures)

## Definition of Done
- [ ] Both APIs fully integrated and tested
- [ ] Automated daily OFAC updates working
- [ ] Data validation preventing corrupt entries
- [ ] Performance benchmarks documented (<100ms per address)
- [ ] Error handling for all failure scenarios

## Estimated Time: 6 hours

## Dependencies: Issue #1 (Infrastructure)

## Related Issues: #3, #7 (Risk Scoring)