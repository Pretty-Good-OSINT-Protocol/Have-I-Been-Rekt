# Have I Been Rekt - AI Agent Training Plan

## Overview
This document outlines the comprehensive plan for collecting, preparing, and training an AI agent capable of analyzing cryptocurrency wallet incidents using publicly available threat intelligence data sources.

## Training Objectives
The AI agent will be capable of:
1. **Risk Assessment**: Score wallet addresses based on known blacklists and sanctions
2. **Incident Classification**: Categorize types of crypto attacks/scams from user descriptions
3. **Attribution Analysis**: Link addresses to known entities, exchanges, or threat actors
4. **Recommendation Generation**: Provide actionable advice based on findings
5. **OSINT Integration**: Correlate findings across multiple data sources

## Data Collection Strategy

### Phase 1: Static Blacklists & Sanctions Data
**Priority: HIGH - Foundation for basic risk scoring**

#### 1.1 Wallet Blacklists
- **CryptoScamDB**: REST API + GitHub repositories
  - ~50k+ scam addresses and domains
  - Real-time API for address lookups
  - Open source licensing
  
- **Chainabuse (TRM Labs)**: Community reporting platform
  - ~220k reports across multi-chain
  - Web scraping + manual API requests
  - Free tier available
  
- **Whale Alert Scam Database**: ~130k fraudulent addresses
  - Real-time blacklist via Scam-Alert.io
  - API available on request
  - Covers major blockchains

#### 1.2 Sanctions & Compliance
- **OFAC Sanctioned Addresses**: U.S. Treasury official list
  - Auto-updated from SDN XML feeds
  - GitHub repo (0xB10C) provides clean JSON/TXT
  - Public domain data
  
- **Chainalysis Sanctions API**: Free compliance API
  - Real-time sanctions screening
  - Covers global watchlists (OFAC, UN, EU)
  - Contextual information included

### Phase 2: Malicious Contract Intelligence
**Priority: HIGH - Essential for DeFi scam detection**

#### 2.1 Smart Contract Threats
- **Honeypot.is API**: Token scam detection
  - Real-time honeypot simulation
  - Free API for individual checks
  - Covers BSC and Ethereum
  
- **Token Security Analysis**: Integration with multiple checkers
  - Automated contract verification
  - Rug pull detection patterns
  - Liquidity lock analysis

### Phase 3: Historical Crime Data
**Priority: MEDIUM - Training data for ML models**

#### 3.1 Ransomware & Cybercrime
- **Ransomwhere Dataset**: Ransomware payment addresses
  - ~$1B+ tracked payments
  - Attribution to malware families
  - CC-BY-4.0 licensed
  
- **Elliptic Illicit Dataset**: Labeled Bitcoin transactions
  - 203k+ transactions (2013-2015)
  - Ground truth labels for ML training
  - Extended version with 822k addresses
  - Academic/research use

#### 3.2 Breach Intelligence
- **Have I Been Pwned API**: Email/identity compromise checking
  - Billions of breach records
  - Free API with attribution
  - Privacy-respecting queries

### Phase 4: Attribution & Entity Mapping
**Priority: MEDIUM - Context for risk assessment**

#### 4.1 Address Attribution
- **GraphSense TagPacks**: Open address attribution
  - MIT licensed tagpacks
  - Exchange, mixer, service labels
  - Multi-blockchain coverage
  - API and bulk download available

#### 4.2 Cross-Reference Databases
- **ScamSearch.io**: Global scammer database
  - 4M+ scammer entries
  - Cross-reference emails, phones, addresses
  - REST API available
  
- **VirusTotal OSINT**: Malware configuration data
  - Address appearances in malware
  - Phishing URL associations
  - Free API tier

## Technical Architecture

### Data Pipeline
```
Raw Data Sources → Data Collectors → Data Processors → Training Dataset → Model Training → API Deployment
```

### Storage & Processing
- **Training Environment**: Google Colab / Hugging Face Spaces
- **Data Storage**: 
  - Raw data: JSON files in Git LFS
  - Processed datasets: Parquet format
  - Model artifacts: Hugging Face Model Hub
- **Processing**: Python + Pandas for ETL, Scikit-learn/PyTorch for ML

### Model Architecture Options
1. **Classification Model**: Risk scoring (High/Medium/Low/Clean)
2. **Multi-label Classification**: Incident type detection
3. **Named Entity Recognition**: Extract addresses, URLs, entities from text
4. **Recommendation Engine**: Rule-based + ML hybrid

## Data Schema Design

### Training Data Format
```python
{
    "wallet_address": "0x...",
    "risk_score": 0.0-1.0,
    "risk_factors": [
        {
            "source": "ofac_sanctions",
            "severity": "critical",
            "description": "Address sanctioned by OFAC",
            "reference_url": "..."
        }
    ],
    "entity_labels": ["exchange", "mixer", "ransomware"],
    "incident_description": "User reported description...",
    "incident_classification": ["phishing", "fake_token"],
    "recommendations": ["Contact exchange", "File police report"],
    "data_sources_checked": ["cryptoscamdb", "chainabuse", "ofac"],
    "last_updated": "2024-01-01T00:00:00Z"
}
```

## Implementation Phases

### Phase 1: Foundation (Weeks 1-2)
- Set up data collection infrastructure
- Implement basic API integrations
- Create data validation pipeline
- Build initial risk scoring model

### Phase 2: Enhancement (Weeks 3-4)
- Add machine learning components
- Integrate historical crime datasets
- Implement incident classification
- Create recommendation engine

### Phase 3: Integration (Weeks 5-6)
- Connect with existing UI components
- Add real-time API endpoints
- Implement caching and rate limiting
- Create deployment pipeline

### Phase 4: Testing & Refinement (Weeks 7-8)
- Beta testing with known cases
- Model performance evaluation
- Security and privacy auditing
- Documentation and user guides

## Privacy & Security Considerations
- **No PII Storage**: Only public wallet addresses and public threat intel
- **Rate Limiting**: Respect API limits of external services
- **Attribution**: Proper crediting of data sources
- **Legal Compliance**: Ensure all data use is within terms of service
- **Anonymization**: Hash or tokenize any sensitive identifiers

## Success Metrics
- **Accuracy**: >90% on known scam address detection
- **Coverage**: Check against >500k known bad addresses
- **Speed**: <5 seconds for full analysis
- **Recall**: >95% detection of sanctioned addresses
- **User Satisfaction**: Clear, actionable recommendations

## Resources Required
- **Compute**: Google Colab Pro for training
- **Storage**: ~10GB for full datasets
- **APIs**: Free tiers initially, paid plans for production
- **Team**: 1-2 developers, ML experience helpful
- **Timeline**: 8 weeks to MVP, additional 4 weeks for production-ready

## Risk Mitigation
- **Data Quality**: Multiple validation layers and cross-referencing
- **API Failures**: Graceful degradation and cached fallbacks
- **False Positives**: Human review process for high-stakes alerts
- **Model Bias**: Diverse training data and regular rebalancing
- **Legal Risks**: Clear terms of service and disclaimer language