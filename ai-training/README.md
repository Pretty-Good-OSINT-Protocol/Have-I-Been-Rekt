# Have I Been Rekt - AI Training Module

## Overview
This module contains the AI training pipeline and data collection infrastructure for the "Have I Been Rekt" cryptocurrency incident analysis tool.

## Quick Start

### Prerequisites
- Python 3.9+
- Google Colab account (for training)
- API keys for external services (see Configuration)

### Installation
```bash
# Clone and navigate to training module
cd ai-training

# Install dependencies
pip install -r requirements.txt

# Set up configuration
cp config/config.example.json config/config.json
# Edit config.json with your API keys
```

### Basic Usage
```python
from src.data_collector import DataCollector
from src.risk_analyzer import RiskAnalyzer

# Initialize components
collector = DataCollector()
analyzer = RiskAnalyzer()

# Analyze a wallet address
result = analyzer.analyze_address("0x1234...")
print(f"Risk Score: {result['risk_score']}")
```

## Architecture

### Data Flow
```
External APIs → Data Collectors → Data Processors → Feature Extractors → ML Models → Risk Reports
```

### Key Components
1. **Data Collectors**: Fetch data from various OSINT sources
2. **Risk Analyzer**: Core analysis engine combining multiple signals
3. **Model Trainer**: ML model training and evaluation
4. **API Server**: REST API for integration with frontend

### Supported Data Sources

#### Sanctions & Compliance (Priority: Critical)
- ✅ **OFAC Sanctions**: U.S. Treasury sanctioned addresses
- ✅ **Chainalysis API**: Global sanctions screening
- 🔄 **EU Sanctions**: European Union sanctioned entities

#### Threat Intelligence (Priority: High)
- ✅ **CryptoScamDB**: Community-reported scam addresses
- 🔄 **Chainabuse**: Multi-chain scam reporting platform
- 🔄 **Whale Alert**: Real-time scam address detection
- 🔄 **ScamSearch**: Global scammer database

#### Smart Contract Analysis (Priority: High)
- 🔄 **Honeypot.is**: Token scam detection
- 🔄 **Token Security**: Automated contract analysis
- 🔄 **Rug Pull Detection**: Liquidity and ownership analysis

#### Attribution & Context (Priority: Medium)
- 🔄 **GraphSense TagPacks**: Address entity attribution
- 🔄 **Exchange Address Lists**: Known exchange wallets
- 🔄 **Mixer Detection**: Privacy coin and mixer identification

#### Historical Crime Data (Priority: Medium)
- 🔄 **Ransomwhere**: Ransomware payment addresses
- 🔄 **Elliptic Dataset**: Labeled illicit Bitcoin transactions
- 🔄 **Have I Been Pwned**: Email compromise checking

#### Malware Intelligence (Priority: Low)
- 🔄 **VirusTotal**: Addresses in malware configurations
- 🔄 **URLVoid**: Malicious URL detection

### Risk Scoring Framework

#### Risk Levels
- **🔴 CRITICAL (0.8-1.0)**: OFAC sanctioned, confirmed ransomware
- **🟠 HIGH (0.6-0.8)**: Multiple scam reports, honeypot contracts  
- **🟡 MEDIUM (0.4-0.6)**: Single reports, mixer usage
- **🟢 LOW (0.2-0.4)**: Suspicious patterns, unverified reports
- **⚪ CLEAN (0.0-0.2)**: No negative indicators found

#### Risk Factors
Each factor contributes to the overall risk score:
```python
risk_factors = {
    "sanctions": {"weight": 1.0, "critical": True},
    "scam_reports": {"weight": 0.7, "count_multiplier": 0.1},
    "honeypot_interaction": {"weight": 0.8, "critical": False},
    "mixer_usage": {"weight": 0.3, "context_dependent": True},
    "breach_exposure": {"weight": 0.2, "correlation_bonus": 0.1}
}
```

## Data Schema

### Core Data Structure
```python
WalletAnalysis = {
    "address": "0x...",
    "analysis_timestamp": "2024-01-01T00:00:00Z",
    "risk_score": 0.75,
    "risk_level": "HIGH", 
    "confidence": 0.92,
    "risk_factors": [
        {
            "source": "cryptoscamdb",
            "factor_type": "scam_report",
            "severity": "high",
            "weight": 0.7,
            "description": "Address reported for phishing scam",
            "reference_url": "https://...",
            "first_seen": "2023-12-01",
            "report_count": 15
        }
    ],
    "entity_attribution": {
        "entity_type": "unknown",
        "confidence": 0.1,
        "possible_entities": []
    },
    "transaction_patterns": {
        "suspicious_activity": False,
        "mixer_usage": False,
        "high_frequency_trading": False
    },
    "recommendations": [
        {
            "action": "immediate",
            "description": "Do not send funds to this address",
            "reason": "Multiple scam reports confirmed"
        }
    ],
    "data_sources": ["cryptoscamdb", "ofac_sanctions", "chainalysis"],
    "metadata": {
        "processing_time_ms": 1250,
        "api_calls_made": 5,
        "cache_hits": 2
    }
}
```

### Training Data Format
```python
TrainingExample = {
    "address": "0x...",
    "ground_truth_label": "scam",  # scam, clean, suspicious, sanctioned
    "ground_truth_score": 0.9,
    "features": {
        "ofac_sanctioned": False,
        "scam_report_count": 12,
        "honeypot_interactions": 3,
        "mixer_transactions": 0,
        "exchange_deposits": 1,
        "age_days": 120,
        "transaction_count": 45,
        "unique_counterparties": 23
    },
    "labels": ["phishing", "fake_token", "rug_pull"],
    "source": "cryptoscamdb",
    "verified": True,
    "last_updated": "2024-01-01"
}
```

## Configuration

### Environment Setup
```bash
# Copy example configuration
cp config/config.example.json config/config.json

# Required API Keys (add to config.json):
{
    "api_keys": {
        "chainalysis": "your_chainalysis_key",
        "haveibeenpwned": "your_hibp_key",
        "virustotal": "your_vt_key"
    },
    "cache": {
        "enabled": true,
        "ttl_hours": 24,
        "max_size_mb": 500
    },
    "rate_limits": {
        "chainalysis": {"calls_per_minute": 100},
        "cryptoscamdb": {"calls_per_minute": 60},
        "haveibeenpwned": {"calls_per_minute": 10}
    }
}
```

### Free Tier Setup (No API Keys Required)
```bash
# Run with only free/public data sources
python src/analyzer.py --free-tier-only

# Uses: OFAC data, CryptoScamDB, GraphSense TagPacks, Ransomwhere
```

## Training Pipeline

### 1. Data Collection
```bash
# Collect training data from all sources
python scripts/collect_training_data.py

# Collect from specific source
python scripts/collect_training_data.py --source cryptoscamdb
```

### 2. Feature Engineering
```bash
# Generate features from raw data
python scripts/generate_features.py --input data/raw --output data/features
```

### 3. Model Training
```bash
# Train risk classification model
python scripts/train_model.py --model-type classification --data data/features/training.parquet

# Train with hyperparameter tuning
python scripts/train_model.py --model-type classification --tune-hyperparameters --cv-folds 5
```

### 4. Evaluation
```bash
# Evaluate on test set
python scripts/evaluate_model.py --model models/risk_classifier.pkl --test-data data/features/test.parquet
```

## API Reference

### Risk Analysis Endpoint
```python
POST /api/v1/analyze
{
    "address": "0x1234...",
    "include_recommendations": true,
    "check_breach_data": false  # optional, requires email
}

Response:
{
    "address": "0x1234...",
    "risk_score": 0.75,
    "risk_level": "HIGH",
    "analysis": { ... },
    "recommendations": [ ... ],
    "processing_time_ms": 1250
}
```

### Batch Analysis
```python
POST /api/v1/analyze/batch
{
    "addresses": ["0x1234...", "0x5678..."],
    "options": { ... }
}
```

## Development

### Running Tests
```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=src --cov-report=html
```

### Code Quality
```bash
# Format code
black src/ tests/

# Lint code  
flake8 src/ tests/

# Type checking
mypy src/
```

### Adding New Data Sources
1. Create collector class in `src/collectors/`
2. Add configuration to `config/sources.json`
3. Update `src/data_collector.py` to include new source
4. Add tests in `tests/collectors/`

## Deployment

### Local Development
```bash
# Start API server
python src/api_server.py --port 8000 --debug

# Start with Docker
docker-compose up -d
```

### Production (Hugging Face Spaces)
```bash
# Deploy to Hugging Face
git push origin main  # Triggers auto-deployment
```

## Troubleshooting

### Common Issues
1. **API Rate Limits**: Check `config/rate_limits.json` and adjust delays
2. **Missing Data**: Run `python scripts/validate_data.py` to check data integrity
3. **Model Performance**: Use `python scripts/debug_predictions.py` to analyze errors

### Debug Mode
```bash
# Enable detailed logging
export LOG_LEVEL=DEBUG
python src/analyzer.py --debug --verbose
```

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on:
- Code style and testing requirements
- Data source integration standards  
- Model evaluation criteria
- Privacy and security considerations

## License

MIT License - See [LICENSE](../LICENSE) for details.

---

**⚠️ Privacy Notice**: This tool only analyzes public blockchain data and publicly available threat intelligence. No private keys or personal data are collected or stored.