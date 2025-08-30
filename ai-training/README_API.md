# Have I Been Rekt AI Analysis API

Complete AI-powered cryptocurrency risk assessment system with machine learning models, multi-source intelligence gathering, and real-time analysis capabilities.

## 🚀 Quick Start

### Using Docker Compose (Recommended)

1. **Clone and setup**:
   ```bash
   git clone <repository-url>
   cd Have-I-Been-Rekt/ai-training
   cp .env.example .env
   # Edit .env with your API keys
   ```

2. **Start services**:
   ```bash
   docker-compose up -d ai-api redis
   ```

3. **Access API**:
   - API: http://localhost:8000
   - Docs: http://localhost:8000/docs
   - Health: http://localhost:8000/health

### Local Development

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r api/requirements.txt
   ```

2. **Start Redis** (optional, for caching):
   ```bash
   docker run -d -p 6379:6379 redis:7-alpine
   ```

3. **Run API server**:
   ```bash
   python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
   ```

## 📊 API Endpoints

### Single Address Analysis
```bash
POST /api/v1/analyze
Content-Type: application/json

{
  "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "options": {
    "include_recommendations": true,
    "check_breach_data": true,
    "deep_analysis": false,
    "include_attribution": true,
    "include_crime_history": true,
    "explanation_level": "standard"
  }
}
```

**Response:**
```json
{
  "request_id": "uuid-here",
  "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "risk_assessment": {
    "risk_score": 0.15,
    "risk_level": "LOW",
    "risk_category": "CLEAN", 
    "confidence": 0.89,
    "primary_concerns": []
  },
  "recommendations": [
    {
      "priority": "low",
      "action": "standard_processing",
      "description": "Address appears safe for standard processing",
      "reason": "Low risk score (0.15) indicates minimal threat"
    }
  ],
  "data_sources": [...],
  "processing_time_ms": 1250,
  "cached": false
}
```

### Batch Analysis
```bash
POST /api/v1/analyze/batch
Content-Type: application/json

{
  "addresses": [
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
  ],
  "options": { ... }
}
```

### Health Check
```bash
GET /health
```

## 🧠 AI Analysis Components

### Risk Scoring Engine
- **5-tier risk classification**: CLEAN, SUSPICIOUS, HIGH_RISK, CRIMINAL, SANCTIONED
- **Weighted multi-source scoring** with configurable source weights
- **ML model integration** for enhanced accuracy
- **Incident type prediction** (ransomware, scams, money laundering, etc.)

### Data Sources Integrated
1. **Government Sources**: OFAC sanctions, law enforcement databases
2. **Crime Intelligence**: HIBP breach data, ransomware tracking, Elliptic dataset
3. **Commercial Intelligence**: Chainalysis, GraphSense TagPacks, VirusTotal
4. **Community Sources**: Crypto scam databases, community reports
5. **Behavioral Analysis**: Entity relationship mapping, transaction patterns

### Machine Learning Models
- **Binary Classification**: Clean vs Risky (>90% accuracy)
- **Multi-class Classification**: Risk level prediction
- **Feature Engineering**: 50+ features from all data sources
- **Explainable AI**: SHAP values for transparent predictions

## 🔧 Configuration

### Environment Variables
```bash
# API Configuration
HOST=0.0.0.0
PORT=8000
LOG_LEVEL=INFO

# Data Source APIs (get your keys)
HIBP_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
CHAINALYSIS_API_KEY=your_key_here

# Caching
REDIS_URL=redis://localhost:6379

# Security
SECRET_KEY=generate-secure-key
CORS_ORIGINS=http://localhost:3000

# Performance
MAX_WORKERS=4
RATE_LIMIT_REQUESTS_PER_MINUTE=10
```

### Analysis Options

| Option | Description | Default |
|--------|-------------|---------|
| `include_recommendations` | Get actionable recommendations | `true` |
| `check_breach_data` | Check email breach databases | `true` |
| `deep_analysis` | Enhanced analysis (slower) | `false` |
| `include_attribution` | Entity attribution data | `true` |
| `include_crime_history` | Historical crime intelligence | `true` |
| `explanation_level` | Detail level: minimal/standard/detailed | `standard` |

## 📈 Performance & Scaling

### Performance Targets
- **Response Time**: < 5 seconds for single analysis
- **Throughput**: 100+ concurrent requests
- **Accuracy**: >90% for critical threats
- **Uptime**: 99.9% availability target

### Scaling Options
1. **Horizontal Scaling**: Multiple API instances behind load balancer
2. **Caching**: Redis for analysis result caching
3. **Background Processing**: Async analysis for batch operations
4. **Database Optimization**: Indexed lookups for large datasets

### Kubernetes Deployment
```bash
# Apply Kubernetes manifests
kubectl apply -f deploy/kubernetes.yaml

# Scale replicas
kubectl scale deployment hibr-ai-api --replicas=5
```

## 🔍 Frontend Integration

### JavaScript/React Integration
```javascript
import { AnalysisService } from './AnalysisService';
import AnalysisResultCard from './AnalysisResultCard';

const analysisService = new AnalysisService('http://localhost:8000/api/v1');

// Analyze address
const result = await analysisService.analyzeAddress('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');

// Display results
<AnalysisResultCard analysisResult={result} />
```

### Components Provided
- `AnalysisService.js`: API integration service
- `AnalysisResultCard.jsx`: Results display component  
- `EnhancedAnalysisForm.jsx`: Advanced analysis form
- CSS styling for professional UI

## 🛠️ Development

### Training ML Models
```bash
# Train models with sample data
python train_risk_models.py --config config/ml_training_config.json

# With custom configuration
python train_risk_models.py --config my_config.json --log-level DEBUG
```

### Testing
```bash
# Run API tests
pytest api/tests/

# Test specific endpoint
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}'
```

### Monitoring
- **Health Check**: `/health` endpoint
- **Metrics**: Prometheus integration available
- **Logging**: Structured logging with request IDs
- **Error Tracking**: Sentry integration supported

## 📊 Data Privacy & Compliance

### Privacy Features
- **No persistent storage** of analyzed addresses by default
- **Configurable data retention** periods
- **GDPR compliance** options available
- **Audit logging** for compliance requirements

### Security
- **Rate limiting** to prevent abuse
- **API key authentication** support
- **CORS configuration** for web integration
- **Input validation** and sanitization

## 🚀 Production Deployment

### Requirements
- **Memory**: 2GB+ per API instance
- **CPU**: 2+ cores recommended  
- **Storage**: 10GB for cache, 5GB for models
- **Network**: Low latency for optimal performance

### Monitoring Stack
- **API Monitoring**: Health checks, response times
- **Resource Monitoring**: CPU, memory, disk usage
- **Error Tracking**: Failed analyses, API errors
- **Performance Metrics**: Throughput, cache hit rates

## 🔗 Integration Examples

### Webhook Integration
```python
# Receive analysis results via webhook
@app.post("/webhook/analysis")
async def analysis_webhook(result: dict):
    # Process analysis result
    if result['risk_assessment']['risk_level'] in ['HIGH', 'CRITICAL']:
        await alert_security_team(result)
```

### Batch Processing
```python
# Process large address lists
addresses = load_addresses_from_file("suspicious_addresses.csv")
batch_result = await analysis_service.analyze_batch(addresses)

# Export results
export_to_csv(batch_result.results, "analysis_results.csv")
```

## 📞 Support

- **Documentation**: `/docs` endpoint for interactive API docs
- **Health Status**: `/health` for system status
- **Logs**: Check application logs for troubleshooting
- **Issues**: Report bugs via GitHub issues

---

**Built with**: FastAPI, scikit-learn, Redis, Docker
**License**: MIT
**Maintained by**: Have I Been Rekt AI Team