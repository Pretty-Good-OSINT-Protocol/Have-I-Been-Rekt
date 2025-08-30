# API Keys Setup Guide

## Required API Keys for Full Functionality

### 🔐 Essential Keys (Required)

1. **Have I Been Pwned (HIBP) API Key**
   - **Get it**: https://haveibeenpwned.com/API/Key
   - **Cost**: ~$3.50/month
   - **Usage**: Email breach detection
   - **Environment Variable**: `HIBP_API_KEY`

2. **VirusTotal API Key** 
   - **Get it**: https://developers.virustotal.com/reference/getting-started
   - **Cost**: Free tier available (4 requests/minute)
   - **Usage**: Malware intelligence
   - **Environment Variable**: `VIRUSTOTAL_API_KEY`

### 💎 Premium Keys (Optional but Recommended)

3. **Chainalysis API Key**
   - **Get it**: Contact Chainalysis sales
   - **Cost**: Enterprise pricing
   - **Usage**: Professional crypto intelligence
   - **Environment Variable**: `CHAINALYSIS_API_KEY`

### 🆓 Free Data Sources (No Keys Required)

- ✅ **GraphSense TagPacks**: Public repository
- ✅ **Elliptic Dataset**: Academic dataset
- ✅ **Ransomwhere**: Public ransomware database
- ✅ **OFAC Sanctions**: Government data

## Quick Setup

1. **Copy environment template**:
   ```bash
   cp .env.example .env
   ```

2. **Edit .env file**:
   ```bash
   nano .env
   # or
   code .env
   ```

3. **Add your keys**:
   ```env
   HIBP_API_KEY=your_hibp_key_here
   VIRUSTOTAL_API_KEY=your_virustotal_key_here
   CHAINALYSIS_API_KEY=your_chainalysis_key_here  # Optional
   ```

## Minimal Setup (Free Tier)

If you want to test without any paid APIs:

```env
# Minimal free setup - edit .env
HIBP_API_KEY=
VIRUSTOTAL_API_KEY=
CHAINALYSIS_API_KEY=

# The system will still work with:
# - GraphSense entity attribution
# - Ransomware database lookups  
# - OFAC sanctions checking
# - Machine learning risk scoring
```

## API Key Priority

1. **Start with VirusTotal** (free tier)
2. **Add HIBP** if you need email breach checking
3. **Add Chainalysis** for enterprise features

## Testing Without Keys

You can test the system with sample data:

```bash
# Train models with sample data (no APIs needed)
python train_risk_models.py

# Start API in demo mode
DEMO_MODE=true docker-compose up
```

## Security Best Practices

- ✅ Never commit API keys to git
- ✅ Use environment variables
- ✅ Rotate keys regularly
- ✅ Monitor API usage/billing
- ✅ Use least-privilege access

## Cost Estimates

| Service | Free Tier | Paid Tier | Use Case |
|---------|-----------|-----------|-----------|
| VirusTotal | 4 req/min | $0.01/req | Malware intel |
| HIBP | None | $3.50/month | Breach data |
| Chainalysis | None | Enterprise | Professional |

**Monthly cost for full features**: ~$4-10 for small scale usage

## Troubleshooting

### API Key Not Working?
```bash
# Test your keys
curl -H "hibp-api-key: YOUR_KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com"

curl -H "x-apikey: YOUR_KEY" \
  "https://www.virustotal.com/api/v3/analyses"
```

### Rate Limits?
- HIBP: 1 request per 1.5 seconds
- VirusTotal: 4 requests per minute (free)
- Our API handles rate limiting automatically

### Missing Keys?
The system gracefully degrades:
- Without HIBP: No email breach checking
- Without VirusTotal: No malware intelligence  
- Without Chainalysis: No commercial intel
- Core ML risk scoring always works