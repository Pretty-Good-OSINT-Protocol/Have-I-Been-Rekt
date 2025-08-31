# 🤖 Have I Been Rekt - Agent Architecture & Prompt Engineering

## 🎯 Core Agent Design

### **Mission Statement**
"An intelligent cryptocurrency incident response agent that analyzes wallet addresses, identifies risks, and generates actionable intelligence reports with varying depth based on subscription tier."

---

## 🔄 Agent Workflow Sequence

### **Phase 1: Input Analysis & Validation**
```
User Input → Address Validation → Chain Detection → Query Classification
```

**Prompt Template:**
```python
INITIAL_ANALYSIS_PROMPT = """
You are a blockchain security analyst. Given the following input:
- Address: {address}
- Chain: {chain}
- User Tier: {tier}

First, validate this is a legitimate blockchain address and determine:
1. Address type (wallet/contract/exchange)
2. Chain confirmation (Ethereum/Bitcoin/BSC/etc)
3. Risk assessment priority level
4. Which data sources to query based on tier

Respond in JSON format with your analysis plan.
"""
```

### **Phase 2: Intelligence Gathering (Tier-Based)**

#### **FREE TIER** (Training Data Only)
```
Query → Cached Intelligence → ML Models → Basic Report
```

**Data Sources:**
- Pre-trained ML model predictions
- Cached Elliptic dataset patterns
- Basic Ethereum fraud detection
- Historical crime database (offline)

#### **PAID TIER** (Live APIs + Training Data)
```
Query → Live APIs + Cached Data → Enhanced ML → Comprehensive Report
```

**Additional Sources:**
- ✅ HIBP (breach correlation)
- ✅ Shodan (infrastructure analysis)
- ✅ VirusTotal (malware association)
- ✅ AbuseIPDB (IP reputation)
- Real-time blockchain queries
- DeFi protocol analysis
- MEV detection

---

## 📊 Report Generation Architecture

### **Standardized Report Format**

```python
REPORT_GENERATION_PROMPT = """
Generate a comprehensive risk assessment report for address {address}.

Intelligence gathered:
{intelligence_data}

Generate a report with these sections:

## 🎯 EXECUTIVE SUMMARY
- Risk Score: [0.0-1.0]
- Risk Level: [CRITICAL/HIGH/MEDIUM/LOW/CLEAN]
- Confidence: [percentage]
- Key Finding: [one sentence]

## 🔍 DETAILED ANALYSIS

### Threat Intelligence
{list all findings from threat sources}

### Network Analysis  
{address relationships and suspicious patterns}

### Historical Activity
{past incidents and crime associations}

### {IF ETHEREUM} DeFi Exposure
{protocol risks and MEV analysis}

## ⚠️ RISK FACTORS
1. [Factor]: [Description] (Weight: X.X)
2. [Factor]: [Description] (Weight: X.X)

## 💡 RECOMMENDATIONS
- Immediate Actions: {what to do now}
- Monitoring Suggestions: {ongoing vigilance}
- Mitigation Strategies: {risk reduction}

## 📈 CONFIDENCE METRICS
- Data Sources Queried: {count}
- Data Freshness: {timestamp}
- Model Confidence: {percentage}

## 🔄 FOLLOW-UP QUESTIONS
Based on this analysis, would you like to:
1. {contextual follow-up question}
2. {deeper analysis option}
3. {related investigation path}

{IF FREE_TIER}
📢 UPGRADE NOTICE: This report used cached data only. 
Upgrade for real-time intelligence and {list 3 premium features}.
{/IF}
"""
```

---

## 🧠 Prompt Engineering Strategy

### **System Prompts**

#### **Master System Prompt**
```python
SYSTEM_PROMPT = """
You are HIBR-AI, an expert blockchain forensics analyst specializing in cryptocurrency fraud detection and risk assessment.

Core Capabilities:
- Multi-source threat intelligence aggregation
- Ethereum ecosystem expertise (DeFi, MEV, smart contracts)
- Bitcoin network analysis (Elliptic patterns)
- Cross-chain correlation
- Real-time risk scoring

Behavioral Guidelines:
1. ALWAYS provide risk scores with confidence levels
2. NEVER make accusations - present evidence objectively
3. PRIORITIZE user safety and loss prevention
4. EXPLAIN technical findings in accessible language
5. SUGGEST actionable next steps
6. IDENTIFY patterns across multiple data sources

Output Standards:
- Use structured markdown for all reports
- Include visual risk indicators (🔴🟠🟡🟢⚪)
- Provide timestamp for all findings
- Cite data sources for transparency
- Generate follow-up questions based on findings
"""
```

#### **Chain-of-Thought Reasoning**
```python
COT_ANALYSIS_PROMPT = """
Analyze this address step-by-step:

Step 1: Direct Risk Indicators
- Is this address on any blacklists? {check}
- Are there scam reports? {count}
- Sanctions status? {verify}

Step 2: Network Analysis
- Who has this address transacted with? {analyze}
- Are connected addresses suspicious? {evaluate}
- What patterns emerge? {identify}

Step 3: Behavioral Analysis
- Transaction frequency? {measure}
- Amount patterns? {analyze}
- Time patterns? {detect}

Step 4: Cross-Reference Intelligence
- Correlate findings across sources
- Weight evidence by reliability
- Calculate composite risk score

Step 5: Generate Insights
- What is the primary risk?
- What evidence supports this?
- What actions should be taken?
"""
```

---

## 🎭 Tier-Based Logic

### **Free Tier Capabilities**
```python
FREE_TIER_CONFIG = {
    "data_sources": [
        "cached_ml_predictions",
        "offline_crime_database",
        "basic_pattern_matching"
    ],
    "report_depth": "basic",
    "api_calls": 0,
    "response_time": "instant",
    "follow_ups": 1,
    "upgrade_prompts": True
}
```

### **Paid Tier Capabilities**
```python
PAID_TIER_CONFIG = {
    "data_sources": [
        "all_free_tier_sources",
        "live_api_calls",
        "real_time_blockchain",
        "defi_protocol_analysis",
        "cross_chain_correlation"
    ],
    "report_depth": "comprehensive",
    "api_calls": "unlimited",
    "response_time": "2-5 seconds",
    "follow_ups": "unlimited",
    "upgrade_prompts": False,
    "additional_features": [
        "continuous_monitoring",
        "alert_notifications",
        "bulk_analysis",
        "api_access"
    ]
}
```

---

## 🔄 Follow-Up Question Engine

### **Context-Aware Questions**
```python
FOLLOWUP_GENERATION_PROMPT = """
Based on the analysis showing {risk_level} risk with primary factor being {main_risk_factor},
generate 3 relevant follow-up questions:

1. [Investigation depth]: "Would you like me to analyze the {next_hop_addresses} addresses 
   that have transacted with this wallet?"

2. [Time analysis]: "Should I examine the transaction patterns during {suspicious_time_period} 
   when unusual activity was detected?"

3. [Related search]: "This address shows patterns similar to {pattern_type}. 
   Would you like to see other addresses with similar characteristics?"

For FREE tier, add:
4. [Upgrade prompt]: "Would you like real-time blockchain data and {premium_feature} 
   analysis available in the paid version?"
"""
```

---

## 🚀 Implementation Flow

### **Request Processing Pipeline**
```python
async def process_request(address: str, tier: str) -> Report:
    # 1. Validate & Classify
    validation = await validate_address(address)
    chain = detect_chain(address)
    
    # 2. Query Intelligence (tier-based)
    if tier == "free":
        intel = await query_cached_intelligence(address)
    else:
        intel = await query_all_sources(address)
    
    # 3. ML Risk Scoring
    risk_score = await calculate_risk_score(intel)
    
    # 4. Generate Report
    report = await generate_report(
        address=address,
        intel=intel,
        risk_score=risk_score,
        tier=tier
    )
    
    # 5. Add Follow-ups
    report.follow_ups = generate_followup_questions(
        report.findings,
        tier=tier
    )
    
    return report
```

---

## 📊 Report Examples

### **Free Tier Report Example**
```markdown
## 🎯 EXECUTIVE SUMMARY
- **Risk Score**: 0.72/1.0
- **Risk Level**: 🟠 HIGH
- **Confidence**: 78%
- **Key Finding**: Address shows patterns consistent with known phishing operations

## 🔍 ANALYSIS (Based on Cached Data)
- Matches 3 fraud patterns in training data
- Similar to 12 known scam addresses
- Last updated: 2 days ago

## 💡 RECOMMENDATIONS
- Do not send funds
- Consider upgrading for real-time analysis

## 🔄 FOLLOW-UP
1. Check related addresses?
2. **Upgrade for live monitoring and 10+ additional data sources**
```

### **Paid Tier Report Example**
```markdown
## 🎯 EXECUTIVE SUMMARY  
- **Risk Score**: 0.89/1.0
- **Risk Level**: 🔴 CRITICAL
- **Confidence**: 94%
- **Key Finding**: Active phishing address with 47 victim transactions in last 24 hours

## 🔍 DETAILED ANALYSIS

### Threat Intelligence
- **HIBP**: 3 associated emails in breaches
- **Shodan**: Linked infrastructure hosting phishing sites
- **VirusTotal**: Address found in 5 malware samples

### Network Analysis
- Connected to 3 sanctioned addresses (2 hops)
- Funds traced to known mixer contracts
- Pattern matches Lazarus Group methodology

### DeFi Exposure
- Interacted with compromised Uniswap pools
- MEV bot victim (12 transactions, $45K extracted)

## ⚠️ RISK FACTORS
1. Active scam operations (Weight: 0.9)
2. Sanctions exposure (Weight: 0.8)
3. Malware association (Weight: 0.7)

## 💡 RECOMMENDATIONS
- **Immediate**: Block all interactions
- **Report**: File with IC3 and local authorities
- **Monitor**: Set alerts for any movement

## 🔄 FOLLOW-UP QUESTIONS
1. Analyze the 23 addresses that sent funds here?
2. Track where stolen funds were sent?
3. Generate evidence package for law enforcement?
```

---

## 🔐 Security & Privacy Considerations

### **Data Handling**
```python
PRIVACY_RULES = {
    "no_storage": ["personal_info", "ip_addresses"],
    "hash_before_cache": ["email_addresses"],
    "redact_in_logs": ["api_keys", "user_ids"],
    "retention": "30_days_max"
}
```

### **Rate Limiting**
```python
RATE_LIMITS = {
    "free_tier": {
        "requests_per_day": 10,
        "follow_ups_per_request": 1
    },
    "paid_tier": {
        "requests_per_minute": 10,
        "follow_ups_per_request": "unlimited"
    }
}
```

---

## 🎯 Success Metrics

### **Key Performance Indicators**
- **Accuracy**: >95% risk classification accuracy
- **Speed**: <2s for free tier, <5s for paid tier  
- **Coverage**: 10+ intelligence sources integrated
- **User Satisfaction**: Clear, actionable reports
- **Conversion**: Free → Paid tier upgrade rate

### **Quality Checks**
- No false positives on legitimate exchanges
- All findings must have evidence citations
- Reports must suggest concrete actions
- Follow-ups must be contextually relevant

---

This architecture ensures consistent, high-quality intelligence reports while maintaining clear differentiation between free and paid tiers. The prompt engineering focuses on evidence-based analysis with actionable outcomes.