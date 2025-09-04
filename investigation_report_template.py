#!/usr/bin/env python3
"""
HIBR Investigation Report Template System
Generates comprehensive, educational reports for users based on form input and analysis
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

class AttackType(Enum):
    STEALER_MALWARE = "stealer_malware"
    PHISHING_WEBSITE = "phishing_website" 
    FAKE_AIRDROP = "fake_airdrop"
    ROMANCE_SCAM = "romance_scam"
    FAKE_SUPPORT = "fake_support"
    DRAINER_CONTRACT = "drainer_contract"
    SIM_SWAP = "sim_swap"
    SOCIAL_ENGINEERING = "social_engineering"
    UNKNOWN = "unknown"

@dataclass
class DataSourceResult:
    source: str
    description: str
    found_indicators: List[str]
    risk_level: str
    details: str
    cost: float = 0.0  # 0 for free sources

@dataclass
class AIAnalysis:
    attack_type: AttackType
    confidence_score: float
    risk_assessment: str
    behavioral_patterns: List[str]
    technical_indicators: List[str]

@dataclass
class InvestigationReport:
    victim_wallet: str
    incident_timestamp: datetime
    report_id: str
    
    # Free tier analysis
    free_sources_checked: List[DataSourceResult]
    ai_analysis: AIAnalysis
    
    # Paid tier opportunities
    premium_sources_available: List[DataSourceResult]
    estimated_investigation_cost: float

class ReportGenerator:
    """Generate user-friendly investigation reports"""
    
    ATTACK_TYPE_DESCRIPTIONS = {
        AttackType.STEALER_MALWARE: {
            "name": "Stealer Malware Attack",
            "description": "Malicious software designed to extract private keys and seed phrases",
            "common_vectors": ["Fake software downloads", "Malicious browser extensions", "Trojan applications"],
            "urgency": "HIGH - Change all passwords immediately"
        },
        AttackType.PHISHING_WEBSITE: {
            "name": "Phishing Website Scam", 
            "description": "Fake websites designed to capture wallet credentials",
            "common_vectors": ["Fake DeFi platforms", "Counterfeit exchange sites", "Malicious wallet connectors"],
            "urgency": "HIGH - Never reuse compromised seed phrase"
        },
        AttackType.FAKE_AIRDROP: {
            "name": "Fake Airdrop Scam",
            "description": "Fraudulent token distributions requiring wallet connection",
            "common_vectors": ["Social media promotions", "Fake official announcements", "Impersonator accounts"],
            "urgency": "MEDIUM - Review recent wallet transactions"
        },
        AttackType.DRAINER_CONTRACT: {
            "name": "Smart Contract Drainer",
            "description": "Malicious contracts with excessive token approval permissions",
            "common_vectors": ["Fake NFT mints", "Malicious DeFi interactions", "Approval farming"],
            "urgency": "HIGH - Revoke all token approvals immediately"
        },
        AttackType.UNKNOWN: {
            "name": "Unknown Attack Vector",
            "description": "Attack pattern not yet classified by our AI analysis",
            "common_vectors": ["Insufficient data", "Novel attack technique", "Mixed attack patterns"],
            "urgency": "MEDIUM - Take standard security precautions"
        }
    }

    def generate_free_tier_report(self, report: InvestigationReport) -> str:
        """Generate the free tier investigation report"""
        
        attack_info = self.ATTACK_TYPE_DESCRIPTIONS.get(
            report.ai_analysis.attack_type, 
            self.ATTACK_TYPE_DESCRIPTIONS[AttackType.UNKNOWN]
        )
        
        return f"""
# 🔍 HIBR Investigation Report
**Report ID:** {report.report_id}  
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}  
**Victim Wallet:** `{report.victim_wallet[:6]}...{report.victim_wallet[-4:]}`

---

## 🤖 AI Analysis Summary

### Attack Classification: **{attack_info['name']}**
**Confidence:** {report.ai_analysis.confidence_score:.1%} | **Risk Level:** {report.ai_analysis.risk_assessment}

{attack_info['description']}

**Urgency Level:** {attack_info['urgency']}

### 📊 Behavioral Pattern Analysis
{self._format_patterns(report.ai_analysis.behavioral_patterns)}

### 🔍 Technical Indicators Found
{self._format_indicators(report.ai_analysis.technical_indicators)}

---

## 📋 Data Sources Checked (Free Tier)

{self._format_free_sources(report.free_sources_checked)}

### 🎯 Total Free Indicators Checked: {sum(len(source.found_indicators) for source in report.free_sources_checked)}

---

## 🚀 Immediate Action Items (Free)

{self._generate_immediate_actions(report.ai_analysis.attack_type)}

---

## 💡 Enhanced Investigation Available

{self._generate_premium_upsell(report)}

---

## ⚖️ Legal Disclaimer

This report is for educational and research purposes only. HIBR provides information based on open-source intelligence and AI analysis. Always verify findings independently and consult legal professionals for formal incident response.

**Not Financial or Legal Advice** | **Community-Funded Research Tool**
        """.strip()
    
    def _format_patterns(self, patterns: List[str]) -> str:
        if not patterns:
            return "• No clear behavioral patterns detected in available data"
        
        return "\n".join(f"• {pattern}" for pattern in patterns)
    
    def _format_indicators(self, indicators: List[str]) -> str:
        if not indicators:
            return "• No technical indicators found in free-tier analysis"
        
        return "\n".join(f"• {indicator}" for indicator in indicators)
    
    def _format_free_sources(self, sources: List[DataSourceResult]) -> str:
        if not sources:
            return "• No threat intelligence sources checked (error in analysis)"
        
        result = []
        for source in sources:
            status = "🟢 CLEAR" if source.risk_level.lower() == "low" else f"🔴 {source.risk_level.upper()} RISK"
            result.append(f"""
### {source.source}
{source.description}  
**Status:** {status} | **Indicators Found:** {len(source.found_indicators)}

{source.details}
            """.strip())
        
        return "\n\n".join(result)
    
    def _generate_immediate_actions(self, attack_type: AttackType) -> str:
        base_actions = [
            "📱 **Screenshot this report** for your records",
            "🔄 **Generate a new wallet** with a fresh seed phrase", 
            "🚫 **Never reuse the compromised wallet** for new transactions",
            "📋 **Document the timeline** of when you first noticed issues"
        ]
        
        specific_actions = {
            AttackType.STEALER_MALWARE: [
                "🦠 **Run full antivirus scan** on all connected devices",
                "🔐 **Change all passwords** immediately (email, exchanges, etc.)",
                "📲 **Check browser extensions** and remove any suspicious ones"
            ],
            AttackType.DRAINER_CONTRACT: [
                "⚠️ **Revoke token approvals** using tools like Etherscan Token Approval",
                "🔍 **Review recent transactions** for additional malicious approvals",
                "📊 **Check other wallets** you may have connected to the same site"
            ],
            AttackType.PHISHING_WEBSITE: [
                "🌐 **Report the phishing site** to browser security teams",
                "📧 **Check email security** if you provided email to the fake site",
                "🔗 **Review bookmark collections** for other suspicious links"
            ]
        }
        
        type_actions = specific_actions.get(attack_type, [])
        all_actions = base_actions + type_actions
        
        return "\n".join(all_actions)
    
    def _generate_premium_upsell(self, report: InvestigationReport) -> str:
        return f"""
Our AI analysis suggests this was a **{self.ATTACK_TYPE_DESCRIPTIONS[report.ai_analysis.attack_type]['name']}**. 

For a complete investigation, we can check {len(report.premium_sources_available)} additional premium threat intelligence sources:

{self._format_premium_sources(report.premium_sources_available)}

### 🎯 Enhanced Investigation Includes:
• **Blockchain forensics** - Trace stolen funds across networks
• **Threat actor attribution** - Link to known scammer groups  
• **Historical analysis** - Check if scammer targeted others
• **Recovery opportunities** - Identify potential fund recovery paths
• **Law enforcement reporting** - Generate formal incident reports

### 💰 Total Cost: ${report.estimated_investigation_cost:.2f}
*Covers real-time API calls + AI analysis. Pay only for what you use.*

[🔍 **Start Enhanced Investigation**] [📋 **Learn More About Premium**]

### Why These Sources Matter:
Premium threat intelligence provides real-time data that static databases miss. This includes active C2 servers, fresh phishing domains, and behavioral analysis from security vendors monitoring live threats.
        """
    
    def _format_premium_sources(self, sources: List[DataSourceResult]) -> str:
        result = []
        for source in sources:
            cost_str = f"${source.cost:.2f}" if source.cost > 0 else "Included"
            result.append(f"• **{source.source}** - {source.description} ({cost_str})")
        
        return "\n".join(result)

# Example usage and test data
if __name__ == "__main__":
    # Example report generation
    test_sources = [
        DataSourceResult(
            source="HIBR AI Threat Detection",
            description="Local AI model trained on 725k threat samples",
            found_indicators=["suspicious domain pattern", "stealer-like behavioral signature"],
            risk_level="HIGH",
            details="Detected patterns consistent with info-stealer malware distribution. High confidence based on domain characteristics and timing patterns.",
            cost=0.0
        ),
        DataSourceResult(
            source="Abuse.ch MalwareBazaar", 
            description="Community-driven malware sample database",
            found_indicators=["sample_hash_match"],
            risk_level="MEDIUM",
            details="Found 1 related malware sample with similar TTPs from same time period. Suggests coordinated campaign.",
            cost=0.0
        )
    ]
    
    premium_sources = [
        DataSourceResult(
            source="VirusTotal Intelligence",
            description="Real-time multi-engine malware analysis",
            found_indicators=[],
            risk_level="UNKNOWN",
            details="Deep file analysis, network behavior, and attribution data",
            cost=2.50
        ),
        DataSourceResult(
            source="Shodan & SecurityTrails",
            description="Infrastructure and domain intelligence", 
            found_indicators=[],
            risk_level="UNKNOWN",
            details="Track hosting providers, registration data, and infrastructure overlap",
            cost=1.25
        )
    ]
    
    ai_analysis = AIAnalysis(
        attack_type=AttackType.STEALER_MALWARE,
        confidence_score=0.847,
        risk_assessment="HIGH",
        behavioral_patterns=[
            "Credential harvesting pattern detected in transaction timing",
            "Multiple small-value transactions consistent with automated tools",
            "Transaction destinations match known stealer wallet clusters"
        ],
        technical_indicators=[
            "Wallet compromised within 24h of suspicious download", 
            "Private key extracted via clipboard monitoring malware",
            "Funds moved to known money laundering service"
        ]
    )
    
    report = InvestigationReport(
        victim_wallet="0x742d35Cc6634C0532925a3b8D9BdEC4EABF2E5DE",
        incident_timestamp=datetime.now(),
        report_id="HIBR-20240904-7X8K2P",
        free_sources_checked=test_sources,
        ai_analysis=ai_analysis,
        premium_sources_available=premium_sources,
        estimated_investigation_cost=3.75
    )
    
    generator = ReportGenerator()
    print(generator.generate_free_tier_report(report))