#!/usr/bin/env python3
"""
Report Generator with Prompt Engineering
Generates standardized risk assessment reports with tier-based logic
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass
import json
from enum import Enum


class RiskLevel(Enum):
    """Risk level classifications"""
    CRITICAL = ("🔴", 0.8, 1.0)
    HIGH = ("🟠", 0.6, 0.8)
    MEDIUM = ("🟡", 0.4, 0.6)
    LOW = ("🟢", 0.2, 0.4)
    CLEAN = ("⚪", 0.0, 0.2)
    
    def __init__(self, emoji: str, min_score: float, max_score: float):
        self.emoji = emoji
        self.min_score = min_score
        self.max_score = max_score
    
    @classmethod
    def from_score(cls, score: float) -> 'RiskLevel':
        """Get risk level from numerical score"""
        for level in cls:
            if level.min_score <= score < level.max_score:
                return level
        return cls.CLEAN


@dataclass
class RiskFactor:
    """Individual risk factor in analysis"""
    source: str
    factor_type: str
    description: str
    weight: float
    evidence: Optional[str] = None
    timestamp: Optional[datetime] = None


@dataclass
class IntelligenceReport:
    """Complete intelligence report structure"""
    address: str
    chain: str
    risk_score: float
    risk_level: RiskLevel
    confidence: float
    key_finding: str
    risk_factors: List[RiskFactor]
    recommendations: Dict[str, str]
    follow_up_questions: List[str]
    data_sources: List[str]
    is_free_tier: bool
    processing_time_ms: int
    timestamp: datetime


class ReportGenerator:
    """Generates formatted risk assessment reports"""
    
    # Master system prompt for the agent
    SYSTEM_PROMPT = """
You are HIBR-AI, an expert blockchain forensics analyst specializing in cryptocurrency 
fraud detection and risk assessment.

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
    
    def __init__(self, config: Dict[str, Any], logger=None):
        self.config = config
        self.logger = logger
        self.free_tier_sources = [
            "cached_ml_predictions",
            "elliptic_dataset", 
            "ethereum_fraud_dataset",
            "historical_crime_db"
        ]
        self.paid_tier_sources = [
            "hibp_api",
            "shodan_api",
            "virustotal_api",
            "abuseipdb_api",
            "real_time_blockchain",
            "defi_protocols",
            "mev_detection"
        ]
    
    def generate_report(
        self,
        address: str,
        intelligence_data: Dict[str, Any],
        risk_score: float,
        tier: str = "free"
    ) -> IntelligenceReport:
        """Generate a complete intelligence report"""
        
        # Determine risk level
        risk_level = RiskLevel.from_score(risk_score)
        
        # Extract risk factors from intelligence
        risk_factors = self._extract_risk_factors(intelligence_data)
        
        # Calculate confidence based on data sources
        confidence = self._calculate_confidence(intelligence_data, tier)
        
        # Generate key finding
        key_finding = self._generate_key_finding(risk_factors, risk_level)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            risk_level, risk_factors, tier
        )
        
        # Generate follow-up questions
        follow_ups = self._generate_follow_up_questions(
            risk_level, risk_factors, tier
        )
        
        # Determine data sources used
        data_sources = (
            self.free_tier_sources if tier == "free" 
            else self.free_tier_sources + self.paid_tier_sources
        )
        
        # Create report object
        report = IntelligenceReport(
            address=address,
            chain=intelligence_data.get("chain", "ethereum"),
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=confidence,
            key_finding=key_finding,
            risk_factors=risk_factors,
            recommendations=recommendations,
            follow_up_questions=follow_ups,
            data_sources=data_sources,
            is_free_tier=(tier == "free"),
            processing_time_ms=intelligence_data.get("processing_time_ms", 0),
            timestamp=datetime.utcnow()
        )
        
        return report
    
    def format_report_markdown(self, report: IntelligenceReport) -> str:
        """Format report as markdown"""
        
        md = f"""# 🔍 Blockchain Risk Assessment Report

**Address**: `{report.address}`  
**Chain**: {report.chain.upper()}  
**Generated**: {report.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")}

---

## 🎯 EXECUTIVE SUMMARY

- **Risk Score**: {report.risk_score:.2f}/1.00
- **Risk Level**: {report.risk_level.emoji} **{report.risk_level.name}**
- **Confidence**: {report.confidence:.0%}
- **Key Finding**: {report.key_finding}

---

## 🔍 DETAILED ANALYSIS

### Risk Factors Identified

"""
        
        # Add risk factors
        for i, factor in enumerate(report.risk_factors, 1):
            md += f"{i}. **{factor.factor_type}** (Weight: {factor.weight:.1f})\n"
            md += f"   - Source: {factor.source}\n"
            md += f"   - {factor.description}\n"
            if factor.evidence:
                md += f"   - Evidence: {factor.evidence}\n"
            md += "\n"
        
        # Add recommendations
        md += "## 💡 RECOMMENDATIONS\n\n"
        for action_type, recommendation in report.recommendations.items():
            md += f"### {action_type}\n{recommendation}\n\n"
        
        # Add confidence metrics
        md += f"""## 📈 CONFIDENCE METRICS

- **Data Sources Queried**: {len(report.data_sources)}
- **Processing Time**: {report.processing_time_ms}ms
- **Model Confidence**: {report.confidence:.0%}
- **Data Freshness**: Real-time""" + (" (cached)" if report.is_free_tier else "") + "\n\n"
        
        # Add follow-up questions
        md += "## 🔄 FOLLOW-UP QUESTIONS\n\n"
        md += "Based on this analysis, would you like to:\n\n"
        for i, question in enumerate(report.follow_up_questions, 1):
            md += f"{i}. {question}\n"
        
        # Add upgrade notice for free tier
        if report.is_free_tier:
            md += self._generate_upgrade_notice(report)
        
        return md
    
    def _extract_risk_factors(
        self, 
        intelligence_data: Dict[str, Any]
    ) -> List[RiskFactor]:
        """Extract risk factors from intelligence data"""
        
        factors = []
        
        # Check for sanctions
        if intelligence_data.get("sanctions"):
            factors.append(RiskFactor(
                source="OFAC",
                factor_type="Sanctions",
                description="Address is on sanctions list",
                weight=1.0,
                evidence=intelligence_data["sanctions"].get("listing_date")
            ))
        
        # Check for scam reports
        if intelligence_data.get("scam_reports", 0) > 0:
            count = intelligence_data["scam_reports"]
            factors.append(RiskFactor(
                source="CryptoScamDB",
                factor_type="Scam Reports",
                description=f"{count} scam reports filed",
                weight=min(0.7 + (count * 0.1), 1.0),
                evidence=f"{count} independent reports"
            ))
        
        # Check for breach exposure
        if intelligence_data.get("breach_exposure"):
            factors.append(RiskFactor(
                source="HIBP",
                factor_type="Breach Exposure",
                description="Associated credentials found in breaches",
                weight=0.3,
                evidence=intelligence_data["breach_exposure"].get("breach_count")
            ))
        
        # Check for DeFi risks (Ethereum specific)
        if intelligence_data.get("defi_risks"):
            defi = intelligence_data["defi_risks"]
            if defi.get("mev_victim"):
                factors.append(RiskFactor(
                    source="DeFi Analysis",
                    factor_type="MEV Exploitation",
                    description="Address has been victim of MEV attacks",
                    weight=0.5,
                    evidence=f"${defi.get('mev_losses', 0):,.0f} extracted"
                ))
        
        # Check for network patterns
        if intelligence_data.get("network_analysis"):
            network = intelligence_data["network_analysis"]
            if network.get("connected_to_illicit"):
                factors.append(RiskFactor(
                    source="Network Analysis",
                    factor_type="Illicit Connections",
                    description="Connected to known illicit addresses",
                    weight=0.6,
                    evidence=f"{network['illicit_connections']} bad actors within 2 hops"
                ))
        
        return factors
    
    def _calculate_confidence(
        self, 
        intelligence_data: Dict[str, Any],
        tier: str
    ) -> float:
        """Calculate confidence score based on data quality"""
        
        base_confidence = 0.5 if tier == "free" else 0.7
        
        # Increase confidence based on number of sources
        source_count = len(intelligence_data.get("sources_queried", []))
        confidence = base_confidence + (source_count * 0.05)
        
        # Adjust for data freshness
        if not intelligence_data.get("cached_data"):
            confidence += 0.1
        
        # Cap at 0.98
        return min(confidence, 0.98)
    
    def _generate_key_finding(
        self, 
        risk_factors: List[RiskFactor],
        risk_level: RiskLevel
    ) -> str:
        """Generate one-sentence key finding"""
        
        if not risk_factors:
            return "No significant risk factors identified"
        
        # Find highest weight factor
        top_factor = max(risk_factors, key=lambda x: x.weight)
        
        if risk_level == RiskLevel.CRITICAL:
            return f"CRITICAL: {top_factor.description} - immediate action required"
        elif risk_level == RiskLevel.HIGH:
            return f"HIGH RISK: {top_factor.description} with {len(risk_factors)} risk factors"
        elif risk_level == RiskLevel.MEDIUM:
            return f"MODERATE RISK: {top_factor.description} detected"
        elif risk_level == RiskLevel.LOW:
            return f"LOW RISK: Minor concerns - {top_factor.description}"
        else:
            return "Address appears clean with no significant risk indicators"
    
    def _generate_recommendations(
        self,
        risk_level: RiskLevel,
        risk_factors: List[RiskFactor],
        tier: str
    ) -> Dict[str, str]:
        """Generate actionable recommendations"""
        
        recommendations = {}
        
        if risk_level == RiskLevel.CRITICAL:
            recommendations["Immediate Actions"] = (
                "⛔ DO NOT interact with this address\n"
                "🚨 Block all pending transactions\n"
                "📞 Contact exchange/wallet provider if funds were sent"
            )
            recommendations["Reporting"] = (
                "📝 File report with IC3.gov\n"
                "🏛️ Report to local law enforcement\n"
                "💬 Warn community on forums/social media"
            )
            
        elif risk_level == RiskLevel.HIGH:
            recommendations["Immediate Actions"] = (
                "⚠️ Suspend all interactions with this address\n"
                "🔍 Verify identity through alternate channels\n"
                "💰 Do not send additional funds"
            )
            recommendations["Monitoring"] = (
                "👁️ Set up alerts for any activity\n"
                "📊 Track fund movements\n"
                "🔄 Re-check in 24 hours for updates"
            )
            
        elif risk_level == RiskLevel.MEDIUM:
            recommendations["Caution Advised"] = (
                "🤔 Exercise increased caution\n"
                "✅ Verify legitimacy before transacting\n"
                "💡 Consider using escrow services"
            )
            
        else:
            recommendations["Standard Practices"] = (
                "✅ Address appears safe for interaction\n"
                "🔍 Continue normal due diligence\n"
                "📊 Monitor for any changes in status"
            )
        
        if tier == "free":
            recommendations["Upgrade Suggestion"] = (
                "🚀 Upgrade for real-time monitoring\n"
                "📡 Access 10+ additional data sources\n"
                "🔔 Get instant alerts on status changes"
            )
        
        return recommendations
    
    def _generate_follow_up_questions(
        self,
        risk_level: RiskLevel,
        risk_factors: List[RiskFactor],
        tier: str
    ) -> List[str]:
        """Generate contextual follow-up questions"""
        
        questions = []
        
        # Context-based questions
        if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            questions.append(
                "Would you like me to trace where funds from this address were sent?"
            )
            questions.append(
                "Should I analyze other addresses that have interacted with this one?"
            )
            questions.append(
                "Do you need a detailed evidence report for law enforcement?"
            )
            
        elif risk_level == RiskLevel.MEDIUM:
            questions.append(
                "Would you like to monitor this address for suspicious activity?"
            )
            questions.append(
                "Should I check for similar patterns in other addresses?"
            )
            
        else:
            questions.append(
                "Would you like to verify another address?"
            )
            questions.append(
                "Do you want to set up monitoring for this address?"
            )
        
        # Tier-specific questions
        if tier == "free":
            questions.append(
                "**[UPGRADE]** Get real-time blockchain data and continuous monitoring?"
            )
        else:
            questions.append(
                "Would you like to enable automated alerts for this address?"
            )
        
        return questions
    
    def _generate_upgrade_notice(self, report: IntelligenceReport) -> str:
        """Generate upgrade notice for free tier users"""
        
        return f"""
---

## 📢 UPGRADE TO PREMIUM

This report was generated using **cached training data only**.

**Upgrade to unlock:**
- ✅ Real-time blockchain analysis
- ✅ {len(self.paid_tier_sources)} additional intelligence sources
- ✅ Live API queries (HIBP, Shodan, VirusTotal)
- ✅ DeFi protocol analysis & MEV detection
- ✅ Continuous monitoring & alerts
- ✅ Bulk address analysis
- ✅ API access for integration

**[UPGRADE NOW]** to get comprehensive real-time intelligence
"""


class PromptTemplates:
    """Collection of prompt templates for different analysis stages"""
    
    INITIAL_VALIDATION = """
Validate the blockchain address: {address}

Determine:
1. Is this a valid {chain} address format?
2. Address type: EOA (wallet) or Contract?
3. If contract, what type? (Token/DEX/Bridge/Other)
4. Risk assessment priority (Critical/High/Medium/Low)

Return JSON:
{{
    "valid": true/false,
    "address_type": "wallet/contract/unknown",
    "contract_type": "token/dex/bridge/other/na",
    "priority": "critical/high/medium/low",
    "reason": "explanation"
}}
"""
    
    CHAIN_OF_THOUGHT_ANALYSIS = """
Analyze address {address} step-by-step:

Step 1: Direct Risk Indicators
- Blacklist status: {blacklist_check}
- Scam reports: {scam_count}
- Sanctions: {sanctions_check}

Step 2: Network Analysis  
- Connected addresses analyzed: {network_size}
- Suspicious connections: {suspicious_count}
- Risk propagation score: {propagation_score}

Step 3: Behavioral Patterns
- Transaction frequency: {tx_frequency}
- Value patterns: {value_patterns}
- Time clustering: {time_patterns}

Step 4: Intelligence Correlation
- Sources agreeing on risk: {source_agreement}
- Conflicting indicators: {conflicts}
- Confidence adjustment: {confidence_adj}

Final Assessment:
- Primary risk: {primary_risk}
- Secondary risks: {secondary_risks}
- Recommended action: {action}
"""
    
    DEFI_SPECIFIC_ANALYSIS = """
Analyze DeFi exposure for Ethereum address {address}:

Protocol Interactions:
- Uniswap: {uniswap_data}
- Compound: {compound_data}
- Aave: {aave_data}
- Other protocols: {other_protocols}

Risk Indicators:
1. Honeypot interactions: {honeypot_count}
2. Rug pull exposure: {rugpull_risk}
3. MEV victimization: {mev_losses}
4. Impermanent loss: {il_amount}

Smart Contract Risks:
- Unverified contracts: {unverified_count}
- Known vulnerabilities: {vulnerability_list}
- Suspicious patterns: {suspicious_patterns}

Generate DeFi risk score (0.0-1.0) and explain the primary concerns.
"""
    
    @classmethod
    def get_prompt(cls, template_name: str, **kwargs) -> str:
        """Get formatted prompt template"""
        template = getattr(cls, template_name, None)
        if template:
            return template.format(**kwargs)
        raise ValueError(f"Template {template_name} not found")


# Example usage
if __name__ == "__main__":
    # Example configuration
    config = {
        "tier": "paid",
        "verbose": True
    }
    
    # Create report generator
    generator = ReportGenerator(config)
    
    # Example intelligence data
    intel_data = {
        "chain": "ethereum",
        "sanctions": None,
        "scam_reports": 3,
        "breach_exposure": {"breach_count": 2},
        "defi_risks": {
            "mev_victim": True,
            "mev_losses": 45000
        },
        "network_analysis": {
            "connected_to_illicit": True,
            "illicit_connections": 5
        },
        "sources_queried": ["hibp", "shodan", "virustotal"],
        "cached_data": False,
        "processing_time_ms": 2340
    }
    
    # Generate report
    report = generator.generate_report(
        address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb6",
        intelligence_data=intel_data,
        risk_score=0.78,
        tier="paid"
    )
    
    # Format as markdown
    markdown_report = generator.format_report_markdown(report)
    print(markdown_report)