"""
Risk Scoring Engine - Core component that combines signals from all data sources
to generate comprehensive risk scores and classifications for cryptocurrency addresses.

Uses weighted scoring algorithms and machine learning models to provide
accurate threat assessment and incident classification.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
import logging
import json

from ..data_collector import RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin


class RiskCategory(Enum):
    """Risk categories for classification"""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious" 
    HIGH_RISK = "high_risk"
    CRIMINAL = "criminal"
    SANCTIONED = "sanctioned"


class IncidentType(Enum):
    """Types of cryptocurrency incidents"""
    RANSOMWARE = "ransomware"
    SCAM = "scam" 
    MONEY_LAUNDERING = "money_laundering"
    SANCTIONS_VIOLATION = "sanctions_violation"
    DARKNET_ACTIVITY = "darknet_activity"
    MIXER_ABUSE = "mixer_abuse"
    EXCHANGE_HACK = "exchange_hack"
    DEFI_EXPLOIT = "defi_exploit"
    RUG_PULL = "rug_pull"
    PHISHING = "phishing"
    OTHER = "other"


@dataclass
class RiskScoreResult:
    """Result of risk scoring analysis"""
    address: str
    overall_risk_score: float
    risk_category: RiskCategory
    confidence_score: float
    risk_factors_score: float
    ml_prediction_score: float
    weighted_scores: Dict[str, float]
    primary_risk_factors: List[RiskFactor]
    incident_predictions: Dict[IncidentType, float]
    explanation: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ModelPerformance:
    """ML model performance metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: float
    confusion_matrix: np.ndarray
    classification_report: Dict[str, Any]


class RiskScoringEngine(LoggingMixin):
    """
    Core risk scoring engine that combines multiple data sources and ML models
    to generate comprehensive risk assessments for cryptocurrency addresses.
    """
    
    # Default risk factor weights by data source type
    DEFAULT_SOURCE_WEIGHTS = {
        DataSourceType.GOVERNMENT: 1.0,        # Highest weight (OFAC, sanctions)
        DataSourceType.LAW_ENFORCEMENT: 0.95,  # Very high weight
        DataSourceType.CRIME_DATABASE: 0.9,    # High weight (HIBP, Elliptic)
        DataSourceType.COMMERCIAL: 0.8,        # Good weight (Chainalysis, etc.)
        DataSourceType.COMMUNITY: 0.7,         # Medium-high weight  
        DataSourceType.BEHAVIORAL_ANALYSIS: 0.6, # Medium weight
        DataSourceType.OPEN_SOURCE: 0.5,       # Medium-low weight
        DataSourceType.INTERNAL: 0.4           # Internal analysis
    }
    
    # Risk level score mapping
    RISK_LEVEL_SCORES = {
        RiskLevel.CRITICAL: 1.0,
        RiskLevel.HIGH: 0.75,
        RiskLevel.MEDIUM: 0.5,
        RiskLevel.LOW: 0.25
    }
    
    # Risk factor type weights (can be customized)
    RISK_FACTOR_TYPE_WEIGHTS = {
        # Sanctions and legal
        'ofac_sanctions': 1.0,
        'sanctions_violation': 1.0,
        'law_enforcement_seizure': 0.95,
        
        # Criminal activity
        'ransomware_payment': 0.9,
        'darknet_market': 0.9,
        'money_laundering': 0.85,
        'criminal_activity': 0.8,
        
        # Data breaches and compromises
        'data_breach_exposure': 0.7,
        'account_compromise': 0.7,
        
        # Service and entity risks
        'mixer_service': 0.8,
        'high_risk_exchange': 0.6,
        'gambling_service': 0.4,
        
        # Technical risks
        'smart_contract_vulnerability': 0.7,
        'honeypot_contract': 0.8,
        'rug_pull_risk': 0.75,
        
        # Behavioral patterns
        'suspicious_pattern': 0.6,
        'high_volume_activity': 0.3,
        'rapid_transactions': 0.4,
        
        # Default for unknown types
        'default': 0.5
    }
    
    # Incident type patterns for classification
    INCIDENT_PATTERNS = {
        IncidentType.RANSOMWARE: {
            'keywords': ['ransomware', 'ransom', 'crypto_locker', 'ryuk', 'conti'],
            'risk_factors': ['ransomware_payment', 'criminal_activity'],
            'sources': [DataSourceType.CRIME_DATABASE, DataSourceType.LAW_ENFORCEMENT]
        },
        IncidentType.SCAM: {
            'keywords': ['scam', 'fraud', 'ponzi', 'fake'],
            'risk_factors': ['scam_report', 'fraudulent_activity'],
            'sources': [DataSourceType.COMMUNITY, DataSourceType.COMMERCIAL]
        },
        IncidentType.SANCTIONS_VIOLATION: {
            'keywords': ['ofac', 'sanctions', 'blocked', 'prohibited'],
            'risk_factors': ['ofac_sanctions', 'sanctions_violation'],
            'sources': [DataSourceType.GOVERNMENT]
        },
        IncidentType.MIXER_ABUSE: {
            'keywords': ['mixer', 'tumbler', 'tornado', 'privacy'],
            'risk_factors': ['mixer_service', 'privacy_service'],
            'sources': [DataSourceType.BEHAVIORAL_ANALYSIS, DataSourceType.COMMERCIAL]
        }
    }
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        
        # Configuration
        self.source_weights = config.get('source_weights', self.DEFAULT_SOURCE_WEIGHTS.copy())
        self.risk_factor_weights = config.get('risk_factor_weights', self.RISK_FACTOR_TYPE_WEIGHTS.copy())
        self.confidence_threshold = config.get('confidence_threshold', 0.7)
        self.enable_ml_scoring = config.get('enable_ml_scoring', True)
        self.enable_explanation = config.get('enable_explanation', True)
        
        # ML models (will be loaded/trained)
        self.binary_classifier = None      # Clean vs Risk
        self.multiclass_classifier = None  # Risk categories
        self.incident_classifier = None    # Incident types
        self.feature_scaler = None
        
        # Performance tracking
        self.model_performance = {}
        self.prediction_history = []
        
        self.logger.info(
            "Risk Scoring Engine initialized",
            ml_enabled=self.enable_ml_scoring,
            source_weights=len(self.source_weights),
            factor_weights=len(self.risk_factor_weights)
        )
    
    def calculate_risk_score(self, wallet_analysis: WalletAnalysis) -> RiskScoreResult:
        """
        Calculate comprehensive risk score for a wallet analysis.
        
        Args:
            wallet_analysis: WalletAnalysis object with risk factors
            
        Returns:
            RiskScoreResult with comprehensive scoring
        """
        try:
            # Extract risk factors
            risk_factors = wallet_analysis.risk_factors or []
            
            if not risk_factors:
                return self._create_clean_result(wallet_analysis.address)
            
            # Calculate weighted risk factor score
            risk_factors_score, weighted_scores = self._calculate_risk_factors_score(risk_factors)
            
            # Get ML prediction score if available
            ml_score = 0.0
            if self.enable_ml_scoring and self.binary_classifier:
                ml_score = self._get_ml_prediction_score(wallet_analysis)
            
            # Combine scores
            overall_score = self._combine_scores(risk_factors_score, ml_score)
            
            # Calculate confidence
            confidence = self._calculate_confidence(risk_factors, ml_score)
            
            # Determine risk category
            risk_category = self._categorize_risk(overall_score, risk_factors)
            
            # Predict incident types
            incident_predictions = self._predict_incident_types(risk_factors)
            
            # Generate explanation
            explanation = ""
            if self.enable_explanation:
                explanation = self._generate_explanation(
                    risk_factors, risk_category, incident_predictions
                )
            
            # Get primary risk factors (top contributors)
            primary_factors = self._get_primary_risk_factors(risk_factors, weighted_scores)
            
            result = RiskScoreResult(
                address=wallet_analysis.address,
                overall_risk_score=overall_score,
                risk_category=risk_category,
                confidence_score=confidence,
                risk_factors_score=risk_factors_score,
                ml_prediction_score=ml_score,
                weighted_scores=weighted_scores,
                primary_risk_factors=primary_factors,
                incident_predictions=incident_predictions,
                explanation=explanation
            )
            
            # Track prediction
            self.prediction_history.append({
                'timestamp': result.timestamp,
                'address': wallet_analysis.address,
                'risk_score': overall_score,
                'risk_category': risk_category.value,
                'confidence': confidence
            })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error calculating risk score for {wallet_analysis.address}: {e}")
            return self._create_error_result(wallet_analysis.address, str(e))
    
    def _calculate_risk_factors_score(self, risk_factors: List[RiskFactor]) -> Tuple[float, Dict[str, float]]:
        """Calculate weighted score from risk factors"""
        
        if not risk_factors:
            return 0.0, {}
        
        total_weighted_score = 0.0
        total_weight = 0.0
        weighted_scores = {}
        
        for factor in risk_factors:
            # Get source weight
            source_weight = self.source_weights.get(factor.source, 0.5)
            
            # Get risk factor type weight
            factor_type = factor.type.lower()
            factor_weight = self._get_factor_type_weight(factor_type)
            
            # Get risk level score
            risk_level_score = self.RISK_LEVEL_SCORES.get(factor.risk_level, 0.5)
            
            # Calculate weighted contribution
            factor_contribution = (
                risk_level_score * 
                factor.confidence * 
                source_weight * 
                factor_weight
            )
            
            total_weighted_score += factor_contribution
            total_weight += source_weight * factor_weight * factor.confidence
            
            # Track individual contributions
            weighted_scores[factor.type] = factor_contribution
        
        # Normalize score
        if total_weight > 0:
            normalized_score = min(1.0, total_weighted_score / total_weight)
        else:
            normalized_score = 0.0
        
        return normalized_score, weighted_scores
    
    def _get_factor_type_weight(self, factor_type: str) -> float:
        """Get weight for risk factor type"""
        
        # Direct match
        if factor_type in self.risk_factor_weights:
            return self.risk_factor_weights[factor_type]
        
        # Pattern matching for compound types
        for pattern, weight in self.risk_factor_weights.items():
            if pattern in factor_type:
                return weight
        
        # Default weight
        return self.risk_factor_weights.get('default', 0.5)
    
    def _get_ml_prediction_score(self, wallet_analysis: WalletAnalysis) -> float:
        """Get ML model prediction score (placeholder)"""
        # This would extract features and run ML prediction
        # For now, return a basic score based on existing analysis
        
        if not wallet_analysis.risk_factors:
            return 0.0
        
        # Simple heuristic until ML models are trained
        high_risk_factors = sum(
            1 for factor in wallet_analysis.risk_factors
            if factor.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]
        )
        
        total_factors = len(wallet_analysis.risk_factors)
        
        if total_factors == 0:
            return 0.0
        
        return min(1.0, (high_risk_factors / total_factors) * 1.2)
    
    def _combine_scores(self, risk_factors_score: float, ml_score: float) -> float:
        """Combine risk factors score and ML prediction score"""
        
        if ml_score == 0.0:
            return risk_factors_score
        
        # Weighted combination (can be tuned)
        risk_factors_weight = 0.7
        ml_weight = 0.3
        
        combined_score = (
            risk_factors_score * risk_factors_weight +
            ml_score * ml_weight
        )
        
        return min(1.0, combined_score)
    
    def _calculate_confidence(self, risk_factors: List[RiskFactor], ml_score: float) -> float:
        """Calculate confidence in the risk assessment"""
        
        if not risk_factors:
            return 0.1
        
        # Factor-based confidence
        avg_factor_confidence = np.mean([factor.confidence for factor in risk_factors])
        
        # Source diversity bonus
        unique_sources = len(set(factor.source for factor in risk_factors))
        source_diversity_bonus = min(0.2, unique_sources * 0.05)
        
        # ML confidence boost
        ml_confidence_boost = 0.1 if ml_score > 0 else 0.0
        
        total_confidence = min(1.0, 
            avg_factor_confidence + 
            source_diversity_bonus + 
            ml_confidence_boost
        )
        
        return total_confidence
    
    def _categorize_risk(self, overall_score: float, risk_factors: List[RiskFactor]) -> RiskCategory:
        """Categorize risk based on score and factors"""
        
        # Check for sanctions (always critical regardless of score)
        for factor in risk_factors:
            if 'sanction' in factor.type.lower() or factor.source == DataSourceType.GOVERNMENT:
                return RiskCategory.SANCTIONED
        
        # Score-based categorization
        if overall_score >= 0.8:
            return RiskCategory.CRIMINAL
        elif overall_score >= 0.6:
            return RiskCategory.HIGH_RISK
        elif overall_score >= 0.3:
            return RiskCategory.SUSPICIOUS
        else:
            return RiskCategory.CLEAN
    
    def _predict_incident_types(self, risk_factors: List[RiskFactor]) -> Dict[IncidentType, float]:
        """Predict likely incident types based on risk factors"""
        
        predictions = {}
        
        for incident_type, patterns in self.INCIDENT_PATTERNS.items():
            score = 0.0
            
            # Check risk factor types
            matching_factors = 0
            for factor in risk_factors:
                factor_type_lower = factor.type.lower()
                
                # Check for keyword matches
                for keyword in patterns['keywords']:
                    if keyword in factor_type_lower or keyword in factor.description.lower():
                        score += 0.3 * factor.confidence
                        matching_factors += 1
                        break
                
                # Check for risk factor type matches
                for risk_factor_type in patterns['risk_factors']:
                    if risk_factor_type in factor_type_lower:
                        score += 0.4 * factor.confidence
                        matching_factors += 1
                        break
                
                # Check for source type matches  
                if factor.source in patterns['sources']:
                    score += 0.2 * factor.confidence
            
            # Normalize score
            if matching_factors > 0:
                score = min(1.0, score / matching_factors)
            
            predictions[incident_type] = score
        
        # Sort by score and return top predictions
        sorted_predictions = dict(
            sorted(predictions.items(), key=lambda x: x[1], reverse=True)
        )
        
        return {k: v for k, v in sorted_predictions.items() if v > 0.1}
    
    def _generate_explanation(self, risk_factors: List[RiskFactor], 
                            risk_category: RiskCategory,
                            incident_predictions: Dict[IncidentType, float]) -> str:
        """Generate human-readable explanation of the risk assessment"""
        
        if not risk_factors:
            return "No risk factors identified. Address appears clean."
        
        explanation_parts = []
        
        # Risk category explanation
        risk_explanations = {
            RiskCategory.CLEAN: "Address shows minimal risk indicators",
            RiskCategory.SUSPICIOUS: "Address shows some concerning patterns requiring investigation",
            RiskCategory.HIGH_RISK: "Address shows significant risk indicators and should be closely monitored",
            RiskCategory.CRIMINAL: "Address shows strong evidence of criminal activity",
            RiskCategory.SANCTIONED: "Address appears on government sanctions lists"
        }
        
        explanation_parts.append(risk_explanations[risk_category])
        
        # Top risk factors
        high_risk_factors = [
            factor for factor in risk_factors 
            if factor.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]
        ]
        
        if high_risk_factors:
            explanation_parts.append(f"Key concerns: {', '.join(factor.type.replace('_', ' ') for factor in high_risk_factors[:3])}")
        
        # Incident predictions
        if incident_predictions:
            top_incident = max(incident_predictions.items(), key=lambda x: x[1])
            if top_incident[1] > 0.5:
                explanation_parts.append(f"Likely incident type: {top_incident[0].value.replace('_', ' ')}")
        
        # Data sources
        unique_sources = set(factor.source.value for factor in risk_factors)
        explanation_parts.append(f"Analysis based on {len(unique_sources)} data sources")
        
        return ". ".join(explanation_parts) + "."
    
    def _get_primary_risk_factors(self, risk_factors: List[RiskFactor], 
                                 weighted_scores: Dict[str, float]) -> List[RiskFactor]:
        """Get the most significant risk factors"""
        
        # Sort factors by their weighted contribution
        factor_scores = []
        for factor in risk_factors:
            score = weighted_scores.get(factor.type, 0.0)
            factor_scores.append((factor, score))
        
        # Sort by score and return top factors
        factor_scores.sort(key=lambda x: x[1], reverse=True)
        
        return [factor for factor, score in factor_scores[:5]]  # Top 5
    
    def _create_clean_result(self, address: str) -> RiskScoreResult:
        """Create result for clean address"""
        return RiskScoreResult(
            address=address,
            overall_risk_score=0.0,
            risk_category=RiskCategory.CLEAN,
            confidence_score=0.8,
            risk_factors_score=0.0,
            ml_prediction_score=0.0,
            weighted_scores={},
            primary_risk_factors=[],
            incident_predictions={},
            explanation="No risk factors identified. Address appears clean."
        )
    
    def _create_error_result(self, address: str, error: str) -> RiskScoreResult:
        """Create result for error case"""
        return RiskScoreResult(
            address=address,
            overall_risk_score=0.0,
            risk_category=RiskCategory.CLEAN,
            confidence_score=0.0,
            risk_factors_score=0.0,
            ml_prediction_score=0.0,
            weighted_scores={},
            primary_risk_factors=[],
            incident_predictions={},
            explanation=f"Error in risk assessment: {error}"
        )
    
    def batch_score_addresses(self, analyses: List[WalletAnalysis]) -> List[RiskScoreResult]:
        """Score multiple addresses in batch"""
        
        results = []
        for analysis in analyses:
            try:
                result = self.calculate_risk_score(analysis)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Error scoring {analysis.address}: {e}")
                results.append(self._create_error_result(analysis.address, str(e)))
        
        return results
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for the risk scoring engine"""
        
        if not self.prediction_history:
            return {'error': 'No predictions made yet'}
        
        recent_predictions = self.prediction_history[-1000:]  # Last 1000
        
        # Calculate basic statistics
        risk_scores = [p['risk_score'] for p in recent_predictions]
        confidences = [p['confidence'] for p in recent_predictions]
        
        # Risk category distribution
        category_distribution = {}
        for prediction in recent_predictions:
            category = prediction['risk_category']
            category_distribution[category] = category_distribution.get(category, 0) + 1
        
        return {
            'total_predictions': len(self.prediction_history),
            'recent_predictions': len(recent_predictions),
            'average_risk_score': np.mean(risk_scores),
            'average_confidence': np.mean(confidences),
            'risk_category_distribution': category_distribution,
            'high_risk_percentage': len([s for s in risk_scores if s > 0.6]) / len(risk_scores) * 100,
            'model_performance': self.model_performance
        }
    
    def update_weights(self, source_weights: Optional[Dict] = None, 
                      factor_weights: Optional[Dict] = None):
        """Update scoring weights"""
        
        if source_weights:
            self.source_weights.update(source_weights)
            self.logger.info("Updated source weights", updated_sources=list(source_weights.keys()))
        
        if factor_weights:
            self.risk_factor_weights.update(factor_weights)
            self.logger.info("Updated factor weights", updated_factors=list(factor_weights.keys()))
    
    def export_configuration(self) -> Dict[str, Any]:
        """Export current engine configuration"""
        
        return {
            'source_weights': self.source_weights,
            'risk_factor_weights': self.risk_factor_weights,
            'confidence_threshold': self.confidence_threshold,
            'enable_ml_scoring': self.enable_ml_scoring,
            'risk_level_scores': {level.value: score for level, score in self.RISK_LEVEL_SCORES.items()},
            'incident_patterns': {
                incident.value: patterns for incident, patterns in self.INCIDENT_PATTERNS.items()
            }
        }
    
    def import_configuration(self, config: Dict[str, Any]):
        """Import engine configuration"""
        
        if 'source_weights' in config:
            self.source_weights.update(config['source_weights'])
        
        if 'risk_factor_weights' in config:
            self.risk_factor_weights.update(config['risk_factor_weights'])
        
        if 'confidence_threshold' in config:
            self.confidence_threshold = config['confidence_threshold']
        
        self.logger.info("Imported risk scoring configuration")


# Utility functions for risk scoring
def aggregate_risk_scores(results: List[RiskScoreResult]) -> Dict[str, Any]:
    """Aggregate multiple risk score results for analysis"""
    
    if not results:
        return {}
    
    risk_scores = [r.overall_risk_score for r in results]
    confidences = [r.confidence_score for r in results]
    
    # Category distribution
    categories = {}
    for result in results:
        cat = result.risk_category.value
        categories[cat] = categories.get(cat, 0) + 1
    
    # Incident type aggregation
    all_incidents = {}
    for result in results:
        for incident_type, score in result.incident_predictions.items():
            incident_name = incident_type.value
            if incident_name not in all_incidents:
                all_incidents[incident_name] = []
            all_incidents[incident_name].append(score)
    
    # Average incident scores
    avg_incidents = {
        incident: np.mean(scores) 
        for incident, scores in all_incidents.items()
    }
    
    return {
        'total_addresses': len(results),
        'average_risk_score': np.mean(risk_scores),
        'max_risk_score': np.max(risk_scores),
        'average_confidence': np.mean(confidences),
        'risk_category_distribution': categories,
        'high_risk_count': len([s for s in risk_scores if s > 0.6]),
        'incident_type_predictions': avg_incidents,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }