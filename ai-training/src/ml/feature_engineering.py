"""
Feature Engineering System - Extracts and creates features from all data collectors
for machine learning training. Handles feature extraction, selection, and creation
of composite risk indicators for optimal model performance.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum
import logging
from collections import defaultdict, Counter
import re

from ..data_collector import RiskFactor, RiskLevel, DataSourceType, WalletAnalysis
from ..utils.logging import LoggingMixin


class FeatureType(Enum):
    """Types of features for ML training"""
    NUMERICAL = "numerical"
    CATEGORICAL = "categorical"
    BINARY = "binary"
    TEXT = "text"
    TEMPORAL = "temporal"
    COMPOSITE = "composite"


@dataclass
class Feature:
    """Represents a single feature for ML training"""
    name: str
    feature_type: FeatureType
    value: Union[float, int, str, bool]
    importance_score: float = 0.0
    source: Optional[str] = None
    description: Optional[str] = None


@dataclass
class FeatureSet:
    """Collection of features extracted from analysis"""
    address: str
    features: Dict[str, Feature]
    target_labels: Dict[str, Any]
    extraction_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    data_sources: List[str] = field(default_factory=list)
    
    def to_dataframe_row(self) -> Dict[str, Any]:
        """Convert to single row for DataFrame"""
        row = {'address': self.address}
        
        # Add feature values
        for name, feature in self.features.items():
            row[name] = feature.value
        
        # Add target labels
        row.update(self.target_labels)
        
        return row


class FeatureEngineer(LoggingMixin):
    """
    Comprehensive feature engineering system for cryptocurrency risk assessment.
    Extracts features from all data collectors and creates composite indicators.
    """
    
    # Feature importance weights (can be learned from data)
    FEATURE_IMPORTANCE_WEIGHTS = {
        'sanctions_features': 1.0,
        'criminal_activity_features': 0.9,
        'service_identification_features': 0.8,
        'relationship_features': 0.7,
        'breach_features': 0.6,
        'behavioral_features': 0.5,
        'technical_features': 0.4
    }
    
    # Text patterns for feature extraction
    TEXT_PATTERNS = {
        'ransomware_indicators': [
            r'ransom(?:ware)?', r'crypto[-_]?locker', r'wannacry', r'ryuk', r'conti',
            r'lockbit', r'maze', r'revil', r'sodinokibi', r'dharma'
        ],
        'scam_indicators': [
            r'scam', r'fraud', r'fake', r'phish', r'ponzi', r'pyramid',
            r'rug[-_]?pull', r'exit[-_]?scam', r'honeypot'
        ],
        'mixer_indicators': [
            r'mix(?:er|ing)', r'tumbl(?:er|ing)', r'tornado', r'privacy',
            r'launder(?:y|ing)', r'obfuscat(?:e|ion)'
        ],
        'darknet_indicators': [
            r'darknet', r'dark[-_]?web', r'silk[-_]?road', r'alphabay',
            r'dream[-_]?market', r'hydra', r'monopoly'
        ]
    }
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        
        # Configuration
        self.enable_composite_features = config.get('enable_composite_features', True)
        self.enable_temporal_features = config.get('enable_temporal_features', True)
        self.enable_text_features = config.get('enable_text_features', True)
        self.feature_selection_threshold = config.get('feature_selection_threshold', 0.01)
        
        # Feature statistics for tracking
        self.feature_statistics = defaultdict(list)
        self.extracted_feature_sets = []
        
        self.logger.info(
            "Feature Engineer initialized",
            composite_features=self.enable_composite_features,
            temporal_features=self.enable_temporal_features,
            text_features=self.enable_text_features
        )
    
    def extract_features(self, wallet_analysis: WalletAnalysis) -> FeatureSet:
        """
        Extract comprehensive features from wallet analysis.
        
        Args:
            wallet_analysis: WalletAnalysis object with risk factors
            
        Returns:
            FeatureSet containing all extracted features
        """
        try:
            features = {}
            
            # Basic features from wallet analysis
            features.update(self._extract_basic_features(wallet_analysis))
            
            # Risk factor features
            features.update(self._extract_risk_factor_features(wallet_analysis.risk_factors))
            
            # Data source features
            features.update(self._extract_data_source_features(wallet_analysis.data_sources))
            
            # Text-based features
            if self.enable_text_features:
                features.update(self._extract_text_features(wallet_analysis))
            
            # Temporal features
            if self.enable_temporal_features:
                features.update(self._extract_temporal_features(wallet_analysis))
            
            # Composite features
            if self.enable_composite_features:
                features.update(self._create_composite_features(features, wallet_analysis))
            
            # Create target labels
            target_labels = self._create_target_labels(wallet_analysis)
            
            feature_set = FeatureSet(
                address=wallet_analysis.address,
                features=features,
                target_labels=target_labels,
                data_sources=wallet_analysis.data_sources
            )
            
            # Track statistics
            self._update_feature_statistics(feature_set)
            self.extracted_feature_sets.append(feature_set)
            
            self.logger.debug(
                f"Features extracted for {wallet_analysis.address}",
                feature_count=len(features),
                target_labels=list(target_labels.keys())
            )
            
            return feature_set
            
        except Exception as e:
            self.logger.error(f"Error extracting features for {wallet_analysis.address}: {e}")
            raise
    
    def _extract_basic_features(self, analysis: WalletAnalysis) -> Dict[str, Feature]:
        """Extract basic features from wallet analysis"""
        
        features = {}
        
        # Overall risk score
        features['overall_risk_score'] = Feature(
            name='overall_risk_score',
            feature_type=FeatureType.NUMERICAL,
            value=analysis.overall_risk_score,
            source='basic',
            description='Overall computed risk score'
        )
        
        # Confidence score
        features['confidence_score'] = Feature(
            name='confidence_score',
            feature_type=FeatureType.NUMERICAL,
            value=analysis.confidence_score,
            source='basic',
            description='Confidence in the analysis'
        )
        
        # Risk level (encoded)
        risk_level_mapping = {
            'LOW': 0,
            'MEDIUM': 1, 
            'HIGH': 2,
            'CRITICAL': 3
        }
        
        features['risk_level_encoded'] = Feature(
            name='risk_level_encoded',
            feature_type=FeatureType.NUMERICAL,
            value=risk_level_mapping.get(analysis.risk_level.name, 0),
            source='basic',
            description='Encoded risk level'
        )
        
        # Is flagged (binary)
        features['is_flagged'] = Feature(
            name='is_flagged',
            feature_type=FeatureType.BINARY,
            value=int(analysis.is_flagged),
            source='basic',
            description='Whether address is flagged as risky'
        )
        
        # Number of data sources
        features['data_source_count'] = Feature(
            name='data_source_count',
            feature_type=FeatureType.NUMERICAL,
            value=len(analysis.data_sources),
            source='basic',
            description='Number of data sources analyzed'
        )
        
        return features
    
    def _extract_risk_factor_features(self, risk_factors: List[RiskFactor]) -> Dict[str, Feature]:
        """Extract features from risk factors"""
        
        features = {}
        
        if not risk_factors:
            # Zero features if no risk factors
            features['risk_factor_count'] = Feature(
                name='risk_factor_count',
                feature_type=FeatureType.NUMERICAL,
                value=0,
                source='risk_factors'
            )
            return features
        
        # Basic risk factor statistics
        features['risk_factor_count'] = Feature(
            name='risk_factor_count',
            feature_type=FeatureType.NUMERICAL,
            value=len(risk_factors),
            source='risk_factors',
            description='Total number of risk factors'
        )
        
        # Risk level distribution
        risk_level_counts = Counter(factor.risk_level.name for factor in risk_factors)
        for level in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
            features[f'risk_factors_{level.lower()}_count'] = Feature(
                name=f'risk_factors_{level.lower()}_count',
                feature_type=FeatureType.NUMERICAL,
                value=risk_level_counts.get(level, 0),
                source='risk_factors'
            )
        
        # Average confidence
        avg_confidence = np.mean([factor.confidence for factor in risk_factors])
        features['risk_factors_avg_confidence'] = Feature(
            name='risk_factors_avg_confidence',
            feature_type=FeatureType.NUMERICAL,
            value=avg_confidence,
            source='risk_factors',
            description='Average confidence of risk factors'
        )
        
        # Data source type distribution
        source_type_counts = Counter(factor.source.name for factor in risk_factors)
        for source_type in ['GOVERNMENT', 'LAW_ENFORCEMENT', 'CRIME_DATABASE', 'COMMERCIAL', 'COMMUNITY']:
            count = source_type_counts.get(source_type, 0)
            features[f'source_{source_type.lower()}_count'] = Feature(
                name=f'source_{source_type.lower()}_count',
                feature_type=FeatureType.NUMERICAL,
                value=count,
                source='risk_factors'
            )
        
        # Risk factor type patterns
        risk_factor_types = [factor.type.lower() for factor in risk_factors]
        
        # Sanctions indicators
        sanctions_count = sum(1 for rf_type in risk_factor_types if 'sanction' in rf_type)
        features['sanctions_factor_count'] = Feature(
            name='sanctions_factor_count',
            feature_type=FeatureType.NUMERICAL,
            value=sanctions_count,
            source='risk_factors'
        )
        
        # Criminal activity indicators
        criminal_keywords = ['criminal', 'ransomware', 'darknet', 'scam', 'fraud']
        criminal_count = sum(
            1 for rf_type in risk_factor_types 
            if any(keyword in rf_type for keyword in criminal_keywords)
        )
        features['criminal_factor_count'] = Feature(
            name='criminal_factor_count',
            feature_type=FeatureType.NUMERICAL,
            value=criminal_count,
            source='risk_factors'
        )
        
        # Service-related indicators
        service_keywords = ['exchange', 'mixer', 'gambling', 'service']
        service_count = sum(
            1 for rf_type in risk_factor_types
            if any(keyword in rf_type for keyword in service_keywords)
        )
        features['service_factor_count'] = Feature(
            name='service_factor_count',
            feature_type=FeatureType.NUMERICAL,
            value=service_count,
            source='risk_factors'
        )
        
        return features
    
    def _extract_data_source_features(self, data_sources: List[str]) -> Dict[str, Feature]:
        """Extract features from data sources"""
        
        features = {}
        
        # Data source indicators (binary features)
        known_sources = [
            'ofac_sanctions', 'chainalysis', 'graphsense', 'hibp', 'virustotal',
            'ransomwhere', 'elliptic', 'exchange_identifier', 'scam_database'
        ]
        
        for source in known_sources:
            has_source = int(any(source in ds.lower() for ds in data_sources))
            features[f'has_{source}_data'] = Feature(
                name=f'has_{source}_data',
                feature_type=FeatureType.BINARY,
                value=has_source,
                source='data_sources'
            )
        
        # Data source diversity
        features['data_source_diversity'] = Feature(
            name='data_source_diversity',
            feature_type=FeatureType.NUMERICAL,
            value=len(set(data_sources)),
            source='data_sources',
            description='Number of unique data sources'
        )
        
        return features
    
    def _extract_text_features(self, analysis: WalletAnalysis) -> Dict[str, Feature]:
        """Extract text-based features from descriptions and summaries"""
        
        features = {}
        
        # Collect all text content
        text_content = []
        text_content.append(analysis.summary or '')
        
        for factor in analysis.risk_factors or []:
            text_content.append(factor.description or '')
            text_content.append(factor.type or '')
        
        combined_text = ' '.join(text_content).lower()
        
        # Pattern-based text features
        for pattern_category, patterns in self.TEXT_PATTERNS.items():
            pattern_count = 0
            for pattern in patterns:
                pattern_count += len(re.findall(pattern, combined_text, re.IGNORECASE))
            
            features[f'{pattern_category}_mentions'] = Feature(
                name=f'{pattern_category}_mentions',
                feature_type=FeatureType.NUMERICAL,
                value=pattern_count,
                source='text_analysis',
                description=f'Number of {pattern_category} mentions'
            )
        
        # Text length features
        features['total_text_length'] = Feature(
            name='total_text_length',
            feature_type=FeatureType.NUMERICAL,
            value=len(combined_text),
            source='text_analysis'
        )
        
        # Word count
        word_count = len(combined_text.split()) if combined_text.strip() else 0
        features['total_word_count'] = Feature(
            name='total_word_count',
            feature_type=FeatureType.NUMERICAL,
            value=word_count,
            source='text_analysis'
        )
        
        return features
    
    def _extract_temporal_features(self, analysis: WalletAnalysis) -> Dict[str, Feature]:
        """Extract temporal features from timestamps"""
        
        features = {}
        
        # Analysis recency (hours since analysis)
        now = datetime.now(timezone.utc)
        hours_since_analysis = (now - analysis.analysis_timestamp).total_seconds() / 3600
        
        features['hours_since_analysis'] = Feature(
            name='hours_since_analysis',
            feature_type=FeatureType.NUMERICAL,
            value=hours_since_analysis,
            source='temporal'
        )
        
        # Day of week (cyclical encoding)
        day_of_week = analysis.analysis_timestamp.weekday()
        features['analysis_day_of_week'] = Feature(
            name='analysis_day_of_week',
            feature_type=FeatureType.NUMERICAL,
            value=day_of_week,
            source='temporal'
        )
        
        # Hour of day (cyclical encoding)
        hour_of_day = analysis.analysis_timestamp.hour
        features['analysis_hour_of_day'] = Feature(
            name='analysis_hour_of_day',
            feature_type=FeatureType.NUMERICAL,
            value=hour_of_day,
            source='temporal'
        )
        
        return features
    
    def _create_composite_features(self, features: Dict[str, Feature], analysis: WalletAnalysis) -> Dict[str, Feature]:
        """Create composite features from existing features"""
        
        composite_features = {}
        
        # Risk-to-confidence ratio
        risk_score = features.get('overall_risk_score', Feature('', FeatureType.NUMERICAL, 0)).value
        confidence = features.get('confidence_score', Feature('', FeatureType.NUMERICAL, 1)).value
        
        if confidence > 0:
            risk_confidence_ratio = risk_score / confidence
        else:
            risk_confidence_ratio = 0
        
        composite_features['risk_confidence_ratio'] = Feature(
            name='risk_confidence_ratio',
            feature_type=FeatureType.NUMERICAL,
            value=risk_confidence_ratio,
            source='composite',
            description='Risk score to confidence ratio'
        )
        
        # High-risk factor density
        total_factors = features.get('risk_factor_count', Feature('', FeatureType.NUMERICAL, 0)).value
        high_risk_factors = features.get('risk_factors_high_count', Feature('', FeatureType.NUMERICAL, 0)).value
        critical_factors = features.get('risk_factors_critical_count', Feature('', FeatureType.NUMERICAL, 0)).value
        
        if total_factors > 0:
            high_risk_density = (high_risk_factors + critical_factors) / total_factors
        else:
            high_risk_density = 0
        
        composite_features['high_risk_factor_density'] = Feature(
            name='high_risk_factor_density',
            feature_type=FeatureType.NUMERICAL,
            value=high_risk_density,
            source='composite'
        )
        
        # Multi-source confirmation score
        gov_sources = features.get('source_government_count', Feature('', FeatureType.NUMERICAL, 0)).value
        le_sources = features.get('source_law_enforcement_count', Feature('', FeatureType.NUMERICAL, 0)).value
        crime_db_sources = features.get('source_crime_database_count', Feature('', FeatureType.NUMERICAL, 0)).value
        
        authoritative_sources = gov_sources + le_sources + crime_db_sources
        total_sources = features.get('data_source_count', Feature('', FeatureType.NUMERICAL, 1)).value
        
        multi_source_score = min(1.0, authoritative_sources / max(1, total_sources))
        
        composite_features['multi_source_confirmation'] = Feature(
            name='multi_source_confirmation',
            feature_type=FeatureType.NUMERICAL,
            value=multi_source_score,
            source='composite'
        )
        
        # Criminal activity composite score
        criminal_factors = features.get('criminal_factor_count', Feature('', FeatureType.NUMERICAL, 0)).value
        sanctions_factors = features.get('sanctions_factor_count', Feature('', FeatureType.NUMERICAL, 0)).value
        ransomware_mentions = features.get('ransomware_indicators_mentions', Feature('', FeatureType.NUMERICAL, 0)).value
        darknet_mentions = features.get('darknet_indicators_mentions', Feature('', FeatureType.NUMERICAL, 0)).value
        
        criminal_composite = min(1.0, (criminal_factors + sanctions_factors + ransomware_mentions + darknet_mentions) / 10)
        
        composite_features['criminal_activity_composite'] = Feature(
            name='criminal_activity_composite',
            feature_type=FeatureType.NUMERICAL,
            value=criminal_composite,
            source='composite'
        )
        
        return composite_features
    
    def _create_target_labels(self, analysis: WalletAnalysis) -> Dict[str, Any]:
        """Create target labels for supervised learning"""
        
        labels = {}
        
        # Binary classification target (clean vs risky)
        labels['is_risky'] = int(analysis.overall_risk_score > 0.3 or analysis.is_flagged)
        
        # Multi-class risk category
        risk_category_mapping = {
            'LOW': 0,
            'MEDIUM': 1,
            'HIGH': 2,
            'CRITICAL': 3
        }
        labels['risk_category'] = risk_category_mapping.get(analysis.risk_level.name, 0)
        
        # High confidence flag
        labels['high_confidence'] = int(analysis.confidence_score > 0.8)
        
        # Sanctions flag (highest priority)
        has_sanctions = any(
            'sanction' in factor.type.lower() or factor.source == DataSourceType.GOVERNMENT
            for factor in analysis.risk_factors or []
        )
        labels['has_sanctions'] = int(has_sanctions)
        
        # Criminal activity flag
        criminal_keywords = ['criminal', 'ransomware', 'darknet', 'scam', 'fraud', 'money_laundering']
        has_criminal_activity = any(
            any(keyword in factor.type.lower() or keyword in factor.description.lower() 
                for keyword in criminal_keywords)
            for factor in analysis.risk_factors or []
        )
        labels['has_criminal_activity'] = int(has_criminal_activity)
        
        return labels
    
    def _update_feature_statistics(self, feature_set: FeatureSet):
        """Update feature statistics for analysis"""
        
        for name, feature in feature_set.features.items():
            if feature.feature_type == FeatureType.NUMERICAL:
                self.feature_statistics[name].append(float(feature.value))
    
    def batch_extract_features(self, analyses: List[WalletAnalysis]) -> pd.DataFrame:
        """
        Extract features from multiple wallet analyses and return as DataFrame.
        
        Args:
            analyses: List of WalletAnalysis objects
            
        Returns:
            DataFrame with features and targets for ML training
        """
        try:
            feature_sets = []
            
            for analysis in analyses:
                feature_set = self.extract_features(analysis)
                feature_sets.append(feature_set)
            
            # Convert to DataFrame
            rows = [fs.to_dataframe_row() for fs in feature_sets]
            df = pd.DataFrame(rows)
            
            self.logger.info(
                f"Batch feature extraction completed",
                samples=len(df),
                features=len(df.columns) - 1,  # Exclude address column
                targets=len(feature_sets[0].target_labels) if feature_sets else 0
            )
            
            return df
            
        except Exception as e:
            self.logger.error(f"Error in batch feature extraction: {e}")
            raise
    
    def select_features(self, df: pd.DataFrame, target_column: str = 'is_risky', 
                       method: str = 'variance') -> List[str]:
        """
        Select most important features for training.
        
        Args:
            df: DataFrame with features
            target_column: Target column name
            method: Feature selection method
            
        Returns:
            List of selected feature names
        """
        try:
            if target_column not in df.columns:
                raise ValueError(f"Target column '{target_column}' not found")
            
            # Separate features and target
            feature_columns = [col for col in df.columns if col not in ['address', target_column]]
            X = df[feature_columns]
            y = df[target_column]
            
            if method == 'variance':
                # Variance threshold
                from sklearn.feature_selection import VarianceThreshold
                selector = VarianceThreshold(threshold=self.feature_selection_threshold)
                selector.fit(X)
                selected_features = [feature_columns[i] for i, selected in enumerate(selector.get_support()) if selected]
            
            elif method == 'mutual_info':
                # Mutual information
                from sklearn.feature_selection import mutual_info_classif, SelectKBest
                selector = SelectKBest(mutual_info_classif, k='all')
                selector.fit(X, y)
                
                # Get scores and select top features
                scores = selector.scores_
                feature_scores = list(zip(feature_columns, scores))
                feature_scores.sort(key=lambda x: x[1], reverse=True)
                
                # Select top 80% of features
                n_features = max(1, int(len(feature_scores) * 0.8))
                selected_features = [name for name, score in feature_scores[:n_features]]
            
            elif method == 'correlation':
                # Remove highly correlated features
                corr_matrix = X.corr().abs()
                upper_triangle = corr_matrix.where(
                    np.triu(np.ones(corr_matrix.shape), k=1).astype(bool)
                )
                
                # Find features with correlation > 0.9
                high_corr_features = [column for column in upper_triangle.columns if any(upper_triangle[column] > 0.9)]
                selected_features = [col for col in feature_columns if col not in high_corr_features]
            
            else:
                selected_features = feature_columns
            
            self.logger.info(
                f"Feature selection completed",
                method=method,
                original_features=len(feature_columns),
                selected_features=len(selected_features)
            )
            
            return selected_features
            
        except Exception as e:
            self.logger.error(f"Error in feature selection: {e}")
            return feature_columns  # Return all features on error
    
    def get_feature_statistics(self) -> Dict[str, Any]:
        """Get feature engineering statistics"""
        
        stats = {
            'total_feature_sets_extracted': len(self.extracted_feature_sets),
            'feature_statistics': {}
        }
        
        # Calculate statistics for numerical features
        for feature_name, values in self.feature_statistics.items():
            if values:
                stats['feature_statistics'][feature_name] = {
                    'mean': np.mean(values),
                    'std': np.std(values),
                    'min': np.min(values),
                    'max': np.max(values),
                    'count': len(values)
                }
        
        return stats
    
    def export_feature_definitions(self) -> Dict[str, Any]:
        """Export feature definitions for documentation"""
        
        if not self.extracted_feature_sets:
            return {}
        
        # Get a sample feature set to extract definitions
        sample_features = self.extracted_feature_sets[0].features
        
        definitions = {}
        for name, feature in sample_features.items():
            definitions[name] = {
                'type': feature.feature_type.value,
                'source': feature.source,
                'description': feature.description
            }
        
        return definitions