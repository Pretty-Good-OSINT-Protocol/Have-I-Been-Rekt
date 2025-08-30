"""
ML Training Pipeline - Comprehensive machine learning pipeline for training
cryptocurrency risk assessment models using data from all collectors.

Supports binary classification, multi-class incident classification, and
recommendation systems with automated hyperparameter tuning and evaluation.
"""

import numpy as np
import pandas as pd
import pickle
import joblib
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
import logging

# ML imports
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler, LabelEncoder, OneHotEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
import xgboost as xgb

from ..utils.logging import LoggingMixin
from .risk_scoring_engine import RiskCategory, IncidentType


class ModelType(Enum):
    """Types of ML models to train"""
    BINARY_CLASSIFIER = "binary_classifier"       # Clean vs Risk
    RISK_CATEGORY_CLASSIFIER = "risk_category"    # Multi-class risk levels
    INCIDENT_TYPE_CLASSIFIER = "incident_type"    # Incident classification
    RECOMMENDATION_ENGINE = "recommendation"      # Next action recommendations
    ENSEMBLE_MODEL = "ensemble"                   # Combined ensemble


@dataclass
class TrainingConfig:
    """Configuration for ML model training"""
    model_type: ModelType
    test_size: float = 0.2
    validation_size: float = 0.2
    random_state: int = 42
    cross_validation_folds: int = 5
    hyperparameter_tuning: bool = True
    feature_selection: bool = True
    class_balancing: bool = True
    model_output_dir: str = "./models"
    enable_ensemble: bool = True
    performance_threshold: Dict[str, float] = field(default_factory=lambda: {
        'accuracy': 0.9,
        'precision': 0.85,
        'recall': 0.95,
        'f1_score': 0.9
    })


@dataclass
class TrainingResult:
    """Result of model training"""
    model_type: ModelType
    model_path: str
    performance_metrics: Dict[str, float]
    feature_importance: Dict[str, float]
    training_time: float
    validation_scores: List[float]
    best_hyperparameters: Dict[str, Any]
    model_size_mb: float
    training_data_size: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class MLTrainingPipeline(LoggingMixin):
    """
    Comprehensive ML training pipeline for cryptocurrency risk assessment.
    Handles data preparation, feature engineering, model training, and evaluation.
    """
    
    # Model configurations
    MODEL_CONFIGS = {
        ModelType.BINARY_CLASSIFIER: {
            'algorithms': ['random_forest', 'gradient_boosting', 'xgboost', 'logistic_regression'],
            'target_column': 'is_risky',
            'metrics': ['accuracy', 'precision', 'recall', 'f1_score', 'auc_roc']
        },
        ModelType.RISK_CATEGORY_CLASSIFIER: {
            'algorithms': ['random_forest', 'gradient_boosting', 'xgboost'],
            'target_column': 'risk_category',
            'metrics': ['accuracy', 'precision_macro', 'recall_macro', 'f1_macro']
        },
        ModelType.INCIDENT_TYPE_CLASSIFIER: {
            'algorithms': ['random_forest', 'gradient_boosting', 'svm'],
            'target_column': 'incident_type',
            'metrics': ['accuracy', 'precision_macro', 'recall_macro', 'f1_macro']
        }
    }
    
    # Hyperparameter grids for tuning
    HYPERPARAMETER_GRIDS = {
        'random_forest': {
            'n_estimators': [100, 200, 300],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4],
            'max_features': ['sqrt', 'log2', None]
        },
        'gradient_boosting': {
            'n_estimators': [100, 200, 300],
            'learning_rate': [0.01, 0.1, 0.2],
            'max_depth': [3, 5, 7],
            'subsample': [0.8, 0.9, 1.0]
        },
        'xgboost': {
            'n_estimators': [100, 200, 300],
            'learning_rate': [0.01, 0.1, 0.2],
            'max_depth': [3, 5, 7],
            'subsample': [0.8, 0.9, 1.0],
            'colsample_bytree': [0.8, 0.9, 1.0]
        },
        'logistic_regression': {
            'C': [0.01, 0.1, 1, 10, 100],
            'penalty': ['l1', 'l2'],
            'solver': ['liblinear', 'saga']
        },
        'svm': {
            'C': [0.1, 1, 10, 100],
            'kernel': ['rbf', 'poly', 'sigmoid'],
            'gamma': ['scale', 'auto', 0.001, 0.01]
        }
    }
    
    def __init__(self, config: TrainingConfig, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        
        self.config = config
        self.trained_models = {}
        self.feature_encoders = {}
        self.label_encoders = {}
        self.scalers = {}
        
        # Create output directory
        Path(self.config.model_output_dir).mkdir(parents=True, exist_ok=True)
        
        self.logger.info(
            "ML Training Pipeline initialized",
            model_type=config.model_type.value,
            output_dir=config.model_output_dir
        )
    
    def prepare_training_data(self, training_data: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Prepare training data with feature engineering and preprocessing.
        
        Args:
            training_data: Raw training data from all collectors
            
        Returns:
            Tuple of (features_df, target_series)
        """
        try:
            self.logger.info(f"Preparing training data: {len(training_data)} samples")
            
            # Get model configuration
            model_config = self.MODEL_CONFIGS[self.config.model_type]
            target_column = model_config['target_column']
            
            if target_column not in training_data.columns:
                raise ValueError(f"Target column '{target_column}' not found in training data")
            
            # Separate features and target
            target = training_data[target_column].copy()
            features = training_data.drop(columns=[target_column])
            
            # Feature preprocessing
            features = self._preprocess_features(features)
            
            # Handle class imbalance for classification
            if self.config.class_balancing:
                features, target = self._balance_classes(features, target)
            
            self.logger.info(
                f"Training data prepared: {len(features)} samples, {len(features.columns)} features"
            )
            
            return features, target
            
        except Exception as e:
            self.logger.error(f"Error preparing training data: {e}")
            raise
    
    def _preprocess_features(self, features: pd.DataFrame) -> pd.DataFrame:
        """Preprocess features for ML training"""
        
        processed_features = features.copy()
        
        # Handle missing values
        processed_features = processed_features.fillna(0)
        
        # Encode categorical features
        categorical_columns = processed_features.select_dtypes(include=['object', 'category']).columns
        
        for col in categorical_columns:
            if col not in self.label_encoders:
                self.label_encoders[col] = LabelEncoder()
                processed_features[col] = self.label_encoders[col].fit_transform(processed_features[col].astype(str))
            else:
                # Handle unseen categories
                known_categories = set(self.label_encoders[col].classes_)
                processed_features[col] = processed_features[col].astype(str).apply(
                    lambda x: x if x in known_categories else 'unknown'
                )
                processed_features[col] = self.label_encoders[col].transform(processed_features[col])
        
        # Scale numerical features
        numerical_columns = processed_features.select_dtypes(include=['int64', 'float64']).columns
        
        if len(numerical_columns) > 0:
            if 'numerical' not in self.scalers:
                self.scalers['numerical'] = StandardScaler()
                processed_features[numerical_columns] = self.scalers['numerical'].fit_transform(
                    processed_features[numerical_columns]
                )
            else:
                processed_features[numerical_columns] = self.scalers['numerical'].transform(
                    processed_features[numerical_columns]
                )
        
        return processed_features
    
    def _balance_classes(self, features: pd.DataFrame, target: pd.Series) -> Tuple[pd.DataFrame, pd.Series]:
        """Balance classes using sampling techniques"""
        
        try:
            from imblearn.over_sampling import SMOTE
            from imblearn.combine import SMOTEENN
            
            # Use SMOTE for oversampling minority classes
            smote = SMOTE(random_state=self.config.random_state)
            features_balanced, target_balanced = smote.fit_resample(features, target)
            
            self.logger.info(
                f"Class balancing applied: {len(features)} -> {len(features_balanced)} samples"
            )
            
            return pd.DataFrame(features_balanced, columns=features.columns), pd.Series(target_balanced)
            
        except ImportError:
            self.logger.warning("imbalanced-learn not available, skipping class balancing")
            return features, target
    
    def train_model(self, features: pd.DataFrame, target: pd.Series) -> TrainingResult:
        """
        Train ML model with hyperparameter tuning and cross-validation.
        
        Args:
            features: Training features
            target: Training target
            
        Returns:
            TrainingResult with model performance and metadata
        """
        try:
            start_time = datetime.now()
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                features, target,
                test_size=self.config.test_size,
                random_state=self.config.random_state,
                stratify=target if self.config.model_type != ModelType.RECOMMENDATION_ENGINE else None
            )
            
            # Get best model through algorithm comparison
            best_model, best_params = self._find_best_algorithm(X_train, y_train)
            
            # Train final model
            final_model = best_model.set_params(**best_params)
            final_model.fit(X_train, y_train)
            
            # Evaluate model
            performance_metrics = self._evaluate_model(final_model, X_test, y_test)
            
            # Get feature importance
            feature_importance = self._get_feature_importance(final_model, features.columns)
            
            # Cross-validation scores
            cv_scores = cross_val_score(
                final_model, X_train, y_train,
                cv=self.config.cross_validation_folds,
                scoring='accuracy'
            )
            
            # Save model
            model_path = self._save_model(final_model)
            model_size_mb = Path(model_path).stat().st_size / (1024 * 1024)
            
            training_time = (datetime.now() - start_time).total_seconds()
            
            # Store trained model
            self.trained_models[self.config.model_type] = final_model
            
            result = TrainingResult(
                model_type=self.config.model_type,
                model_path=model_path,
                performance_metrics=performance_metrics,
                feature_importance=feature_importance,
                training_time=training_time,
                validation_scores=cv_scores.tolist(),
                best_hyperparameters=best_params,
                model_size_mb=model_size_mb,
                training_data_size=len(features)
            )
            
            self.logger.info(
                f"Model training completed",
                model_type=self.config.model_type.value,
                accuracy=performance_metrics.get('accuracy', 0),
                training_time=training_time
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error training model: {e}")
            raise
    
    def _find_best_algorithm(self, X_train: pd.DataFrame, y_train: pd.Series) -> Tuple[Any, Dict[str, Any]]:
        """Find best algorithm through cross-validation and hyperparameter tuning"""
        
        model_config = self.MODEL_CONFIGS[self.config.model_type]
        algorithms = model_config['algorithms']
        
        best_score = -1
        best_model = None
        best_params = {}
        
        for algorithm in algorithms:
            try:
                self.logger.info(f"Testing algorithm: {algorithm}")
                
                # Get base model
                model = self._get_base_model(algorithm)
                
                # Hyperparameter tuning if enabled
                if self.config.hyperparameter_tuning and algorithm in self.HYPERPARAMETER_GRIDS:
                    param_grid = self.HYPERPARAMETER_GRIDS[algorithm]
                    
                    grid_search = GridSearchCV(
                        model, param_grid,
                        cv=self.config.cross_validation_folds,
                        scoring='accuracy',
                        n_jobs=-1,
                        verbose=0
                    )
                    
                    grid_search.fit(X_train, y_train)
                    
                    score = grid_search.best_score_
                    current_model = grid_search.best_estimator_
                    current_params = grid_search.best_params_
                    
                else:
                    # Simple cross-validation
                    scores = cross_val_score(model, X_train, y_train, cv=self.config.cross_validation_folds)
                    score = np.mean(scores)
                    current_model = model
                    current_params = {}
                
                self.logger.info(f"{algorithm} CV score: {score:.4f}")
                
                if score > best_score:
                    best_score = score
                    best_model = current_model
                    best_params = current_params
                    
            except Exception as e:
                self.logger.warning(f"Error testing {algorithm}: {e}")
                continue
        
        if best_model is None:
            raise ValueError("No successful model training found")
        
        self.logger.info(f"Best algorithm selected with CV score: {best_score:.4f}")
        
        return best_model, best_params
    
    def _get_base_model(self, algorithm: str):
        """Get base model instance for algorithm"""
        
        models = {
            'random_forest': RandomForestClassifier(random_state=self.config.random_state),
            'gradient_boosting': GradientBoostingClassifier(random_state=self.config.random_state),
            'xgboost': xgb.XGBClassifier(random_state=self.config.random_state, eval_metric='logloss'),
            'logistic_regression': LogisticRegression(random_state=self.config.random_state, max_iter=1000),
            'svm': SVC(random_state=self.config.random_state, probability=True)
        }
        
        if algorithm not in models:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        return models[algorithm]
    
    def _evaluate_model(self, model, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, float]:
        """Evaluate model performance on test set"""
        
        predictions = model.predict(X_test)
        
        # Basic metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        metrics = {
            'accuracy': accuracy_score(y_test, predictions),
            'precision': precision_score(y_test, predictions, average='weighted', zero_division=0),
            'recall': recall_score(y_test, predictions, average='weighted', zero_division=0),
            'f1_score': f1_score(y_test, predictions, average='weighted', zero_division=0)
        }
        
        # ROC AUC for binary classification
        if hasattr(model, 'predict_proba') and len(np.unique(y_test)) == 2:
            probabilities = model.predict_proba(X_test)[:, 1]
            metrics['auc_roc'] = roc_auc_score(y_test, probabilities)
        
        return metrics
    
    def _get_feature_importance(self, model, feature_names: List[str]) -> Dict[str, float]:
        """Get feature importance from trained model"""
        
        try:
            if hasattr(model, 'feature_importances_'):
                importance_values = model.feature_importances_
            elif hasattr(model, 'coef_'):
                importance_values = np.abs(model.coef_[0])
            else:
                return {}
            
            importance_dict = dict(zip(feature_names, importance_values))
            
            # Sort by importance
            sorted_importance = dict(
                sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
            )
            
            return sorted_importance
            
        except Exception as e:
            self.logger.warning(f"Could not extract feature importance: {e}")
            return {}
    
    def _save_model(self, model) -> str:
        """Save trained model to disk"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_filename = f"{self.config.model_type.value}_{timestamp}.pkl"
        model_path = Path(self.config.model_output_dir) / model_filename
        
        # Save model
        joblib.dump(model, model_path)
        
        # Save encoders and scalers
        encoders_path = model_path.with_suffix('.encoders.pkl')
        joblib.dump({
            'label_encoders': self.label_encoders,
            'scalers': self.scalers
        }, encoders_path)
        
        return str(model_path)
    
    def load_model(self, model_path: str):
        """Load trained model from disk"""
        
        try:
            # Load model
            model = joblib.load(model_path)
            
            # Load encoders and scalers
            encoders_path = Path(model_path).with_suffix('.encoders.pkl')
            if encoders_path.exists():
                encoders_data = joblib.load(encoders_path)
                self.label_encoders = encoders_data.get('label_encoders', {})
                self.scalers = encoders_data.get('scalers', {})
            
            self.trained_models[self.config.model_type] = model
            
            self.logger.info(f"Model loaded successfully from {model_path}")
            
            return model
            
        except Exception as e:
            self.logger.error(f"Error loading model from {model_path}: {e}")
            raise
    
    def predict(self, features: pd.DataFrame) -> np.ndarray:
        """Make predictions using trained model"""
        
        if self.config.model_type not in self.trained_models:
            raise ValueError(f"No trained model found for {self.config.model_type}")
        
        model = self.trained_models[self.config.model_type]
        
        # Preprocess features
        processed_features = self._preprocess_features(features)
        
        return model.predict(processed_features)
    
    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        """Get prediction probabilities"""
        
        if self.config.model_type not in self.trained_models:
            raise ValueError(f"No trained model found for {self.config.model_type}")
        
        model = self.trained_models[self.config.model_type]
        
        if not hasattr(model, 'predict_proba'):
            raise ValueError("Model does not support probability predictions")
        
        # Preprocess features
        processed_features = self._preprocess_features(features)
        
        return model.predict_proba(processed_features)
    
    def create_ensemble_model(self, individual_models: List[Any]) -> VotingClassifier:
        """Create ensemble model from multiple trained models"""
        
        if not individual_models:
            raise ValueError("No models provided for ensemble")
        
        # Create voting classifier
        estimators = [(f"model_{i}", model) for i, model in enumerate(individual_models)]
        
        ensemble = VotingClassifier(
            estimators=estimators,
            voting='soft',  # Use probabilities if available
            n_jobs=-1
        )
        
        return ensemble
    
    def get_training_statistics(self) -> Dict[str, Any]:
        """Get training pipeline statistics"""
        
        return {
            'config': {
                'model_type': self.config.model_type.value,
                'test_size': self.config.test_size,
                'cross_validation_folds': self.config.cross_validation_folds,
                'hyperparameter_tuning': self.config.hyperparameter_tuning,
                'class_balancing': self.config.class_balancing
            },
            'trained_models': list(self.trained_models.keys()),
            'encoders': list(self.label_encoders.keys()),
            'scalers': list(self.scalers.keys()),
            'output_directory': self.config.model_output_dir
        }