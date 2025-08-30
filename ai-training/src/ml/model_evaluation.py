"""
Model Evaluation System - Comprehensive evaluation and monitoring of ML models
for cryptocurrency risk assessment with performance metrics, explainability,
and deployment readiness assessment.
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
import json

# ML evaluation imports
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, classification_report, roc_curve, precision_recall_curve,
    average_precision_score, matthews_corrcoef, cohen_kappa_score
)
from sklearn.calibration import calibration_curve
from sklearn.model_selection import learning_curve, validation_curve
import shap

from ..utils.logging import LoggingMixin
from .risk_scoring_engine import RiskCategory, IncidentType


class EvaluationMetric(Enum):
    """Types of evaluation metrics"""
    ACCURACY = "accuracy"
    PRECISION = "precision"
    RECALL = "recall"
    F1_SCORE = "f1_score"
    AUC_ROC = "auc_roc"
    AUC_PR = "auc_pr"
    MATTHEWS_CORRCOEF = "matthews_corrcoef"
    COHEN_KAPPA = "cohen_kappa"
    CALIBRATION_ERROR = "calibration_error"


@dataclass
class EvaluationMetrics:
    """Container for model evaluation metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: Optional[float] = None
    auc_pr: Optional[float] = None
    matthews_corrcoef: float = 0.0
    cohen_kappa: float = 0.0
    calibration_error: float = 0.0
    confusion_matrix: np.ndarray = field(default_factory=lambda: np.array([]))
    classification_report: Dict[str, Any] = field(default_factory=dict)
    
    def meets_threshold(self, thresholds: Dict[str, float]) -> bool:
        """Check if metrics meet minimum thresholds"""
        checks = {
            'accuracy': self.accuracy >= thresholds.get('accuracy', 0.9),
            'precision': self.precision >= thresholds.get('precision', 0.85),
            'recall': self.recall >= thresholds.get('recall', 0.95),
            'f1_score': self.f1_score >= thresholds.get('f1_score', 0.9)
        }
        
        return all(checks.values())


@dataclass
class ModelPerformanceReport:
    """Comprehensive model performance report"""
    model_name: str
    model_type: str
    evaluation_timestamp: datetime
    metrics: EvaluationMetrics
    feature_importance: Dict[str, float]
    prediction_examples: List[Dict[str, Any]]
    performance_summary: str
    deployment_ready: bool
    recommendations: List[str]
    evaluation_plots: Dict[str, str] = field(default_factory=dict)  # plot_type -> file_path


class ModelEvaluator(LoggingMixin):
    """
    Comprehensive model evaluation system for cryptocurrency risk assessment models.
    Provides detailed performance analysis, explainability, and deployment readiness.
    """
    
    # Performance thresholds for different model types
    PERFORMANCE_THRESHOLDS = {
        'binary_classifier': {
            'accuracy': 0.90,
            'precision': 0.85,
            'recall': 0.95,  # High recall for security
            'f1_score': 0.90
        },
        'risk_category': {
            'accuracy': 0.85,
            'precision': 0.80,
            'recall': 0.85,
            'f1_score': 0.82
        },
        'incident_type': {
            'accuracy': 0.80,
            'precision': 0.75,
            'recall': 0.80,
            'f1_score': 0.77
        }
    }
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        
        # Configuration
        self.output_dir = Path(config.get('evaluation_output_dir', './evaluation_results'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.enable_shap_analysis = config.get('enable_shap_analysis', True)
        self.enable_plots = config.get('enable_plots', True)
        self.plot_format = config.get('plot_format', 'png')
        self.max_shap_samples = config.get('max_shap_samples', 100)
        
        # Performance tracking
        self.evaluation_history = []
        
        self.logger.info(
            "Model Evaluator initialized",
            output_dir=str(self.output_dir),
            shap_enabled=self.enable_shap_analysis,
            plots_enabled=self.enable_plots
        )
    
    def evaluate_model(self, model, X_test: pd.DataFrame, y_test: pd.Series,
                      model_name: str, model_type: str = 'binary_classifier',
                      X_train: Optional[pd.DataFrame] = None) -> ModelPerformanceReport:
        """
        Comprehensive evaluation of a trained model.
        
        Args:
            model: Trained model object
            X_test: Test features
            y_test: Test targets
            model_name: Name identifier for the model
            model_type: Type of model for threshold selection
            X_train: Optional training data for additional analysis
            
        Returns:
            ModelPerformanceReport with comprehensive evaluation
        """
        try:
            self.logger.info(f"Evaluating model: {model_name}")
            
            # Get predictions
            y_pred = model.predict(X_test)
            y_prob = None
            
            if hasattr(model, 'predict_proba'):
                y_prob = model.predict_proba(X_test)
                if y_prob.shape[1] == 2:  # Binary classification
                    y_prob = y_prob[:, 1]  # Get positive class probabilities
            
            # Calculate metrics
            metrics = self._calculate_metrics(y_test, y_pred, y_prob)
            
            # Feature importance
            feature_importance = self._extract_feature_importance(model, X_test.columns)
            
            # SHAP analysis
            shap_values = None
            if self.enable_shap_analysis and X_train is not None:
                shap_values = self._calculate_shap_values(model, X_test, X_train)
            
            # Generate plots
            plots = {}
            if self.enable_plots:
                plots = self._generate_evaluation_plots(
                    y_test, y_pred, y_prob, model_name, shap_values
                )
            
            # Prediction examples
            prediction_examples = self._create_prediction_examples(
                X_test, y_test, y_pred, y_prob, feature_importance
            )
            
            # Performance assessment
            deployment_ready = metrics.meets_threshold(
                self.PERFORMANCE_THRESHOLDS.get(model_type, {})
            )
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                metrics, feature_importance, model_type, deployment_ready
            )
            
            # Create performance summary
            performance_summary = self._create_performance_summary(
                metrics, model_name, deployment_ready
            )
            
            # Create report
            report = ModelPerformanceReport(
                model_name=model_name,
                model_type=model_type,
                evaluation_timestamp=datetime.now(timezone.utc),
                metrics=metrics,
                feature_importance=feature_importance,
                prediction_examples=prediction_examples,
                performance_summary=performance_summary,
                deployment_ready=deployment_ready,
                recommendations=recommendations,
                evaluation_plots=plots
            )
            
            # Save report
            self._save_report(report)
            
            # Track evaluation history
            self.evaluation_history.append({
                'timestamp': report.evaluation_timestamp,
                'model_name': model_name,
                'model_type': model_type,
                'accuracy': metrics.accuracy,
                'f1_score': metrics.f1_score,
                'deployment_ready': deployment_ready
            })
            
            self.logger.info(
                f"Model evaluation completed for {model_name}",
                accuracy=metrics.accuracy,
                f1_score=metrics.f1_score,
                deployment_ready=deployment_ready
            )
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error evaluating model {model_name}: {e}")
            raise
    
    def _calculate_metrics(self, y_true: pd.Series, y_pred: np.ndarray, 
                         y_prob: Optional[np.ndarray] = None) -> EvaluationMetrics:
        """Calculate comprehensive evaluation metrics"""
        
        # Basic metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_true, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        
        # Classification report
        class_report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
        
        # Additional metrics
        matthews_coeff = matthews_corrcoef(y_true, y_pred)
        kappa = cohen_kappa_score(y_true, y_pred)
        
        # Probability-based metrics
        auc_roc = None
        auc_pr = None
        calibration_error = 0.0
        
        if y_prob is not None:
            try:
                # ROC AUC (for binary classification)
                if len(np.unique(y_true)) == 2:
                    auc_roc = roc_auc_score(y_true, y_prob)
                    auc_pr = average_precision_score(y_true, y_prob)
                    
                    # Calibration error
                    calibration_error = self._calculate_calibration_error(y_true, y_prob)
            except Exception as e:
                self.logger.warning(f"Could not calculate probability-based metrics: {e}")
        
        return EvaluationMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            auc_roc=auc_roc,
            auc_pr=auc_pr,
            matthews_corrcoef=matthews_coeff,
            cohen_kappa=kappa,
            calibration_error=calibration_error,
            confusion_matrix=cm,
            classification_report=class_report
        )
    
    def _calculate_calibration_error(self, y_true: pd.Series, y_prob: np.ndarray, 
                                   n_bins: int = 10) -> float:
        """Calculate Expected Calibration Error (ECE)"""
        
        try:
            bin_boundaries = np.linspace(0, 1, n_bins + 1)
            bin_lowers = bin_boundaries[:-1]
            bin_uppers = bin_boundaries[1:]
            
            ece = 0
            for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
                # Find samples in this bin
                in_bin = (y_prob > bin_lower) & (y_prob <= bin_upper)
                prop_in_bin = in_bin.mean()
                
                if prop_in_bin > 0:
                    # Accuracy in this bin
                    accuracy_in_bin = y_true[in_bin].mean()
                    # Average confidence in this bin
                    avg_confidence_in_bin = y_prob[in_bin].mean()
                    # Add to ECE
                    ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin
            
            return ece
            
        except Exception as e:
            self.logger.warning(f"Could not calculate calibration error: {e}")
            return 0.0
    
    def _extract_feature_importance(self, model, feature_names: List[str]) -> Dict[str, float]:
        """Extract feature importance from model"""
        
        try:
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
            elif hasattr(model, 'coef_'):
                importances = np.abs(model.coef_[0]) if model.coef_.ndim > 1 else np.abs(model.coef_)
            else:
                return {}
            
            importance_dict = dict(zip(feature_names, importances))
            
            # Sort by importance
            sorted_importance = dict(
                sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
            )
            
            return sorted_importance
            
        except Exception as e:
            self.logger.warning(f"Could not extract feature importance: {e}")
            return {}
    
    def _calculate_shap_values(self, model, X_test: pd.DataFrame, X_train: pd.DataFrame) -> Optional[np.ndarray]:
        """Calculate SHAP values for model explainability"""
        
        if not self.enable_shap_analysis:
            return None
        
        try:
            # Sample data if too large
            if len(X_test) > self.max_shap_samples:
                sample_indices = np.random.choice(len(X_test), self.max_shap_samples, replace=False)
                X_test_sample = X_test.iloc[sample_indices]
            else:
                X_test_sample = X_test
            
            # Create SHAP explainer
            if hasattr(model, 'predict_proba'):
                # Tree-based models
                if hasattr(model, 'estimators_') or 'XGB' in str(type(model)):
                    explainer = shap.TreeExplainer(model)
                else:
                    # Use KernelExplainer for other models
                    explainer = shap.KernelExplainer(
                        model.predict_proba, 
                        X_train.sample(min(100, len(X_train)))  # Background sample
                    )
            else:
                explainer = shap.KernelExplainer(
                    model.predict,
                    X_train.sample(min(100, len(X_train)))
                )
            
            # Calculate SHAP values
            shap_values = explainer.shap_values(X_test_sample)
            
            # For binary classification, get positive class SHAP values
            if isinstance(shap_values, list) and len(shap_values) == 2:
                shap_values = shap_values[1]
            
            return shap_values
            
        except Exception as e:
            self.logger.warning(f"Could not calculate SHAP values: {e}")
            return None
    
    def _generate_evaluation_plots(self, y_test: pd.Series, y_pred: np.ndarray,
                                 y_prob: Optional[np.ndarray], model_name: str,
                                 shap_values: Optional[np.ndarray] = None) -> Dict[str, str]:
        """Generate evaluation plots"""
        
        plots = {}
        
        try:
            # Set style
            plt.style.use('default')
            sns.set_palette("husl")
            
            # 1. Confusion Matrix
            plt.figure(figsize=(8, 6))
            cm = confusion_matrix(y_test, y_pred)
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
            plt.title(f'Confusion Matrix - {model_name}')
            plt.ylabel('True Label')
            plt.xlabel('Predicted Label')
            
            cm_path = self.output_dir / f"{model_name}_confusion_matrix.{self.plot_format}"
            plt.savefig(cm_path, dpi=300, bbox_inches='tight')
            plt.close()
            plots['confusion_matrix'] = str(cm_path)
            
            # 2. ROC Curve (if probabilities available and binary classification)
            if y_prob is not None and len(np.unique(y_test)) == 2:
                plt.figure(figsize=(8, 6))
                fpr, tpr, _ = roc_curve(y_test, y_prob)
                auc_score = roc_auc_score(y_test, y_prob)
                
                plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {auc_score:.3f})')
                plt.plot([0, 1], [0, 1], 'k--', label='Random Classifier')
                plt.xlim([0.0, 1.0])
                plt.ylim([0.0, 1.05])
                plt.xlabel('False Positive Rate')
                plt.ylabel('True Positive Rate')
                plt.title(f'ROC Curve - {model_name}')
                plt.legend()
                plt.grid(True, alpha=0.3)
                
                roc_path = self.output_dir / f"{model_name}_roc_curve.{self.plot_format}"
                plt.savefig(roc_path, dpi=300, bbox_inches='tight')
                plt.close()
                plots['roc_curve'] = str(roc_path)
                
                # 3. Precision-Recall Curve
                plt.figure(figsize=(8, 6))
                precision, recall, _ = precision_recall_curve(y_test, y_prob)
                ap_score = average_precision_score(y_test, y_prob)
                
                plt.plot(recall, precision, label=f'PR Curve (AP = {ap_score:.3f})')
                plt.xlabel('Recall')
                plt.ylabel('Precision')
                plt.title(f'Precision-Recall Curve - {model_name}')
                plt.legend()
                plt.grid(True, alpha=0.3)
                
                pr_path = self.output_dir / f"{model_name}_pr_curve.{self.plot_format}"
                plt.savefig(pr_path, dpi=300, bbox_inches='tight')
                plt.close()
                plots['pr_curve'] = str(pr_path)
            
            # 4. SHAP Summary Plot
            if shap_values is not None:
                plt.figure(figsize=(10, 8))
                shap.summary_plot(shap_values, features=X_test.sample(len(shap_values)), show=False)
                plt.title(f'SHAP Summary Plot - {model_name}')
                
                shap_path = self.output_dir / f"{model_name}_shap_summary.{self.plot_format}"
                plt.savefig(shap_path, dpi=300, bbox_inches='tight')
                plt.close()
                plots['shap_summary'] = str(shap_path)
            
        except Exception as e:
            self.logger.warning(f"Error generating plots: {e}")
        
        return plots
    
    def _create_prediction_examples(self, X_test: pd.DataFrame, y_test: pd.Series,
                                  y_pred: np.ndarray, y_prob: Optional[np.ndarray],
                                  feature_importance: Dict[str, float]) -> List[Dict[str, Any]]:
        """Create example predictions for analysis"""
        
        examples = []
        
        try:
            # Get indices for different types of predictions
            correct_positive = ((y_test == 1) & (y_pred == 1))
            correct_negative = ((y_test == 0) & (y_pred == 0))
            false_positive = ((y_test == 0) & (y_pred == 1))
            false_negative = ((y_test == 1) & (y_pred == 0))
            
            # Get top features
            top_features = list(feature_importance.keys())[:10]
            
            # Sample examples from each category
            for category, mask, max_samples in [
                ('correct_positive', correct_positive, 3),
                ('correct_negative', correct_negative, 3),
                ('false_positive', false_positive, 3),
                ('false_negative', false_negative, 3)
            ]:
                indices = np.where(mask)[0]
                if len(indices) > 0:
                    sample_indices = np.random.choice(
                        indices, min(max_samples, len(indices)), replace=False
                    )
                    
                    for idx in sample_indices:
                        example = {
                            'category': category,
                            'true_label': int(y_test.iloc[idx]),
                            'predicted_label': int(y_pred[idx]),
                            'confidence': float(y_prob[idx]) if y_prob is not None else None,
                            'top_features': {
                                feature: float(X_test.iloc[idx][feature])
                                for feature in top_features
                                if feature in X_test.columns
                            }
                        }
                        examples.append(example)
            
        except Exception as e:
            self.logger.warning(f"Error creating prediction examples: {e}")
        
        return examples
    
    def _generate_recommendations(self, metrics: EvaluationMetrics, 
                                feature_importance: Dict[str, float],
                                model_type: str, deployment_ready: bool) -> List[str]:
        """Generate recommendations for model improvement"""
        
        recommendations = []
        
        # Performance-based recommendations
        if metrics.accuracy < 0.9:
            recommendations.append("Consider collecting more training data to improve accuracy")
        
        if metrics.precision < 0.85:
            recommendations.append("Review feature engineering to reduce false positives")
        
        if metrics.recall < 0.9:
            recommendations.append("⚠️ Low recall detected - may miss critical threats. Consider adjusting classification threshold")
        
        if metrics.f1_score < 0.85:
            recommendations.append("F1 score suggests imbalanced performance - review class distribution")
        
        # Feature importance recommendations
        if feature_importance:
            top_feature = list(feature_importance.keys())[0]
            if feature_importance[top_feature] > 0.5:
                recommendations.append(f"Model heavily relies on '{top_feature}' - consider feature diversity")
        
        # Model-specific recommendations
        if model_type == 'binary_classifier':
            if metrics.auc_roc and metrics.auc_roc < 0.9:
                recommendations.append("AUC-ROC below 0.9 - consider ensemble methods")
        
        # Calibration recommendations
        if metrics.calibration_error > 0.1:
            recommendations.append("High calibration error - consider calibration techniques")
        
        # Deployment recommendations
        if not deployment_ready:
            recommendations.append("🚫 Model does not meet deployment thresholds - requires improvement before production use")
        else:
            recommendations.append("✅ Model meets performance criteria for deployment")
        
        return recommendations
    
    def _create_performance_summary(self, metrics: EvaluationMetrics, 
                                  model_name: str, deployment_ready: bool) -> str:
        """Create human-readable performance summary"""
        
        summary_parts = [
            f"Model '{model_name}' Performance Summary:",
            f"• Accuracy: {metrics.accuracy:.3f}",
            f"• Precision: {metrics.precision:.3f}",
            f"• Recall: {metrics.recall:.3f}",
            f"• F1-Score: {metrics.f1_score:.3f}"
        ]
        
        if metrics.auc_roc:
            summary_parts.append(f"• AUC-ROC: {metrics.auc_roc:.3f}")
        
        if metrics.auc_pr:
            summary_parts.append(f"• AUC-PR: {metrics.auc_pr:.3f}")
        
        summary_parts.append(f"• Matthews Correlation: {metrics.matthews_corrcoef:.3f}")
        summary_parts.append(f"• Cohen's Kappa: {metrics.cohen_kappa:.3f}")
        
        if deployment_ready:
            summary_parts.append("✅ DEPLOYMENT READY: All performance thresholds met")
        else:
            summary_parts.append("🚫 NOT DEPLOYMENT READY: Performance below thresholds")
        
        return "\n".join(summary_parts)
    
    def _save_report(self, report: ModelPerformanceReport):
        """Save evaluation report to disk"""
        
        try:
            # Create report dictionary
            report_dict = {
                'model_name': report.model_name,
                'model_type': report.model_type,
                'evaluation_timestamp': report.evaluation_timestamp.isoformat(),
                'metrics': {
                    'accuracy': report.metrics.accuracy,
                    'precision': report.metrics.precision,
                    'recall': report.metrics.recall,
                    'f1_score': report.metrics.f1_score,
                    'auc_roc': report.metrics.auc_roc,
                    'auc_pr': report.metrics.auc_pr,
                    'matthews_corrcoef': report.metrics.matthews_corrcoef,
                    'cohen_kappa': report.metrics.cohen_kappa,
                    'calibration_error': report.metrics.calibration_error,
                    'confusion_matrix': report.metrics.confusion_matrix.tolist(),
                    'classification_report': report.metrics.classification_report
                },
                'feature_importance': report.feature_importance,
                'prediction_examples': report.prediction_examples,
                'performance_summary': report.performance_summary,
                'deployment_ready': report.deployment_ready,
                'recommendations': report.recommendations,
                'evaluation_plots': report.evaluation_plots
            }
            
            # Save as JSON
            timestamp = report.evaluation_timestamp.strftime("%Y%m%d_%H%M%S")
            report_path = self.output_dir / f"{report.model_name}_evaluation_{timestamp}.json"
            
            with open(report_path, 'w') as f:
                json.dump(report_dict, f, indent=2, default=str)
            
            self.logger.info(f"Evaluation report saved: {report_path}")
            
        except Exception as e:
            self.logger.error(f"Error saving evaluation report: {e}")
    
    def compare_models(self, reports: List[ModelPerformanceReport]) -> Dict[str, Any]:
        """Compare multiple model evaluation reports"""
        
        if not reports:
            return {}
        
        comparison = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'models_compared': len(reports),
            'metrics_comparison': {},
            'best_model': None,
            'recommendations': []
        }
        
        # Extract metrics for comparison
        metrics_data = {}
        for report in reports:
            metrics_data[report.model_name] = {
                'accuracy': report.metrics.accuracy,
                'precision': report.metrics.precision,
                'recall': report.metrics.recall,
                'f1_score': report.metrics.f1_score,
                'deployment_ready': report.deployment_ready
            }
        
        comparison['metrics_comparison'] = metrics_data
        
        # Find best model by F1 score
        best_model = max(reports, key=lambda r: r.metrics.f1_score)
        comparison['best_model'] = {
            'name': best_model.model_name,
            'f1_score': best_model.metrics.f1_score,
            'deployment_ready': best_model.deployment_ready
        }
        
        # Generate comparison recommendations
        deployment_ready_count = sum(1 for r in reports if r.deployment_ready)
        
        if deployment_ready_count == 0:
            comparison['recommendations'].append("No models meet deployment criteria - additional development required")
        elif deployment_ready_count == 1:
            comparison['recommendations'].append("One model ready for deployment - consider ensemble methods")
        else:
            comparison['recommendations'].append("Multiple models ready - consider ensemble approach for best performance")
        
        return comparison
    
    def get_evaluation_statistics(self) -> Dict[str, Any]:
        """Get evaluation system statistics"""
        
        return {
            'total_evaluations': len(self.evaluation_history),
            'output_directory': str(self.output_dir),
            'configuration': {
                'shap_enabled': self.enable_shap_analysis,
                'plots_enabled': self.enable_plots,
                'plot_format': self.plot_format,
                'max_shap_samples': self.max_shap_samples
            },
            'recent_evaluations': self.evaluation_history[-10:] if self.evaluation_history else [],
            'performance_thresholds': self.PERFORMANCE_THRESHOLDS
        }