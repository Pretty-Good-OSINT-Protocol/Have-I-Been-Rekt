#!/usr/bin/env python3
"""
Enhanced ML Training Pipeline - Train risk assessment models using
comprehensive multi-source blockchain investigation datasets with
Ethereum ecosystem prioritization.

Integrates:
- Elliptic++ Dataset (203k Bitcoin transactions, 822k addresses)
- Elliptic2 Money Laundering Patterns
- Ethereum Fraud Detection Dataset
- HuggingFace Smart Contract Vulnerabilities
- Multi-source threat intelligence
"""

import sys
import os
import json
import pandas as pd
import numpy as np
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.collectors.historical_crime_aggregator import HistoricalCrimeAggregator
from src.collectors.elliptic_plus_processor import EllipticPlusProcessor
from src.collectors.ethereum_dataset_processor import EthereumDatasetProcessor
from src.collectors.huggingface_datasets import HuggingFaceDatasetManager
from src.ml.ml_training_pipeline import MLTrainingPipeline
from src.ml.feature_engineering import FeatureEngineer
from src.ml.model_evaluation import ModelEvaluator
from src.utils.config import ConfigManager
from src.utils.logging import setup_logging

class EnhancedTrainingPipeline:
    """Enhanced training pipeline with multi-source dataset integration"""
    
    def __init__(self, config: dict, logger):
        self.config = config
        self.logger = logger
        
        # Initialize components
        self.aggregator = HistoricalCrimeAggregator(config, "./cache", logger)
        self.ml_pipeline = MLTrainingPipeline(config, logger)
        self.feature_engineer = FeatureEngineer(config, logger)
        self.evaluator = ModelEvaluator(config, logger)
        
        # Output directories
        self.models_dir = Path("./models")
        self.training_data_dir = Path("./data/training")
        self.results_dir = Path("./results")
        
        # Create directories
        for dir_path in [self.models_dir, self.training_data_dir, self.results_dir]:
            dir_path.mkdir(exist_ok=True, parents=True)
        
        self.logger.info("Enhanced training pipeline initialized")
    
    def collect_training_data(self) -> dict:
        """Collect and prepare training data from all sources"""
        
        self.logger.info("🔍 Collecting training data from all sources...")
        
        training_data = {
            'ethereum_data': None,
            'elliptic_plus_data': None,
            'elliptic2_data': None,
            'huggingface_data': None,
            'metadata': {
                'collection_timestamp': datetime.utcnow().isoformat(),
                'sources_attempted': [],
                'sources_successful': [],
                'total_samples': 0
            }
        }
        
        # Collect Ethereum dataset (PRIORITIZED)
        try:
            self.logger.info("📊 Collecting Ethereum fraud detection data...")
            ethereum_processor = self.aggregator.ethereum_datasets
            
            if ethereum_processor.is_configured():
                eth_data = ethereum_processor.get_training_data(include_features=True)
                training_data['ethereum_data'] = eth_data
                training_data['metadata']['sources_attempted'].append('ethereum')
                
                if eth_data['ethereum_transactions']:
                    training_data['metadata']['sources_successful'].append('ethereum')
                    training_data['metadata']['total_samples'] += eth_data['metadata']['total_transactions']
                    self.logger.info(f"✅ Ethereum data: {eth_data['metadata']['total_transactions']} transactions")
                
            else:
                self.logger.warning("❌ Ethereum datasets not configured")
                
        except Exception as e:
            self.logger.error(f"❌ Ethereum data collection failed: {e}")
        
        # Collect Elliptic++ dataset
        try:
            self.logger.info("📊 Collecting Elliptic++ data...")
            elliptic_plus = self.aggregator.elliptic_plus
            
            if elliptic_plus.is_configured():
                elliptic_data = elliptic_plus.get_training_data(include_unknown=False)
                training_data['elliptic_plus_data'] = elliptic_data
                training_data['metadata']['sources_attempted'].append('elliptic_plus')
                
                if elliptic_data['transactions'] or elliptic_data['actors']:
                    training_data['metadata']['sources_successful'].append('elliptic_plus')
                    tx_count = elliptic_data['metadata']['total_transactions']
                    actor_count = elliptic_data['metadata']['total_actors']
                    training_data['metadata']['total_samples'] += tx_count + actor_count
                    self.logger.info(f"✅ Elliptic++ data: {tx_count} transactions, {actor_count} addresses")
                
            else:
                self.logger.warning("❌ Elliptic++ dataset not configured - download from GitHub")
                
        except Exception as e:
            self.logger.error(f"❌ Elliptic++ data collection failed: {e}")
        
        # Collect HuggingFace smart contract data
        try:
            self.logger.info("📊 Collecting HuggingFace vulnerability data...")
            hf_manager = self.aggregator.huggingface_manager
            
            if hf_manager.is_configured():
                # Export training data
                export_path = self.training_data_dir / "huggingface_export"
                hf_files = hf_manager.export_for_training(str(export_path))
                
                if hf_files:
                    training_data['huggingface_data'] = {
                        'exported_files': hf_files,
                        'export_path': str(export_path)
                    }
                    training_data['metadata']['sources_attempted'].append('huggingface')
                    training_data['metadata']['sources_successful'].append('huggingface')
                    self.logger.info(f"✅ HuggingFace data: {len(hf_files)} dataset files exported")
                
            else:
                self.logger.warning("❌ HuggingFace datasets not configured - run: pip install datasets")
                
        except Exception as e:
            self.logger.error(f"❌ HuggingFace data collection failed: {e}")
        
        # Save training data metadata
        metadata_file = self.training_data_dir / "training_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(training_data['metadata'], f, indent=2)
        
        self.logger.info(f"📊 Training data collection complete:")
        self.logger.info(f"   Sources successful: {len(training_data['metadata']['sources_successful'])}")
        self.logger.info(f"   Total samples: {training_data['metadata']['total_samples']:,}")
        
        return training_data
    
    def prepare_unified_dataset(self, training_data: dict) -> pd.DataFrame:
        """Prepare unified dataset for ML training"""
        
        self.logger.info("🔧 Preparing unified training dataset...")
        
        unified_samples = []
        
        # Process Ethereum data (PRIORITIZED)
        if training_data.get('ethereum_data'):
            eth_data = training_data['ethereum_data']
            
            for tx in eth_data.get('ethereum_transactions', []):
                if tx.get('features') and isinstance(tx['features'], dict):
                    sample = {
                        'source': 'ethereum',
                        'address_type': 'ethereum',
                        'is_fraud': tx.get('is_fraud', False),
                        'confidence': 1.0,
                        **{f"eth_{k}": v for k, v in tx['features'].items() if isinstance(v, (int, float))}
                    }
                    unified_samples.append(sample)
            
            self.logger.info(f"✅ Processed {len(eth_data.get('ethereum_transactions', []))} Ethereum samples")
        
        # Process Elliptic++ data
        if training_data.get('elliptic_plus_data'):
            elliptic_data = training_data['elliptic_plus_data']
            
            # Process transaction data
            for tx in elliptic_data.get('transactions', []):
                if tx.get('features') and tx.get('label') != 'unknown':
                    sample = {
                        'source': 'elliptic_plus_tx',
                        'address_type': 'bitcoin',
                        'is_fraud': tx['label'] == 'illicit',
                        'confidence': 1.0,
                        **{f"elliptic_tx_{i}": v for i, v in enumerate(tx['features']) if isinstance(v, (int, float))}
                    }
                    unified_samples.append(sample)
            
            # Process actor data
            for actor in elliptic_data.get('actors', []):
                if actor.get('features') and actor.get('label') != 'unknown':
                    sample = {
                        'source': 'elliptic_plus_actor',
                        'address_type': 'bitcoin',
                        'is_fraud': actor['label'] == 'illicit',
                        'confidence': 1.0,
                        **{f"elliptic_actor_{i}": v for i, v in enumerate(actor['features']) if isinstance(v, (int, float))}
                    }
                    unified_samples.append(sample)
            
            tx_count = len(elliptic_data.get('transactions', []))
            actor_count = len(elliptic_data.get('actors', []))
            self.logger.info(f"✅ Processed {tx_count} Elliptic++ transactions, {actor_count} actors")
        
        # Convert to DataFrame
        if unified_samples:
            df = pd.DataFrame(unified_samples)
            
            # Fill NaN values with 0
            numeric_columns = df.select_dtypes(include=[np.number]).columns
            df[numeric_columns] = df[numeric_columns].fillna(0)
            
            self.logger.info(f"✅ Unified dataset created: {len(df)} samples, {len(df.columns)} features")
            
            # Save unified dataset
            dataset_file = self.training_data_dir / "unified_dataset.csv"
            df.to_csv(dataset_file, index=False)
            self.logger.info(f"💾 Saved unified dataset to: {dataset_file}")
            
            return df
        
        else:
            self.logger.error("❌ No training samples collected!")
            return pd.DataFrame()
    
    def train_models(self, dataset: pd.DataFrame) -> dict:
        """Train ML models on unified dataset"""
        
        if dataset.empty:
            self.logger.error("❌ Cannot train on empty dataset")
            return {}
        
        self.logger.info("🤖 Starting ML model training...")
        
        # Separate features and labels
        feature_columns = [col for col in dataset.columns 
                          if col not in ['source', 'address_type', 'is_fraud', 'confidence']]
        
        X = dataset[feature_columns]
        y = dataset['is_fraud']
        
        self.logger.info(f"📊 Training data shape: {X.shape}")
        self.logger.info(f"📊 Positive samples: {y.sum()}/{len(y)} ({y.mean():.2%})")
        
        # Feature engineering
        X_engineered = self.feature_engineer.engineer_features(X, dataset['address_type'])
        
        # Train models using the ML pipeline
        training_results = self.ml_pipeline.train_models(
            X_engineered, y,
            test_size=0.2,
            random_state=42
        )
        
        # Evaluate models
        evaluation_results = self.evaluator.evaluate_models(training_results)
        
        # Save models and results
        self._save_training_results(training_results, evaluation_results, dataset)
        
        return {
            'training_results': training_results,
            'evaluation_results': evaluation_results,
            'dataset_info': {
                'samples': len(dataset),
                'features': X_engineered.shape[1],
                'fraud_rate': y.mean(),
                'sources': dataset['source'].value_counts().to_dict()
            }
        }
    
    def _save_training_results(self, training_results: dict, evaluation_results: dict, dataset: pd.DataFrame):
        """Save training results and models"""
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        # Save models
        for model_name, model_info in training_results.get('trained_models', {}).items():
            model_file = self.models_dir / f"{model_name}_{timestamp}.pkl"
            
            import pickle
            with open(model_file, 'wb') as f:
                pickle.dump(model_info['model'], f)
            
            self.logger.info(f"💾 Saved {model_name} model to: {model_file}")
        
        # Save comprehensive results
        results = {
            'timestamp': timestamp,
            'dataset_info': {
                'total_samples': len(dataset),
                'features': dataset.shape[1],
                'fraud_rate': dataset['is_fraud'].mean(),
                'sources': dataset['source'].value_counts().to_dict(),
                'address_types': dataset['address_type'].value_counts().to_dict()
            },
            'training_results': training_results,
            'evaluation_results': evaluation_results,
            'model_files': list(self.models_dir.glob(f"*_{timestamp}.pkl"))
        }
        
        results_file = self.results_dir / f"training_results_{timestamp}.json"
        
        # Convert any non-serializable objects
        def serialize_results(obj):
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, (np.int64, np.int32)):
                return int(obj)
            elif isinstance(obj, (np.float64, np.float32)):
                return float(obj)
            elif isinstance(obj, Path):
                return str(obj)
            return obj
        
        import json
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=serialize_results)
        
        self.logger.info(f"💾 Saved training results to: {results_file}")
    
    def run_complete_training(self) -> dict:
        """Run the complete training pipeline"""
        
        self.logger.info("🚀 STARTING ENHANCED ML TRAINING PIPELINE")
        self.logger.info("=" * 60)
        
        # Step 1: Collect training data
        training_data = self.collect_training_data()
        
        # Step 2: Prepare unified dataset
        dataset = self.prepare_unified_dataset(training_data)
        
        if dataset.empty:
            self.logger.error("❌ No training data available - please download datasets first")
            return {}
        
        # Step 3: Train models
        results = self.train_models(dataset)
        
        self.logger.info("✅ ENHANCED ML TRAINING PIPELINE COMPLETE")
        self.logger.info("=" * 60)
        
        return results

def main():
    """Main training function"""
    
    print("🚀 ENHANCED BLOCKCHAIN INVESTIGATION AI TRAINING")
    print("=" * 60)
    print("Training with Ethereum prioritization + Elliptic Labs datasets")
    print("=" * 60)
    
    # Setup
    logger = setup_logging(log_level="INFO")
    config_manager = ConfigManager()
    config = config_manager.load_config()
    
    # Initialize and run training pipeline
    pipeline = EnhancedTrainingPipeline(config, logger)
    
    try:
        results = pipeline.run_complete_training()
        
        if results:
            print("\n🎉 TRAINING SUCCESS!")
            print(f"📊 Dataset: {results['dataset_info']['samples']:,} samples")
            print(f"📊 Features: {results['dataset_info']['features']:,}")
            print(f"📊 Fraud rate: {results['dataset_info']['fraud_rate']:.2%}")
            
            # Display model performance
            eval_results = results.get('evaluation_results', {})
            if eval_results:
                print("\n🏆 MODEL PERFORMANCE:")
                for model_name, metrics in eval_results.items():
                    if isinstance(metrics, dict) and 'accuracy' in metrics:
                        acc = metrics['accuracy']
                        f1 = metrics.get('f1_score', 0)
                        print(f"   {model_name}: {acc:.1%} accuracy, {f1:.3f} F1-score")
            
            print("\n📁 Output files created in:")
            print(f"   Models: ./models/")
            print(f"   Training data: ./data/training/")
            print(f"   Results: ./results/")
            
        else:
            print("\n❌ TRAINING FAILED")
            print("Please ensure datasets are downloaded and configured:")
            print("1. Kaggle: kaggle datasets download vagifa/ethereum-frauddetection-dataset")
            print("2. Elliptic++: https://github.com/git-disl/EllipticPlusPlus")
            print("3. HuggingFace: pip install datasets")
    
    except Exception as e:
        logger.error(f"Training failed: {e}")
        print(f"\n❌ Training failed: {e}")
        print("\nTroubleshooting:")
        print("1. Check your .env file has API keys configured")
        print("2. Ensure datasets are downloaded to ./data/ directory")
        print("3. Verify dependencies are installed: pip install -r requirements.txt")

if __name__ == "__main__":
    main()