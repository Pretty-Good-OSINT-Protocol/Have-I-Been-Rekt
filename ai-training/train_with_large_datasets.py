#!/usr/bin/env python3
"""
Enhanced ML Training Pipeline for Large Datasets - Memory-efficient training
with cloud storage integration and streaming data processing.
"""

import sys
import os
import json
import gc
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.utils.cloud_dataset_manager import CloudDatasetManager
from src.utils.config import ConfigManager
from src.utils.logging import setup_logging
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib


class LargeDatasetTrainer:
    """Enhanced trainer for large blockchain investigation datasets"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        
        # Initialize cloud dataset manager
        self.dataset_manager = CloudDatasetManager(config, logger=logger)
        
        # Training configuration
        self.batch_size = config.get('training_batch_size', 50000)
        self.max_memory_usage_gb = config.get('max_memory_usage_gb', 4)
        self.use_streaming = config.get('use_streaming_training', True)
        
        # Model storage
        self.models_dir = Path("./models")
        self.models_dir.mkdir(exist_ok=True)
        
        self.logger.info("Large dataset trainer initialized")
    
    def download_datasets_from_cloud(self) -> Dict[str, str]:
        """Download datasets from configured cloud locations"""
        
        cloud_urls = self.config.get('dataset_cloud_urls', {})
        downloaded_datasets = {}
        
        for dataset_name, cloud_url in cloud_urls.items():
            self.logger.info(f"Downloading {dataset_name} from cloud...")
            
            local_path = self.dataset_manager.download_dataset_from_cloud(
                cloud_url, 
                f"./data/{dataset_name}/{Path(cloud_url).name}"
            )
            
            if local_path:
                downloaded_datasets[dataset_name] = local_path
                self.logger.info(f"✅ {dataset_name} downloaded to {local_path}")
            else:
                self.logger.error(f"❌ Failed to download {dataset_name}")
        
        return downloaded_datasets
    
    def prepare_datasets_for_training(self, dataset_paths: Dict[str, str]) -> Dict[str, Any]:
        """Analyze and prepare datasets for efficient training"""
        
        dataset_info = {}
        
        for dataset_name, dataset_path in dataset_paths.items():
            self.logger.info(f"Analyzing {dataset_name}...")
            
            # Get dataset information
            info = self.dataset_manager.get_dataset_info(dataset_path)
            suggestions = self.dataset_manager.suggest_processing_strategy(dataset_path)
            
            dataset_info[dataset_name] = {
                'path': dataset_path,
                'info': info,
                'strategy': suggestions,
                'use_streaming': suggestions['memory_efficient']
            }
            
            self.logger.info(f"{dataset_name}: {info['size_gb']:.2f}GB, strategy: {suggestions['processing_strategy']}")
            
            # Optimize storage if recommended
            if suggestions.get('format_optimization_recommended'):
                self.logger.info(f"Optimizing storage for {dataset_name}...")
                optimization_result = self.dataset_manager.optimize_dataset_storage(dataset_path)
                
                if optimization_result['optimized_path'] != dataset_path:
                    dataset_info[dataset_name]['path'] = optimization_result['optimized_path']
                    self.logger.info(f"✅ Storage optimized: {optimization_result['compression_ratio']:.2f}x compression")
        
        return dataset_info
    
    def stream_unified_training_data(self, dataset_info: Dict[str, Any]) -> pd.DataFrame:
        """Create unified training dataset using streaming for memory efficiency"""
        
        self.logger.info("Creating unified training dataset with streaming...")
        
        # Process each dataset in chunks and combine
        unified_chunks = []
        total_samples = 0
        
        for dataset_name, info in dataset_info.items():
            dataset_path = info['path']
            use_streaming = info['use_streaming']
            
            self.logger.info(f"Processing {dataset_name} (streaming: {use_streaming})...")
            
            if use_streaming:
                # Stream large datasets
                chunk_count = 0
                for chunk in self.dataset_manager.stream_dataset(dataset_path):
                    # Process chunk for ML training
                    processed_chunk = self._process_chunk_for_ml(chunk, dataset_name)
                    if processed_chunk is not None and len(processed_chunk) > 0:
                        unified_chunks.append(processed_chunk)
                        total_samples += len(processed_chunk)
                        chunk_count += 1
                    
                    # Memory management
                    if chunk_count % 10 == 0:
                        gc.collect()
                        self.logger.debug(f"Processed {chunk_count} chunks from {dataset_name}")
                    
                    # Limit chunks for memory constraints
                    if len(unified_chunks) >= 100:  # Limit total chunks in memory
                        self.logger.info(f"Reached chunk limit for {dataset_name}, continuing with next dataset")
                        break
            
            else:
                # Load smaller datasets entirely
                try:
                    df = pd.read_csv(dataset_path)
                    processed_df = self._process_chunk_for_ml(df, dataset_name)
                    if processed_df is not None and len(processed_df) > 0:
                        unified_chunks.append(processed_df)
                        total_samples += len(processed_df)
                except Exception as e:
                    self.logger.error(f"Failed to load {dataset_name}: {e}")
        
        # Combine all chunks
        if unified_chunks:
            self.logger.info(f"Combining {len(unified_chunks)} chunks with {total_samples:,} total samples...")
            unified_dataset = pd.concat(unified_chunks, ignore_index=True)
            
            # Memory cleanup
            del unified_chunks
            gc.collect()
            
            self.logger.info(f"✅ Unified dataset created: {len(unified_dataset):,} samples, {unified_dataset.shape[1]} features")
            return unified_dataset
        else:
            self.logger.error("❌ No training data could be processed")
            return pd.DataFrame()
    
    def _process_chunk_for_ml(self, chunk: pd.DataFrame, dataset_source: str) -> Optional[pd.DataFrame]:
        """Process a data chunk for ML training"""
        
        try:
            # Dataset-specific processing
            if dataset_source == 'ethereum':
                return self._process_ethereum_chunk(chunk)
            elif dataset_source == 'elliptic_plus':
                return self._process_elliptic_plus_chunk(chunk)
            elif dataset_source == 'elliptic2':
                return self._process_elliptic2_chunk(chunk)
            else:
                # Generic processing
                return self._process_generic_chunk(chunk, dataset_source)
        
        except Exception as e:
            self.logger.warning(f"Failed to process chunk from {dataset_source}: {e}")
            return None
    
    def _process_ethereum_chunk(self, chunk: pd.DataFrame) -> Optional[pd.DataFrame]:
        """Process Ethereum fraud detection chunk"""
        
        # Look for fraud label column
        label_columns = ['FLAG', 'flag', 'is_fraud', 'fraud']
        label_col = None
        
        for col in label_columns:
            if col in chunk.columns:
                label_col = col
                break
        
        if label_col is None:
            return None
        
        # Prepare features and labels
        features = chunk.select_dtypes(include=[np.number]).copy()
        features = features.drop(columns=[label_col], errors='ignore')
        
        # Add metadata
        processed_chunk = features.copy()
        processed_chunk['is_fraud'] = chunk[label_col].astype(bool)
        processed_chunk['source'] = 'ethereum'
        processed_chunk['confidence'] = 1.0
        
        # Handle missing values
        processed_chunk = processed_chunk.fillna(0)
        
        return processed_chunk
    
    def _process_elliptic_plus_chunk(self, chunk: pd.DataFrame) -> Optional[pd.DataFrame]:
        """Process Elliptic++ chunk"""
        
        # Handle both transaction and address data
        if 'txId' in chunk.columns:
            # Transaction data
            if 'class' not in chunk.columns:
                return None
            
            # Filter out unknown labels for training
            chunk = chunk[chunk['class'].isin([1, 2])]  # 1=illicit, 2=licit
            
            if len(chunk) == 0:
                return None
            
            # Prepare features
            feature_cols = [col for col in chunk.columns 
                           if col not in ['txId', 'class', 'time_step']]
            
            processed_chunk = chunk[feature_cols].copy()
            processed_chunk['is_fraud'] = (chunk['class'] == 1).astype(bool)
            processed_chunk['source'] = 'elliptic_plus_tx'
            processed_chunk['confidence'] = 1.0
            
        elif 'address' in chunk.columns:
            # Address data
            if 'class' not in chunk.columns:
                return None
            
            chunk = chunk[chunk['class'].isin([1, 2])]
            
            if len(chunk) == 0:
                return None
            
            feature_cols = [col for col in chunk.columns 
                           if col not in ['address', 'class', 'time_step']]
            
            processed_chunk = chunk[feature_cols].copy()
            processed_chunk['is_fraud'] = (chunk['class'] == 1).astype(bool)
            processed_chunk['source'] = 'elliptic_plus_addr'
            processed_chunk['confidence'] = 1.0
        
        else:
            return None
        
        # Handle missing values
        processed_chunk = processed_chunk.fillna(0)
        
        return processed_chunk
    
    def _process_elliptic2_chunk(self, chunk: pd.DataFrame) -> Optional[pd.DataFrame]:
        """Process Elliptic2 money laundering chunk"""
        
        # This would need specific logic based on Elliptic2 format
        # For now, return None (placeholder)
        return None
    
    def _process_generic_chunk(self, chunk: pd.DataFrame, source: str) -> Optional[pd.DataFrame]:
        """Generic chunk processing"""
        
        # Look for common fraud indicators
        fraud_columns = ['is_fraud', 'fraud', 'malicious', 'label']
        
        label_col = None
        for col in fraud_columns:
            if col in chunk.columns:
                label_col = col
                break
        
        if label_col is None:
            return None
        
        # Select numeric features
        features = chunk.select_dtypes(include=[np.number]).copy()
        features = features.drop(columns=[label_col], errors='ignore')
        
        processed_chunk = features.copy()
        processed_chunk['is_fraud'] = chunk[label_col].astype(bool)
        processed_chunk['source'] = source
        processed_chunk['confidence'] = 0.8  # Lower confidence for generic processing
        
        processed_chunk = processed_chunk.fillna(0)
        
        return processed_chunk
    
    def train_models_incrementally(self, dataset: pd.DataFrame) -> Dict[str, Any]:
        """Train models using incremental learning for large datasets"""
        
        if dataset.empty:
            return {}
        
        self.logger.info(f"Starting incremental training on {len(dataset):,} samples...")
        
        # Separate features and labels
        feature_columns = [col for col in dataset.columns 
                          if col not in ['is_fraud', 'source', 'confidence']]
        
        X = dataset[feature_columns]
        y = dataset['is_fraud']
        
        self.logger.info(f"Feature matrix: {X.shape}")
        self.logger.info(f"Class distribution: {y.value_counts().to_dict()}")
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train models using incremental algorithms
        models = self._train_incremental_models(X_train, y_train, X_test, y_test)
        
        # Save models and scaler
        self._save_models_and_scaler(models, scaler, feature_columns)
        
        return {
            'models': models,
            'scaler': scaler,
            'feature_columns': feature_columns,
            'dataset_info': {
                'samples': len(dataset),
                'features': len(feature_columns),
                'fraud_rate': y.mean()
            }
        }
    
    def _train_incremental_models(self, X_train, y_train, X_test, y_test) -> Dict[str, Any]:
        """Train models that support incremental learning"""
        
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import SGDClassifier
        from sklearn.naive_bayes import MultinomialNB
        
        models = {}
        
        # Models that can handle large datasets efficiently
        model_configs = {
            'sgd_classifier': SGDClassifier(random_state=42, max_iter=1000),
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        }
        
        for model_name, model in model_configs.items():
            try:
                self.logger.info(f"Training {model_name}...")
                
                # Train model
                model.fit(X_train, y_train)
                
                # Evaluate
                train_score = model.score(X_train, y_train)
                test_score = model.score(X_test, y_test)
                
                models[model_name] = {
                    'model': model,
                    'train_accuracy': train_score,
                    'test_accuracy': test_score
                }
                
                self.logger.info(f"✅ {model_name}: train={train_score:.3f}, test={test_score:.3f}")
                
            except Exception as e:
                self.logger.error(f"❌ {model_name} training failed: {e}")
        
        return models
    
    def _save_models_and_scaler(self, models: Dict[str, Any], scaler, feature_columns: List[str]):
        """Save trained models and preprocessing objects"""
        
        timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
        
        # Save scaler
        scaler_path = self.models_dir / f"scaler_{timestamp}.pkl"
        joblib.dump(scaler, scaler_path)
        
        # Save feature columns
        features_path = self.models_dir / f"features_{timestamp}.json"
        with open(features_path, 'w') as f:
            json.dump(feature_columns, f)
        
        # Save models
        for model_name, model_info in models.items():
            model_path = self.models_dir / f"{model_name}_{timestamp}.pkl"
            joblib.dump(model_info['model'], model_path)
            
            self.logger.info(f"💾 Saved {model_name} to {model_path}")
        
        # Save metadata
        metadata = {
            'timestamp': timestamp,
            'models': {name: info['test_accuracy'] for name, info in models.items()},
            'scaler_path': str(scaler_path),
            'features_path': str(features_path),
            'feature_count': len(feature_columns)
        }
        
        metadata_path = self.models_dir / f"training_metadata_{timestamp}.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"💾 Training metadata saved to {metadata_path}")


def main():
    """Main function for large dataset training"""
    
    print("🚀 LARGE DATASET ML TRAINING PIPELINE")
    print("=" * 60)
    print("Memory-efficient training with cloud storage integration")
    print("=" * 60)
    
    # Setup
    logger = setup_logging(log_level="INFO")
    
    # Configuration
    config_manager = ConfigManager()
    config = config_manager.load_config()
    
    # Add large dataset specific configuration
    config.update({
        'training_batch_size': 50000,
        'max_memory_usage_gb': 4,
        'use_streaming_training': True,
        
        # Cloud dataset URLs (examples)
        'dataset_cloud_urls': {
            # Add your cloud URLs here
            # 'ethereum': 's3://your-bucket/ethereum_fraud.csv.gz',
            # 'elliptic_plus': 'https://your-domain/elliptic_plus.parquet.gz'
        }
    })
    
    # Initialize trainer
    trainer = LargeDatasetTrainer(config, logger)
    
    try:
        # Step 1: Download datasets from cloud (if configured)
        downloaded_datasets = trainer.download_datasets_from_cloud()
        
        # Step 2: Check for local datasets
        local_datasets = {}
        dataset_dirs = ['./data/ethereum', './data/elliptic_plus', './data/elliptic2']
        
        for data_dir in dataset_dirs:
            data_path = Path(data_dir)
            if data_path.exists():
                csv_files = list(data_path.glob('*.csv'))
                if csv_files:
                    dataset_name = data_path.name
                    local_datasets[dataset_name] = str(csv_files[0])  # Use first CSV file
        
        # Combine all available datasets
        all_datasets = {**downloaded_datasets, **local_datasets}
        
        if not all_datasets:
            print("❌ No datasets found!")
            print("Options:")
            print("1. Download datasets to ./data/ directories")
            print("2. Configure cloud URLs in config")
            print("3. Use the manage_large_datasets.py tool")
            return
        
        print(f"📊 Found {len(all_datasets)} datasets: {list(all_datasets.keys())}")
        
        # Step 3: Prepare datasets for training
        dataset_info = trainer.prepare_datasets_for_training(all_datasets)
        
        # Step 4: Create unified training dataset with streaming
        unified_dataset = trainer.stream_unified_training_data(dataset_info)
        
        if unified_dataset.empty:
            print("❌ No training data could be prepared")
            return
        
        # Step 5: Train models incrementally
        training_results = trainer.train_models_incrementally(unified_dataset)
        
        if training_results:
            print(f"\n🎉 TRAINING COMPLETED SUCCESSFULLY!")
            print(f"📊 Dataset: {training_results['dataset_info']['samples']:,} samples")
            print(f"📊 Features: {training_results['dataset_info']['features']}")
            print(f"📊 Fraud rate: {training_results['dataset_info']['fraud_rate']:.2%}")
            
            print(f"\n🏆 MODEL PERFORMANCE:")
            for model_name, model_info in training_results['models'].items():
                print(f"   {model_name}: {model_info['test_accuracy']:.1%} accuracy")
            
            print(f"\n📁 Models saved to: ./models/")
        
    except Exception as e:
        logger.exception("Training failed")
        print(f"❌ Training failed: {e}")


if __name__ == "__main__":
    main()