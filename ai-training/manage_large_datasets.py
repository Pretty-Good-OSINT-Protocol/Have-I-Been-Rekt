#!/usr/bin/env python3
"""
Large Dataset Management Tool - Handle massive blockchain investigation datasets
efficiently with cloud storage, streaming, and intelligent processing strategies.
"""

import sys
import os
import json
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.utils.cloud_dataset_manager import CloudDatasetManager, create_cloud_config_template
from src.utils.logging import setup_logging


def analyze_dataset(manager: CloudDatasetManager, dataset_path: str):
    """Analyze dataset and suggest optimal processing strategy"""
    print(f"📊 Analyzing dataset: {dataset_path}")
    print("-" * 50)
    
    # Get dataset info
    info = manager.get_dataset_info(dataset_path)
    
    if not info.get('exists'):
        print("❌ Dataset file not found")
        return
    
    # Display basic info
    print(f"📁 File size: {info['size_gb']:.2f} GB ({info['size_mb']:.1f} MB)")
    print(f"📅 Modified: {info['modified_time']}")
    print(f"📋 Format: {info['format']}")
    print(f"🗜️  Compressed: {'Yes' if info.get('compressed') else 'No'}")
    
    if info.get('columns'):
        print(f"📊 Columns: {info['columns']}")
        if info.get('estimated_rows'):
            print(f"📊 Estimated rows: {info['estimated_rows']:,}")
    
    # Get processing suggestions
    suggestions = manager.suggest_processing_strategy(dataset_path)
    
    print(f"\n🎯 RECOMMENDED PROCESSING STRATEGY")
    print("-" * 40)
    print(f"Strategy: {suggestions['processing_strategy'].upper()}")
    print(f"Memory efficient: {'Yes' if suggestions['memory_efficient'] else 'No'}")
    print(f"Chunk size: {suggestions['recommended_chunk_size']:,} rows")
    
    if suggestions['cloud_storage_recommended']:
        print("☁️  Cloud storage recommended for this dataset size")
    
    if suggestions['format_optimization_recommended']:
        print("⚡ Format optimization recommended (CSV → Parquet)")
    
    print("\nRationale:")
    for reason in suggestions['rationale']:
        print(f"  • {reason}")


def upload_to_cloud(manager: CloudDatasetManager, dataset_path: str, 
                   cloud_provider: str, bucket: str, key: str):
    """Upload dataset to cloud storage"""
    print(f"☁️  Uploading to {cloud_provider.upper()}: {bucket}/{key}")
    print("-" * 50)
    
    success = manager.upload_dataset_to_cloud(dataset_path, cloud_provider, bucket, key)
    
    if success:
        print("✅ Upload completed successfully!")
        print(f"📍 Location: {cloud_provider}://{bucket}/{key}")
    else:
        print("❌ Upload failed - check credentials and configuration")


def download_from_cloud(manager: CloudDatasetManager, cloud_url: str, local_path: str = None):
    """Download dataset from cloud storage"""
    print(f"📥 Downloading from cloud: {cloud_url}")
    print("-" * 50)
    
    result_path = manager.download_dataset_from_cloud(cloud_url, local_path)
    
    if result_path:
        print(f"✅ Download completed: {result_path}")
        
        # Analyze downloaded dataset
        print("\n" + "="*50)
        analyze_dataset(manager, result_path)
    else:
        print("❌ Download failed")


def optimize_dataset(manager: CloudDatasetManager, dataset_path: str):
    """Optimize dataset storage format and compression"""
    print(f"⚡ Optimizing dataset: {dataset_path}")
    print("-" * 50)
    
    results = manager.optimize_dataset_storage(dataset_path)
    
    print(f"📊 OPTIMIZATION RESULTS:")
    print(f"Original size: {results['original_size']/(1024**3):.2f} GB")
    print(f"Optimized size: {results['final_size']/(1024**3):.2f} GB")
    print(f"Compression ratio: {results['compression_ratio']:.2f}x")
    print(f"Space saved: {(results['original_size']-results['final_size'])/(1024**3):.2f} GB")
    print(f"Optimizations applied: {', '.join(results['optimizations_applied'])}")
    print(f"Optimized file: {results['optimized_path']}")


def stream_dataset_demo(manager: CloudDatasetManager, dataset_path: str, max_chunks: int = 3):
    """Demonstrate streaming dataset processing"""
    print(f"🌊 Streaming dataset demo: {dataset_path}")
    print("-" * 50)
    
    try:
        chunk_count = 0
        total_rows = 0
        
        for chunk in manager.stream_dataset(dataset_path):
            chunk_count += 1
            total_rows += len(chunk)
            
            print(f"Chunk {chunk_count}: {len(chunk)} rows, {chunk.shape[1]} columns")
            print(f"  Memory usage: ~{chunk.memory_usage(deep=True).sum()/(1024**2):.1f} MB")
            
            # Show sample of first chunk
            if chunk_count == 1:
                print("  Sample data:")
                print(chunk.head(3).to_string(max_cols=5))
            
            if chunk_count >= max_chunks:
                print(f"  ... (stopping demo after {max_chunks} chunks)")
                break
        
        print(f"\n📊 Streaming summary: {chunk_count} chunks, {total_rows:,} total rows processed")
        print("✅ Streaming completed successfully!")
        
    except Exception as e:
        print(f"❌ Streaming failed: {e}")


def setup_cloud_config():
    """Setup cloud storage configuration"""
    print("🔧 Setting up cloud storage configuration")
    print("-" * 50)
    
    config_file = Path("./cloud_config.json")
    
    if config_file.exists():
        print("⚠️  Cloud config already exists. Overwrite? (y/N): ", end="")
        response = input().lower()
        if response != 'y':
            print("Configuration setup cancelled.")
            return
    
    # Create template config
    config = create_cloud_config_template()
    
    print("📝 Creating cloud configuration template...")
    
    # Save template
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"✅ Cloud configuration template created: {config_file}")
    print("\n🔧 Next steps:")
    print(f"1. Edit {config_file} with your actual credentials")
    print("2. Uncomment and configure your preferred cloud provider")
    print("3. Run this script again with cloud operations")
    
    print(f"\n📋 Configuration file preview:")
    print("-" * 30)
    with open(config_file, 'r') as f:
        lines = f.readlines()
        for i, line in enumerate(lines[:15]):  # Show first 15 lines
            print(f"{i+1:2d}: {line.rstrip()}")
        if len(lines) > 15:
            print(f"... ({len(lines)-15} more lines)")


def main():
    """Main function with CLI interface"""
    parser = argparse.ArgumentParser(
        description="Large Dataset Management Tool for Blockchain Investigation AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # analyze a dataset
  python manage_large_datasets.py analyze data/ethereum/fraud_dataset.csv
  
  # setup cloud configuration  
  python manage_large_datasets.py setup-cloud
  
  # optimize dataset storage
  python manage_large_datasets.py optimize data/ethereum/large_dataset.csv
  
  # upload to cloud
  python manage_large_datasets.py upload data/dataset.csv aws my-bucket dataset.csv
  
  # download from cloud
  python manage_large_datasets.py download s3://my-bucket/dataset.csv
  
  # stream dataset demo
  python manage_large_datasets.py stream data/dataset.csv
        """
    )
    
    parser.add_argument('action', choices=[
        'analyze', 'upload', 'download', 'optimize', 'stream', 'setup-cloud'
    ], help='Action to perform')
    
    parser.add_argument('dataset_path', nargs='?', help='Path to dataset file')
    parser.add_argument('cloud_provider', nargs='?', help='Cloud provider (aws/gcp/azure)')
    parser.add_argument('bucket', nargs='?', help='Bucket/container name')  
    parser.add_argument('key', nargs='?', help='Object key/blob name')
    
    parser.add_argument('--config', default='./cloud_config.json', 
                       help='Cloud configuration file')
    parser.add_argument('--chunk-size', type=int, default=10000,
                       help='Chunk size for streaming')
    parser.add_argument('--max-memory', type=int, default=4,
                       help='Maximum memory usage in GB')
    
    args = parser.parse_args()
    
    print("🚀 LARGE DATASET MANAGEMENT TOOL")
    print("=" * 60)
    print("Efficient handling of massive blockchain investigation datasets")
    print("=" * 60)
    
    # Setup cloud config first if needed
    if args.action == 'setup-cloud':
        setup_cloud_config()
        return
    
    # Load configuration
    config_file = Path(args.config)
    if config_file.exists():
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        print(f"⚠️  Cloud config not found: {config_file}")
        print("Run: python manage_large_datasets.py setup-cloud")
        config = {}
    
    # Update config with CLI args
    config.update({
        'chunk_size_rows': args.chunk_size,
        'max_memory_usage_gb': args.max_memory
    })
    
    # Initialize manager
    logger = setup_logging({"level": "INFO", "format": "simple"})
    manager = CloudDatasetManager(config, logger=logger)
    
    # Execute requested action
    try:
        if args.action == 'analyze':
            if not args.dataset_path:
                print("❌ Dataset path required for analyze action")
                return
            analyze_dataset(manager, args.dataset_path)
        
        elif args.action == 'upload':
            if not all([args.dataset_path, args.cloud_provider, args.bucket, args.key]):
                print("❌ Required: dataset_path cloud_provider bucket key")
                return
            upload_to_cloud(manager, args.dataset_path, args.cloud_provider, args.bucket, args.key)
        
        elif args.action == 'download':
            if not args.dataset_path:
                print("❌ Cloud URL required for download action")
                return
            download_from_cloud(manager, args.dataset_path)
        
        elif args.action == 'optimize':
            if not args.dataset_path:
                print("❌ Dataset path required for optimize action")
                return
            optimize_dataset(manager, args.dataset_path)
        
        elif args.action == 'stream':
            if not args.dataset_path:
                print("❌ Dataset path required for stream action")
                return
            stream_dataset_demo(manager, args.dataset_path)
    
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        logger.exception("Operation failed")


if __name__ == "__main__":
    main()