#!/usr/bin/env python3
"""
Training Setup Script - Automated setup for enhanced blockchain investigation
AI training with Ethereum prioritization.
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def check_dependencies():
    """Check and install required dependencies"""
    print("📦 Checking dependencies...")
    
    required_packages = [
        'pandas',
        'numpy', 
        'scikit-learn',
        'matplotlib',
        'seaborn',
        'plotly',
        'shap',
        'imbalanced-learn',
        'xgboost',
        'lightgbm',
        'datasets',  # For HuggingFace
        'kaggle',    # For Kaggle datasets
        'web3',      # For Ethereum analysis
        'networkx'   # For graph analysis
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"  ✅ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"  ❌ {package}")
    
    if missing_packages:
        print(f"\n📥 Installing {len(missing_packages)} missing packages...")
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install'
            ] + missing_packages)
            print("✅ Dependencies installed successfully!")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            return False
    
    return True

def setup_directories():
    """Create necessary directories"""
    print("\n📁 Setting up directories...")
    
    directories = [
        Path("./data"),
        Path("./data/ethereum"),
        Path("./data/elliptic_plus"), 
        Path("./data/elliptic2"),
        Path("./data/huggingface"),
        Path("./data/training"),
        Path("./models"),
        Path("./results"),
        Path("./cache"),
        Path("./logs")
    ]
    
    for directory in directories:
        directory.mkdir(exist_ok=True, parents=True)
        print(f"  ✅ {directory}")
    
    return True

def check_env_file():
    """Check and create .env file if needed"""
    print("\n🔧 Checking environment configuration...")
    
    env_file = Path("./.env")
    example_env = Path("./.env.example")
    
    if not env_file.exists():
        if example_env.exists():
            print("  📝 Creating .env file from template...")
            import shutil
            shutil.copy2(example_env, env_file)
            print("  ✅ .env file created")
            print("  ⚠️  Please edit .env file and add your API keys")
        else:
            print("  ❌ No .env.example file found")
            return False
    else:
        print("  ✅ .env file exists")
    
    # Check for key configurations
    try:
        with open(env_file, 'r') as f:
            env_content = f.read()
        
        api_keys_to_check = [
            'HIBP_API_KEY',
            'VIRUSTOTAL_API_KEY', 
            'SHODAN_API_KEY',
            'DEHASHED_API_KEY'
        ]
        
        configured_keys = []
        for key in api_keys_to_check:
            if f"{key}=" in env_content and "your_" not in env_content.split(f"{key}=")[1].split('\n')[0]:
                configured_keys.append(key)
        
        if configured_keys:
            print(f"  ✅ {len(configured_keys)}/{len(api_keys_to_check)} API keys configured")
        else:
            print("  ⚠️  No API keys configured yet")
    
    except Exception as e:
        print(f"  ❌ Error checking .env file: {e}")
    
    return True

def check_datasets():
    """Check for available datasets"""
    print("\n📊 Checking dataset availability...")
    
    dataset_status = {}
    
    # Check Ethereum fraud dataset
    ethereum_files = list(Path("./data/ethereum").glob("*.csv"))
    if ethereum_files:
        dataset_status['ethereum'] = True
        print(f"  ✅ Ethereum fraud dataset: {len(ethereum_files)} files")
    else:
        dataset_status['ethereum'] = False
        print("  ❌ Ethereum fraud dataset not found")
    
    # Check Elliptic++ dataset
    elliptic_plus_files = list(Path("./data/elliptic_plus").glob("*.csv"))
    if elliptic_plus_files:
        dataset_status['elliptic_plus'] = True
        print(f"  ✅ Elliptic++ dataset: {len(elliptic_plus_files)} files")
    else:
        dataset_status['elliptic_plus'] = False
        print("  ❌ Elliptic++ dataset not found")
    
    # Check Elliptic2 dataset
    elliptic2_files = list(Path("./data/elliptic2").glob("*.csv"))
    if elliptic2_files:
        dataset_status['elliptic2'] = True
        print(f"  ✅ Elliptic2 dataset: {len(elliptic2_files)} files")
    else:
        dataset_status['elliptic2'] = False
        print("  ❌ Elliptic2 dataset not found")
    
    # Check HuggingFace datasets availability
    try:
        import datasets
        dataset_status['huggingface'] = True
        print("  ✅ HuggingFace datasets library available")
    except ImportError:
        dataset_status['huggingface'] = False
        print("  ❌ HuggingFace datasets library not available")
    
    return dataset_status

def show_download_instructions():
    """Show dataset download instructions"""
    print("\n📥 DATASET DOWNLOAD INSTRUCTIONS")
    print("=" * 50)
    
    print("\n🔷 ETHEREUM FRAUD DATASET (Kaggle):")
    print("1. Install Kaggle CLI: pip install kaggle")
    print("2. Setup Kaggle API token: ~/.kaggle/kaggle.json")
    print("3. Download: kaggle datasets download vagifa/ethereum-frauddetection-dataset")
    print("4. Extract to: ./data/ethereum/")
    
    print("\n🎯 ELLIPTIC++ DATASET:")
    print("1. Visit: https://github.com/git-disl/EllipticPlusPlus")
    print("2. Download dataset files")
    print("3. Extract to: ./data/elliptic_plus/")
    print("   Required files:")
    print("   - txs_features.csv")
    print("   - txs_classes.csv")
    print("   - txs_edgelist.csv")
    print("   - wallets_features.csv")
    print("   - wallets_classes.csv")
    
    print("\n🏦 ELLIPTIC2 DATASET:")
    print("1. Visit: http://elliptic.co/elliptic2")
    print("2. Download dataset files")
    print("3. Extract to: ./data/elliptic2/")
    print("   Required files:")
    print("   - nodes.csv")
    print("   - edges.csv")
    print("   - background_nodes.csv")
    print("   - background_edges.csv")
    
    print("\n🤗 HUGGINGFACE DATASETS:")
    print("1. Install: pip install datasets")
    print("2. Datasets will auto-download during training")

def main():
    """Main setup function"""
    print("🚀 BLOCKCHAIN INVESTIGATION AI - TRAINING SETUP")
    print("=" * 60)
    
    success = True
    
    # Check dependencies
    if not check_dependencies():
        success = False
    
    # Setup directories
    if not setup_directories():
        success = False
    
    # Check environment
    if not check_env_file():
        success = False
    
    # Check datasets
    dataset_status = check_datasets()
    
    # Show results
    print("\n📋 SETUP SUMMARY")
    print("=" * 30)
    
    if success:
        print("✅ Basic setup completed successfully!")
        
        available_datasets = sum(dataset_status.values())
        total_datasets = len(dataset_status)
        
        print(f"📊 Datasets: {available_datasets}/{total_datasets} available")
        
        if available_datasets > 0:
            print("\n🚀 READY TO START TRAINING!")
            print("Run: python train_enhanced_models.py")
        else:
            print("\n📥 Download datasets first:")
            show_download_instructions()
    else:
        print("❌ Setup encountered errors")
    
    print(f"\n📁 Working directory: {os.getcwd()}")
    print("\n🔧 Next steps:")
    print("1. Configure API keys in .env file")
    print("2. Download required datasets")
    print("3. Run: python train_enhanced_models.py")

if __name__ == "__main__":
    main()