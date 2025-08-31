#!/usr/bin/env python3
"""
Basic Setup Test - Test the enhanced intelligence pipeline without requiring
external API keys or datasets. Shows what's working and what needs configuration.
"""

import sys
import os
import traceback

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_imports():
    """Test that all our modules can be imported"""
    print("🔍 Testing module imports...")
    
    modules_to_test = [
        ('Base Data Collector', 'src.data_collector'),
        ('Config Manager', 'src.utils.config'),
        ('Logging Utils', 'src.utils.logging'),
        ('HIBP Client', 'src.collectors.hibp_client'),
        ('Shodan Client', 'src.collectors.shodan_client'),
        ('DeHashed Client', 'src.collectors.dehashed_client'),
        ('Elliptic++ Processor', 'src.collectors.elliptic_plus_processor'),
        ('Elliptic2 Processor', 'src.collectors.elliptic2_processor'),
    ]
    
    success_count = 0
    
    for name, module_path in modules_to_test:
        try:
            __import__(module_path)
            print(f"  ✅ {name}")
            success_count += 1
        except Exception as e:
            print(f"  ❌ {name}: {e}")
    
    print(f"\n📊 Import Success: {success_count}/{len(modules_to_test)} modules")
    return success_count == len(modules_to_test)

def test_basic_functionality():
    """Test basic functionality without external dependencies"""
    print("\n🔧 Testing basic functionality...")
    
    try:
        from src.utils.config import ConfigManager
        from src.utils.logging import setup_logging
        
        # Test config loading
        config_manager = ConfigManager()
        config = config_manager.load_config()
        print("  ✅ Configuration system working")
        
        # Test logging
        logger = setup_logging({"level": "INFO", "format": "simple"})
        logger.info("Test log message")
        print("  ✅ Logging system working")
        
        # Test that we can create collector instances (even if not configured)
        from src.collectors.hibp_client import HIBPClient
        from src.collectors.shodan_client import ShodanClient
        from src.collectors.dehashed_client import DeHashedClient
        
        hibp = HIBPClient(config, logger=logger)
        shodan = ShodanClient(config, logger=logger) 
        dehashed = DeHashedClient(config, logger=logger)
        
        print("  ✅ Data collectors can be instantiated")
        
        # Test configuration checking
        sources_available = []
        if hibp.api_key:
            sources_available.append('HIBP')
        if shodan.is_configured():
            sources_available.append('Shodan')
        if dehashed.is_configured():
            sources_available.append('DeHashed')
        
        print(f"  📊 Configured sources: {len(sources_available)} ({', '.join(sources_available) if sources_available else 'None'})")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Basic functionality test failed: {e}")
        traceback.print_exc()
        return False

def test_ml_components():
    """Test ML training components"""
    print("\n🤖 Testing ML components...")
    
    try:
        from src.ml.risk_scoring_engine import RiskScoringEngine
        from src.ml.feature_engineering import FeatureEngineer
        
        # Create instances
        config = {'risk_scoring': {'enabled': True}}
        risk_engine = RiskScoringEngine(config, None)
        feature_eng = FeatureEngineer(config, None)
        
        print("  ✅ Risk scoring engine can be created")
        print("  ✅ Feature engineering can be created")
        
        return True
        
    except Exception as e:
        print(f"  ❌ ML components test failed: {e}")
        return False

def test_dataset_processors():
    """Test dataset processors (without actual data)"""
    print("\n📊 Testing dataset processors...")
    
    try:
        from src.collectors.elliptic_plus_processor import EllipticPlusProcessor
        from src.collectors.elliptic2_processor import Elliptic2Processor
        
        config = {
            'elliptic_data_dir': './data/elliptic_plus',
            'elliptic2_data_dir': './data/elliptic2'
        }
        
        elliptic_plus = EllipticPlusProcessor(config, logger=None)
        elliptic2 = Elliptic2Processor(config, logger=None)
        
        print("  ✅ Elliptic++ processor can be created")
        print("  ✅ Elliptic2 processor can be created")
        
        # Test configuration checking
        print(f"  📊 Elliptic++ configured: {elliptic_plus.is_configured()}")
        print(f"  📊 Elliptic2 configured: {elliptic2.is_configured()}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Dataset processors test failed: {e}")
        traceback.print_exc()
        return False

def test_training_readiness():
    """Test if we're ready for training"""
    print("\n🚀 Testing training readiness...")
    
    # Check for training script
    training_script = './train_enhanced_models.py'
    if os.path.exists(training_script):
        print("  ✅ Training script available")
    else:
        print("  ❌ Training script missing")
    
    # Check directories
    required_dirs = ['./data', './models', './results', './cache']
    dirs_ok = True
    for dir_path in required_dirs:
        if os.path.exists(dir_path):
            print(f"  ✅ Directory exists: {dir_path}")
        else:
            print(f"  ❌ Directory missing: {dir_path}")
            dirs_ok = False
    
    # Check for datasets
    dataset_dirs = {
        'Ethereum': './data/ethereum',
        'Elliptic++': './data/elliptic_plus', 
        'Elliptic2': './data/elliptic2'
    }
    
    available_datasets = 0
    for name, path in dataset_dirs.items():
        if os.path.exists(path) and os.listdir(path):
            print(f"  ✅ {name} dataset directory has files")
            available_datasets += 1
        else:
            print(f"  ❌ {name} dataset not found")
    
    print(f"\n📊 Training readiness: {available_datasets}/{len(dataset_dirs)} datasets available")
    
    # Test dependencies
    try:
        import pandas, numpy, sklearn, xgboost, lightgbm
        print("  ✅ ML dependencies available")
    except ImportError as e:
        print(f"  ❌ Missing ML dependencies: {e}")
        return False
    
    return dirs_ok

def main():
    """Main test function"""
    print("🧪 BASIC SETUP AND FUNCTIONALITY TEST")
    print("=" * 50)
    print("Testing enhanced blockchain investigation AI setup")
    print("=" * 50)
    
    results = {
        'imports': test_imports(),
        'basic_functionality': test_basic_functionality(), 
        'ml_components': test_ml_components(),
        'dataset_processors': test_dataset_processors(),
        'training_readiness': test_training_readiness()
    }
    
    print("\n📋 TEST RESULTS SUMMARY")
    print("=" * 30)
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status} {test_name.replace('_', ' ').title()}")
    
    print(f"\n🏆 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 SYSTEM READY FOR ENHANCED TRAINING!")
        print("\n🚀 Next steps:")
        print("1. Configure API keys in .env file")
        print("2. Download datasets (see GitHub issues #47-49)")
        print("3. Run: python3 train_enhanced_models.py")
    else:
        print("\n⚠️  Some components need attention")
        print("Check the failures above and:")
        print("1. Install missing dependencies")
        print("2. Fix configuration issues") 
        print("3. Re-run this test")
    
    print(f"\n📁 Working directory: {os.getcwd()}")

if __name__ == "__main__":
    main()