#!/usr/bin/env python3
"""
Colab Setup Script for Comprehensive Threat Intelligence Training
Run this in your first Colab cell to set everything up quickly
"""

# 🚀 COLAB SETUP SCRIPT - Run this first!
print("🚀 SETTING UP COMPREHENSIVE THREAT INTELLIGENCE TRAINING")
print("=" * 60)

# 1. Clone your repo (if not already done)
import os
import subprocess

def setup_github_repo():
    """Setup GitHub repo in Colab"""
    if not os.path.exists('/content/Have-I-Been-Rekt'):
        print("📥 Cloning Have-I-Been-Rekt repository...")
        subprocess.run(['git', 'clone', 'https://github.com/Pretty-Good-OSINT-Protocol/Have-I-Been-Rekt.git'], 
                      cwd='/content', check=True)
        print("✅ Repository cloned successfully")
    else:
        print("✅ Repository already available")
    
    # Change to the repo directory
    os.chdir('/content/Have-I-Been-Rekt')
    print(f"📁 Working directory: {os.getcwd()}")

setup_github_repo()

# 2. Install dependencies quickly
print("\n📦 Installing dependencies...")
subprocess.run(['pip', 'install', '-q', 'transformers', 'torch', 'datasets', 'accelerate', 'evaluate'], check=True)
subprocess.run(['pip', 'install', '-q', 'scikit-learn', 'pandas', 'numpy', 'matplotlib', 'seaborn'], check=True)
subprocess.run(['pip', 'install', '-q', 'web3', 'eth-utils', 'aiohttp', 'python-dotenv'], check=True)
print("✅ All dependencies installed")

# 3. Create datasets directory and check for existing data
os.makedirs('/content/datasets', exist_ok=True)
os.makedirs('/content/models', exist_ok=True)

print("\n📊 Checking for existing datasets...")
ai_training_dir = '/content/Have-I-Been-Rekt/ai-training'

# Check what datasets we have
existing_files = []
if os.path.exists(f"{ai_training_dir}/datasets"):
    for file in os.listdir(f"{ai_training_dir}/datasets"):
        if file.endswith(('.json', '.csv')):
            existing_files.append(file)
            # Copy to working datasets directory
            subprocess.run(['cp', f"{ai_training_dir}/datasets/{file}", '/content/datasets/'], check=True)

print(f"✅ Found {len(existing_files)} existing dataset files:")
for file in existing_files:
    print(f"   - {file}")

# 4. Run threat intelligence collector to generate fresh data
print("\n🔍 Generating fresh threat intelligence data...")
try:
    if os.path.exists(f"{ai_training_dir}/collect_comprehensive_intelligence.py"):
        result = subprocess.run(['python3', f"{ai_training_dir}/collect_comprehensive_intelligence.py"], 
                              capture_output=True, text=True, cwd=ai_training_dir)
        if result.returncode == 0:
            print("✅ Fresh threat intelligence data generated")
            # Copy new datasets
            if os.path.exists(f"{ai_training_dir}/datasets"):
                subprocess.run(['cp', '-r', f"{ai_training_dir}/datasets/.", '/content/datasets/'], check=True)
        else:
            print(f"⚠️ Data generation had issues: {result.stderr}")
    else:
        print("⚠️ Threat intelligence collector not found")
except Exception as e:
    print(f"⚠️ Error running data collector: {e}")

# 5. Check final dataset status
print("\n📊 FINAL DATASET STATUS:")
if os.path.exists('/content/datasets'):
    dataset_files = os.listdir('/content/datasets')
    total_size = 0
    for file in dataset_files:
        file_path = f"/content/datasets/{file}"
        if os.path.isfile(file_path):
            size = os.path.getsize(file_path)
            total_size += size
            print(f"   ✅ {file} ({size:,} bytes)")
    
    print(f"\n📊 Total dataset size: {total_size:,} bytes ({total_size/1024/1024:.2f} MB)")
else:
    print("❌ No datasets directory found")

# 6. GPU Check
print("\n🔥 GPU STATUS:")
try:
    import torch
    if torch.cuda.is_available():
        gpu_name = torch.cuda.get_device_name(0)
        gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1024**3
        print(f"   ✅ GPU Available: {gpu_name}")
        print(f"   💾 GPU Memory: {gpu_memory:.1f} GB")
        print("   🚀 Ready for overnight training!")
    else:
        print("   ⚠️ No GPU detected - training will be slower on CPU")
except Exception as e:
    print(f"   ❌ GPU check failed: {e}")

print("\n" + "=" * 60)
print("🎯 SETUP COMPLETE!")
print("=" * 60)
print("📋 NEXT STEPS:")
print("1. Open the Comprehensive_Threat_Intelligence_Training.ipynb notebook")
print("2. Run each cell in order")
print("3. Upload any additional datasets when prompted")
print("4. Start the overnight training run")
print("5. Check back in the morning for results!")
print("\n🌙 Perfect for overnight training on your 6-year-old video editing box!")
print("✅ Ready to make this REAL!")