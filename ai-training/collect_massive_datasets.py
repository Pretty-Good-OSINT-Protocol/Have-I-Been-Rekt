#!/usr/bin/env python3
"""
MASSIVE Threat Intelligence Dataset Collection
Collects gigabytes of real threat intelligence from all available sources
"""

import asyncio
import os
import sys
import json
import pandas as pd
from pathlib import Path
from datetime import datetime
import logging
from typing import Dict, List, Any
import time

# Import all data collectors
sys.path.append('./src')

from collectors.elliptic_dataset_processor import EllipticDatasetProcessor
from collectors.ethereum_dataset_processor import EthereumDatasetProcessor
from collectors.historical_crime_aggregator import HistoricalCrimeAggregator
from collectors.chainalysis_client import ChainalysisClient
from collectors.hibp_client import HIBPClient
from collectors.cryptoscamdb_collector import CryptoScamDBCollector
from collectors.ransomwhere_processor import RansomwhereProcessor
from collectors.community_scam_aggregator import CommunityScamAggregator
from collectors.chainabuse_scraper import ChainAbuseScraper

class MassiveDatasetCollector:
    """Collects massive threat intelligence datasets from all sources"""
    
    def __init__(self):
        self.datasets = {}
        self.total_records = 0
        self.start_time = time.time()
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        print("🚀 MASSIVE THREAT INTELLIGENCE DATASET COLLECTION")
        print("=" * 60)
        print("Collecting GIGABYTES of real threat intelligence data...")
        print("Sources: Elliptic, Ethereum, HIBP, Ransomware, Scam DBs")
        print("=" * 60)

    async def collect_all_datasets(self):
        """Collect all available massive datasets"""
        
        # 1. Elliptic Bitcoin Dataset (203k+ labeled transactions)
        print("\n📊 1. Elliptic Bitcoin Dataset (203k+ transactions)")
        try:
            elliptic_processor = EllipticDatasetProcessor()
            elliptic_data = await elliptic_processor.collect_all_data()
            self.datasets['elliptic_bitcoin'] = elliptic_data
            print(f"   ✅ Collected {len(elliptic_data)} Elliptic Bitcoin records")
        except Exception as e:
            print(f"   ⚠️ Elliptic collection failed: {e}")
            self.datasets['elliptic_bitcoin'] = []
        
        # 2. Ethereum Fraud Detection Dataset (Millions of transactions)
        print("\n📊 2. Ethereum Fraud Detection Dataset")
        try:
            ethereum_processor = EthereumDatasetProcessor()
            ethereum_data = await ethereum_processor.collect_ethereum_fraud_data()
            self.datasets['ethereum_fraud'] = ethereum_data
            print(f"   ✅ Collected {len(ethereum_data)} Ethereum fraud records")
        except Exception as e:
            print(f"   ⚠️ Ethereum collection failed: {e}")
            self.datasets['ethereum_fraud'] = []
        
        # 3. Historical Crime Aggregation (HIBP + Ransomware + More)
        print("\n📊 3. Historical Crime Intelligence")
        try:
            crime_aggregator = HistoricalCrimeAggregator()
            crime_data = await crime_aggregator.aggregate_all_sources()
            self.datasets['historical_crime'] = crime_data
            print(f"   ✅ Collected {len(crime_data)} historical crime records")
        except Exception as e:
            print(f"   ⚠️ Crime data collection failed: {e}")
            self.datasets['historical_crime'] = []
        
        # 4. CryptoScamDB (Comprehensive scam database)
        print("\n📊 4. CryptoScamDB Comprehensive Database")
        try:
            scamdb_collector = CryptoScamDBCollector()
            scamdb_data = await scamdb_collector.collect_all_scams()
            self.datasets['crypto_scamdb'] = scamdb_data
            print(f"   ✅ Collected {len(scamdb_data)} CryptoScamDB records")
        except Exception as e:
            print(f"   ⚠️ CryptoScamDB collection failed: {e}")
            self.datasets['crypto_scamdb'] = []
        
        # 5. Ransomwhere Payment Tracking (10k+ ransomware addresses)
        print("\n📊 5. Ransomwhere Payment Database")
        try:
            ransom_processor = RansomwhereProcessor()
            ransom_data = await ransom_processor.collect_all_ransomware_data()
            self.datasets['ransomware_payments'] = ransom_data
            print(f"   ✅ Collected {len(ransom_data)} ransomware payment records")
        except Exception as e:
            print(f"   ⚠️ Ransomware collection failed: {e}")
            self.datasets['ransomware_payments'] = []
        
        # 6. Community Scam Aggregation (Multiple sources)
        print("\n📊 6. Community Scam Reports")
        try:
            community_aggregator = CommunityScamAggregator()
            community_data = await community_aggregator.collect_community_reports()
            self.datasets['community_scams'] = community_data
            print(f"   ✅ Collected {len(community_data)} community scam reports")
        except Exception as e:
            print(f"   ⚠️ Community scam collection failed: {e}")
            self.datasets['community_scams'] = []
        
        # 7. ChainAbuse Scraping (Abuse reports)
        print("\n📊 7. ChainAbuse Cryptocurrency Abuse Database")
        try:
            chainabuse_scraper = ChainAbuseScraper()
            chainabuse_data = await chainabuse_scraper.scrape_all_addresses()
            self.datasets['chain_abuse'] = chainabuse_data
            print(f"   ✅ Collected {len(chainabuse_data)} chain abuse records")
        except Exception as e:
            print(f"   ⚠️ ChainAbuse collection failed: {e}")
            self.datasets['chain_abuse'] = []

    def process_for_training(self):
        """Process all collected data for ML training"""
        
        print(f"\n🔄 PROCESSING {sum(len(data) for data in self.datasets.values()):,} RECORDS FOR TRAINING")
        print("=" * 60)
        
        training_data = []
        
        # Process each dataset type
        for dataset_name, dataset in self.datasets.items():
            if not dataset:
                continue
                
            print(f"🔄 Processing {dataset_name}: {len(dataset):,} records")
            
            for record in dataset:
                # Convert each record to unified training format
                training_record = self._convert_to_training_format(record, dataset_name)
                if training_record:
                    training_data.append(training_record)
        
        print(f"\n✅ PROCESSED {len(training_data):,} UNIFIED TRAINING RECORDS")
        return training_data

    def _convert_to_training_format(self, record, dataset_type):
        """Convert any record type to unified training format"""
        
        try:
            # Base training record structure
            training_record = {
                'type': f'{dataset_type}_intelligence',
                'source_dataset': dataset_type,
                'timestamp': int(time.time())
            }
            
            # Dataset-specific processing
            if 'elliptic' in dataset_type:
                training_record['data'] = self._process_elliptic_record(record)
                
            elif 'ethereum' in dataset_type:
                training_record['data'] = self._process_ethereum_record(record)
                
            elif 'crime' in dataset_type or 'scam' in dataset_type:
                training_record['data'] = self._process_crime_record(record)
                
            elif 'ransomware' in dataset_type:
                training_record['data'] = self._process_ransomware_record(record)
                
            else:
                training_record['data'] = self._process_generic_record(record)
            
            return training_record
            
        except Exception as e:
            self.logger.warning(f"Failed to process record: {e}")
            return None

    def _process_elliptic_record(self, record):
        """Process Elliptic Bitcoin transaction record"""
        return {
            'address': getattr(record, 'transaction_id', str(record)),
            'label': getattr(record, 'label', 'unknown'),
            'confidence': getattr(record, 'label_confidence', 0.5),
            'features': getattr(record, 'address_features', []),
            'risk_indicators': ['illicit_bitcoin'] if getattr(record, 'label', '') == 'illicit' else []
        }

    def _process_ethereum_record(self, record):
        """Process Ethereum fraud detection record"""
        return {
            'address': getattr(record, 'address', ''),
            'tx_hash': getattr(record, 'tx_hash', ''),
            'fraud_flag': getattr(record, 'fraud_flag', False),
            'transaction_type': getattr(record, 'transaction_type', 'normal'),
            'risk_indicators': ['ethereum_fraud'] if getattr(record, 'fraud_flag', False) else []
        }

    def _process_crime_record(self, record):
        """Process historical crime/scam record"""
        return {
            'identifier': str(record.get('address', record.get('email', record.get('domain', '')))),
            'crime_type': record.get('type', 'unknown'),
            'threat_level': record.get('risk_level', 'medium'),
            'risk_indicators': [record.get('type', 'general_crime')]
        }

    def _process_ransomware_record(self, record):
        """Process ransomware payment record"""
        return {
            'address': record.get('address', ''),
            'malware_family': record.get('family', 'unknown'),
            'payment_amount': record.get('amount', 0),
            'risk_indicators': ['ransomware_payment']
        }

    def _process_generic_record(self, record):
        """Process any other record type"""
        return {
            'data': str(record),
            'risk_indicators': ['generic_threat']
        }

    def save_massive_dataset(self, training_data):
        """Save the massive unified training dataset"""
        
        # Create datasets directory
        os.makedirs('datasets', exist_ok=True)
        
        # Save comprehensive dataset
        comprehensive_file = 'datasets/massive_threat_intelligence.json'
        with open(comprehensive_file, 'w') as f:
            json.dump(training_data, f, indent=2)
        
        # Save dataset statistics
        stats = {
            'total_records': len(training_data),
            'collection_time': time.time() - self.start_time,
            'datasets_collected': {name: len(data) for name, data in self.datasets.items()},
            'dataset_sources': list(self.datasets.keys()),
            'created_at': datetime.now().isoformat()
        }
        
        stats_file = 'datasets/massive_dataset_stats.json'
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
        
        # Create training-ready CSV for quick analysis
        try:
            # Convert to DataFrame for analysis
            df_data = []
            for record in training_data[:10000]:  # Sample for CSV
                flat_record = {
                    'type': record['type'],
                    'source': record['source_dataset'],
                    'has_risk_indicators': len(record['data'].get('risk_indicators', [])) > 0,
                    'risk_count': len(record['data'].get('risk_indicators', [])),
                    'timestamp': record['timestamp']
                }
                df_data.append(flat_record)
            
            df = pd.DataFrame(df_data)
            df.to_csv('datasets/massive_threat_sample.csv', index=False)
            
        except Exception as e:
            print(f"⚠️ CSV creation failed: {e}")
        
        print(f"\n💾 MASSIVE DATASET SAVED:")
        print(f"   📁 Main dataset: {comprehensive_file}")
        print(f"   📊 Statistics: {stats_file}")
        print(f"   📊 Sample CSV: datasets/massive_threat_sample.csv")
        print(f"   📈 Total size: {len(training_data):,} records")
        print(f"   ⏱️ Collection time: {stats['collection_time']:.1f} seconds")
        
        return comprehensive_file


async def main():
    """Main collection function for massive datasets"""
    
    collector = MassiveDatasetCollector()
    
    try:
        # Collect all massive datasets
        await collector.collect_all_datasets()
        
        # Process for training
        training_data = collector.process_for_training()
        
        # Save comprehensive dataset
        output_file = collector.save_massive_dataset(training_data)
        
        print(f"\n🎉 SUCCESS! MASSIVE THREAT INTELLIGENCE COLLECTION COMPLETE!")
        print("=" * 70)
        print(f"📊 Collected data from {len([d for d in collector.datasets.values() if d])} sources")
        print(f"🎯 Total training records: {len(training_data):,}")
        print(f"💾 Saved to: {output_file}")
        print(f"🚀 Ready for PRODUCTION-SCALE AI training!")
        
        return output_file
        
    except Exception as e:
        print(f"\n❌ Collection failed: {e}")
        print("💾 Attempting to save partial results...")
        
        if hasattr(collector, 'datasets'):
            training_data = collector.process_for_training()
            if training_data:
                return collector.save_massive_dataset(training_data)
        
        return None


if __name__ == "__main__":
    result = asyncio.run(main())
    if result:
        print(f"\n✅ Massive dataset ready at: {result}")
        print("🎯 Use this with your production Colab training notebook!")
    else:
        print("\n❌ Collection failed - check your API keys and network connection")