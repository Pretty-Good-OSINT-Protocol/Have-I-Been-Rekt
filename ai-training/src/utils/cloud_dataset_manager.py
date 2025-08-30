"""
Cloud Dataset Manager - Efficient handling of large blockchain investigation datasets
using cloud storage, streaming processing, and intelligent caching strategies.

Supports:
- AWS S3, Google Cloud Storage, Azure Blob Storage
- Streaming dataset processing to minimize memory usage
- Intelligent chunking and compression
- Progress tracking and resumable downloads
- Local caching with LRU eviction
"""

import os
import json
import hashlib
import gzip
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterator, Union
from datetime import datetime, timedelta
import logging
import requests
from urllib.parse import urlparse
import tempfile
import shutil

import pandas as pd
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from google.cloud import storage as gcs
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

try:
    from azure.storage.blob import BlobServiceClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False


class CloudDatasetManager:
    """
    Advanced dataset manager for large blockchain investigation datasets
    with cloud storage integration and memory-efficient processing.
    """
    
    def __init__(self, config: Dict[str, Any], cache_dir: str = "./cache/datasets", 
                 logger: Optional[logging.Logger] = None):
        self.config = config
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = logger or logging.getLogger(__name__)
        
        # Configuration
        self.max_memory_usage = config.get('max_memory_usage_gb', 4) * 1024**3  # Convert to bytes
        self.chunk_size = config.get('chunk_size_rows', 10000)
        self.compression_enabled = config.get('enable_compression', True)
        self.max_cache_size_gb = config.get('max_cache_size_gb', 10)
        
        # Cloud storage clients
        self.s3_client = None
        self.gcs_client = None
        self.azure_client = None
        
        # Initialize available cloud clients
        self._initialize_cloud_clients()
        
        # Dataset registry
        self.dataset_registry_file = self.cache_dir / "dataset_registry.json"
        self.dataset_registry = self._load_dataset_registry()
        
        self.logger.info("Cloud Dataset Manager initialized", 
                        cache_dir=str(self.cache_dir),
                        max_memory_gb=self.max_memory_usage/(1024**3))
    
    def _initialize_cloud_clients(self):
        """Initialize available cloud storage clients"""
        
        # AWS S3
        if AWS_AVAILABLE and self.config.get('aws_access_key_id'):
            try:
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=self.config.get('aws_access_key_id'),
                    aws_secret_access_key=self.config.get('aws_secret_access_key'),
                    region_name=self.config.get('aws_region', 'us-east-1')
                )
                self.logger.info("AWS S3 client initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize AWS S3: {e}")
        
        # Google Cloud Storage
        if GCP_AVAILABLE and self.config.get('gcp_credentials_path'):
            try:
                self.gcs_client = gcs.Client.from_service_account_json(
                    self.config.get('gcp_credentials_path')
                )
                self.logger.info("Google Cloud Storage client initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize GCS: {e}")
        
        # Azure Blob Storage
        if AZURE_AVAILABLE and self.config.get('azure_connection_string'):
            try:
                self.azure_client = BlobServiceClient.from_connection_string(
                    self.config.get('azure_connection_string')
                )
                self.logger.info("Azure Blob Storage client initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Azure: {e}")
    
    def _load_dataset_registry(self) -> Dict[str, Any]:
        """Load dataset registry from cache"""
        if self.dataset_registry_file.exists():
            try:
                with open(self.dataset_registry_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Failed to load dataset registry: {e}")
        
        return {
            'datasets': {},
            'last_updated': datetime.utcnow().isoformat(),
            'cache_stats': {
                'total_size_bytes': 0,
                'dataset_count': 0
            }
        }
    
    def _save_dataset_registry(self):
        """Save dataset registry to cache"""
        try:
            self.dataset_registry['last_updated'] = datetime.utcnow().isoformat()
            with open(self.dataset_registry_file, 'w') as f:
                json.dump(self.dataset_registry, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save dataset registry: {e}")
    
    def upload_dataset_to_cloud(self, dataset_path: str, cloud_provider: str, 
                               bucket_name: str, object_key: str) -> bool:
        """Upload dataset to cloud storage with compression"""
        
        dataset_path = Path(dataset_path)
        if not dataset_path.exists():
            self.logger.error(f"Dataset file not found: {dataset_path}")
            return False
        
        try:
            # Compress dataset if enabled
            upload_path = dataset_path
            if self.compression_enabled and not dataset_path.name.endswith('.gz'):
                compressed_path = dataset_path.with_suffix(dataset_path.suffix + '.gz')
                self.logger.info(f"Compressing dataset: {dataset_path} -> {compressed_path}")
                
                with open(dataset_path, 'rb') as f_in:
                    with gzip.open(compressed_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                upload_path = compressed_path
                object_key += '.gz'
            
            # Upload to specified cloud provider
            if cloud_provider.lower() == 'aws' and self.s3_client:
                return self._upload_to_s3(upload_path, bucket_name, object_key)
            elif cloud_provider.lower() == 'gcp' and self.gcs_client:
                return self._upload_to_gcs(upload_path, bucket_name, object_key)
            elif cloud_provider.lower() == 'azure' and self.azure_client:
                return self._upload_to_azure(upload_path, bucket_name, object_key)
            else:
                self.logger.error(f"Cloud provider '{cloud_provider}' not available or configured")
                return False
                
        except Exception as e:
            self.logger.error(f"Dataset upload failed: {e}")
            return False
    
    def _upload_to_s3(self, file_path: Path, bucket_name: str, object_key: str) -> bool:
        """Upload file to AWS S3"""
        try:
            file_size = file_path.stat().st_size
            
            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Uploading to S3") as pbar:
                def callback(bytes_transferred):
                    pbar.update(bytes_transferred)
                
                self.s3_client.upload_file(
                    str(file_path), bucket_name, object_key,
                    Callback=callback
                )
            
            self.logger.info(f"Successfully uploaded to S3: s3://{bucket_name}/{object_key}")
            return True
            
        except ClientError as e:
            self.logger.error(f"S3 upload failed: {e}")
            return False
    
    def _upload_to_gcs(self, file_path: Path, bucket_name: str, object_key: str) -> bool:
        """Upload file to Google Cloud Storage"""
        try:
            bucket = self.gcs_client.bucket(bucket_name)
            blob = bucket.blob(object_key)
            
            file_size = file_path.stat().st_size
            
            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Uploading to GCS") as pbar:
                with open(file_path, 'rb') as f:
                    blob.upload_from_file(f)
                    pbar.update(file_size)
            
            self.logger.info(f"Successfully uploaded to GCS: gs://{bucket_name}/{object_key}")
            return True
            
        except Exception as e:
            self.logger.error(f"GCS upload failed: {e}")
            return False
    
    def _upload_to_azure(self, file_path: Path, container_name: str, blob_name: str) -> bool:
        """Upload file to Azure Blob Storage"""
        try:
            blob_client = self.azure_client.get_blob_client(
                container=container_name, blob=blob_name
            )
            
            file_size = file_path.stat().st_size
            
            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Uploading to Azure") as pbar:
                with open(file_path, 'rb') as f:
                    blob_client.upload_blob(f, overwrite=True)
                    pbar.update(file_size)
            
            self.logger.info(f"Successfully uploaded to Azure: {container_name}/{blob_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Azure upload failed: {e}")
            return False
    
    def download_dataset_from_cloud(self, cloud_url: str, local_path: Optional[str] = None) -> Optional[str]:
        """Download dataset from cloud storage with resume capability"""
        
        # Parse cloud URL
        parsed_url = urlparse(cloud_url)
        
        if parsed_url.scheme == 's3' and self.s3_client:
            return self._download_from_s3(cloud_url, local_path)
        elif parsed_url.scheme in ['gs', 'gcs'] and self.gcs_client:
            return self._download_from_gcs(cloud_url, local_path)
        elif parsed_url.scheme.startswith('http'):
            return self._download_from_http(cloud_url, local_path)
        else:
            self.logger.error(f"Unsupported cloud URL format: {cloud_url}")
            return None
    
    def _download_from_s3(self, s3_url: str, local_path: Optional[str] = None) -> Optional[str]:
        """Download dataset from S3 with progress tracking"""
        try:
            # Parse S3 URL: s3://bucket/key
            parsed = urlparse(s3_url)
            bucket_name = parsed.netloc
            object_key = parsed.path.lstrip('/')
            
            if not local_path:
                local_path = self.cache_dir / Path(object_key).name
            else:
                local_path = Path(local_path)
            
            # Get object info
            response = self.s3_client.head_object(Bucket=bucket_name, Key=object_key)
            file_size = response['ContentLength']
            
            # Download with progress
            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Downloading from S3") as pbar:
                def callback(bytes_transferred):
                    pbar.update(bytes_transferred)
                
                self.s3_client.download_file(
                    bucket_name, object_key, str(local_path),
                    Callback=callback
                )
            
            self.logger.info(f"Downloaded from S3: {s3_url} -> {local_path}")
            return str(local_path)
            
        except Exception as e:
            self.logger.error(f"S3 download failed: {e}")
            return None
    
    def _download_from_http(self, url: str, local_path: Optional[str] = None) -> Optional[str]:
        """Download dataset from HTTP/HTTPS with resume capability"""
        try:
            if not local_path:
                local_path = self.cache_dir / Path(urlparse(url).path).name
            else:
                local_path = Path(local_path)
            
            local_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Check if partial file exists
            resume_header = {}
            if local_path.exists():
                resume_header['Range'] = f'bytes={local_path.stat().st_size}-'
                mode = 'ab'
            else:
                mode = 'wb'
            
            # Get file info
            head_response = requests.head(url, allow_redirects=True)
            total_size = int(head_response.headers.get('Content-Length', 0))
            
            # Download with progress
            response = requests.get(url, headers=resume_header, stream=True)
            response.raise_for_status()
            
            with open(local_path, mode) as f:
                with tqdm(total=total_size, unit='B', unit_scale=True, 
                         initial=local_path.stat().st_size if local_path.exists() else 0,
                         desc="Downloading dataset") as pbar:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            pbar.update(len(chunk))
            
            self.logger.info(f"Downloaded: {url} -> {local_path}")
            return str(local_path)
            
        except Exception as e:
            self.logger.error(f"HTTP download failed: {e}")
            return None
    
    def stream_dataset(self, dataset_path: str, chunk_size: Optional[int] = None) -> Iterator[pd.DataFrame]:
        """Stream large dataset in chunks to minimize memory usage"""
        
        dataset_path = Path(dataset_path)
        chunk_size = chunk_size or self.chunk_size
        
        try:
            # Handle compressed files
            if dataset_path.suffix == '.gz':
                self.logger.info(f"Streaming compressed dataset: {dataset_path}")
                
                # For CSV files
                if dataset_path.stem.endswith('.csv'):
                    with gzip.open(dataset_path, 'rt') as f:
                        for chunk in pd.read_csv(f, chunksize=chunk_size):
                            yield chunk
                else:
                    # Decompress first, then stream
                    temp_path = self._decompress_to_temp(dataset_path)
                    try:
                        yield from self._stream_uncompressed(temp_path, chunk_size)
                    finally:
                        temp_path.unlink(missing_ok=True)
            
            else:
                yield from self._stream_uncompressed(dataset_path, chunk_size)
                
        except Exception as e:
            self.logger.error(f"Dataset streaming failed: {e}")
            raise
    
    def _stream_uncompressed(self, dataset_path: Path, chunk_size: int) -> Iterator[pd.DataFrame]:
        """Stream uncompressed dataset file"""
        
        if dataset_path.suffix == '.csv':
            for chunk in pd.read_csv(dataset_path, chunksize=chunk_size):
                yield chunk
        
        elif dataset_path.suffix in ['.parquet', '.pq']:
            # For Parquet files, read in row groups
            import pyarrow.parquet as pq
            parquet_file = pq.ParquetFile(dataset_path)
            
            for batch in parquet_file.iter_batches(batch_size=chunk_size):
                yield batch.to_pandas()
        
        elif dataset_path.suffix == '.pkl':
            # For pickle files, load entirely (not streamable)
            self.logger.warning("Pickle files cannot be streamed, loading entirely")
            with open(dataset_path, 'rb') as f:
                data = pickle.load(f)
                if isinstance(data, pd.DataFrame):
                    # Split into chunks
                    for i in range(0, len(data), chunk_size):
                        yield data.iloc[i:i+chunk_size]
                else:
                    raise ValueError("Pickle file does not contain pandas DataFrame")
        
        else:
            raise ValueError(f"Unsupported file format: {dataset_path.suffix}")
    
    def _decompress_to_temp(self, compressed_path: Path) -> Path:
        """Decompress file to temporary location"""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=compressed_path.stem)
        
        with gzip.open(compressed_path, 'rb') as f_in:
            with open(temp_file.name, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        return Path(temp_file.name)
    
    def optimize_dataset_storage(self, dataset_path: str) -> Dict[str, Any]:
        """Optimize dataset storage through compression and format conversion"""
        
        dataset_path = Path(dataset_path)
        optimization_results = {
            'original_size': dataset_path.stat().st_size,
            'optimizations_applied': [],
            'final_size': 0,
            'compression_ratio': 1.0,
            'optimized_path': str(dataset_path)
        }
        
        try:
            # Read dataset
            self.logger.info(f"Optimizing dataset storage: {dataset_path}")
            
            if dataset_path.suffix == '.csv':
                df = pd.read_csv(dataset_path)
                
                # Convert to more efficient formats
                
                # 1. Convert to Parquet (better compression, faster I/O)
                parquet_path = dataset_path.with_suffix('.parquet')
                df.to_parquet(parquet_path, compression='snappy')
                optimization_results['optimizations_applied'].append('converted_to_parquet')
                
                # 2. Optimize data types
                df_optimized = self._optimize_dtypes(df)
                if not df_optimized.equals(df):
                    parquet_path = dataset_path.with_suffix('.optimized.parquet')
                    df_optimized.to_parquet(parquet_path, compression='snappy')
                    optimization_results['optimizations_applied'].append('optimized_dtypes')
                
                # 3. Compress with gzip if still CSV
                if self.compression_enabled:
                    compressed_path = dataset_path.with_suffix('.csv.gz')
                    df.to_csv(compressed_path, index=False, compression='gzip')
                    optimization_results['optimizations_applied'].append('gzip_compression')
                    
                    # Use the most efficient option
                    sizes = {}
                    if parquet_path.exists():
                        sizes['parquet'] = (parquet_path, parquet_path.stat().st_size)
                    if compressed_path.exists():
                        sizes['csv_gz'] = (compressed_path, compressed_path.stat().st_size)
                    
                    if sizes:
                        best_format, (best_path, best_size) = min(sizes.items(), key=lambda x: x[1][1])
                        optimization_results['optimized_path'] = str(best_path)
                        optimization_results['final_size'] = best_size
                        
                        # Clean up other formats
                        for format_name, (path, _) in sizes.items():
                            if format_name != best_format:
                                path.unlink(missing_ok=True)
            
            # Calculate compression ratio
            if optimization_results['final_size'] > 0:
                optimization_results['compression_ratio'] = (
                    optimization_results['original_size'] / optimization_results['final_size']
                )
            
            self.logger.info(
                f"Dataset optimization complete: {optimization_results['compression_ratio']:.2f}x compression",
                optimizations=optimization_results['optimizations_applied']
            )
            
            return optimization_results
            
        except Exception as e:
            self.logger.error(f"Dataset optimization failed: {e}")
            return optimization_results
    
    def _optimize_dtypes(self, df: pd.DataFrame) -> pd.DataFrame:
        """Optimize pandas DataFrame data types to reduce memory usage"""
        
        df_optimized = df.copy()
        
        for col in df_optimized.columns:
            col_type = df_optimized[col].dtype
            
            if col_type != 'object':
                c_min = df_optimized[col].min()
                c_max = df_optimized[col].max()
                
                if str(col_type)[:3] == 'int':
                    # Optimize integer types
                    if c_min > np.iinfo(np.int8).min and c_max < np.iinfo(np.int8).max:
                        df_optimized[col] = df_optimized[col].astype(np.int8)
                    elif c_min > np.iinfo(np.int16).min and c_max < np.iinfo(np.int16).max:
                        df_optimized[col] = df_optimized[col].astype(np.int16)
                    elif c_min > np.iinfo(np.int32).min and c_max < np.iinfo(np.int32).max:
                        df_optimized[col] = df_optimized[col].astype(np.int32)
                
                elif str(col_type)[:5] == 'float':
                    # Optimize float types
                    if (c_min > np.finfo(np.float32).min and 
                        c_max < np.finfo(np.float32).max):
                        df_optimized[col] = df_optimized[col].astype(np.float32)
        
        return df_optimized
    
    def manage_cache_size(self):
        """Manage local cache size using LRU eviction"""
        try:
            cache_size = sum(f.stat().st_size for f in self.cache_dir.rglob('*') if f.is_file())
            max_cache_bytes = self.max_cache_size_gb * 1024**3
            
            if cache_size > max_cache_bytes:
                self.logger.info(f"Cache size ({cache_size/(1024**3):.2f}GB) exceeds limit ({self.max_cache_size_gb}GB)")
                
                # Get all files with access times
                files_with_atime = []
                for f in self.cache_dir.rglob('*'):
                    if f.is_file():
                        files_with_atime.append((f.stat().st_atime, f.stat().st_size, f))
                
                # Sort by access time (oldest first)
                files_with_atime.sort()
                
                # Remove oldest files until under limit
                bytes_to_remove = cache_size - max_cache_bytes
                bytes_removed = 0
                
                for atime, size, file_path in files_with_atime:
                    if bytes_removed >= bytes_to_remove:
                        break
                    
                    file_path.unlink()
                    bytes_removed += size
                    self.logger.debug(f"Removed cached file: {file_path}")
                
                self.logger.info(f"Cache cleanup complete: removed {bytes_removed/(1024**3):.2f}GB")
        
        except Exception as e:
            self.logger.error(f"Cache management failed: {e}")
    
    def get_dataset_info(self, dataset_path: str) -> Dict[str, Any]:
        """Get comprehensive information about a dataset"""
        
        dataset_path = Path(dataset_path)
        
        if not dataset_path.exists():
            return {'exists': False}
        
        try:
            info = {
                'exists': True,
                'path': str(dataset_path),
                'size_bytes': dataset_path.stat().st_size,
                'size_mb': dataset_path.stat().st_size / (1024**2),
                'size_gb': dataset_path.stat().st_size / (1024**3),
                'modified_time': datetime.fromtimestamp(dataset_path.stat().st_mtime).isoformat(),
                'format': dataset_path.suffix,
                'compressed': dataset_path.suffix == '.gz'
            }
            
            # Try to get more detailed info for supported formats
            if dataset_path.suffix == '.csv':
                sample_df = pd.read_csv(dataset_path, nrows=1000)
                info.update({
                    'estimated_rows': None,  # Would need full scan
                    'columns': len(sample_df.columns),
                    'column_names': sample_df.columns.tolist(),
                    'dtypes': {col: str(dtype) for col, dtype in sample_df.dtypes.items()}
                })
                
                # Estimate total rows by file size vs sample size
                sample_size = len(sample_df)
                if sample_size > 0:
                    # Rough estimate based on average bytes per row
                    avg_bytes_per_row = info['size_bytes'] / 1000  # Assuming 1000 sample is representative
                    info['estimated_rows'] = int(info['size_bytes'] / avg_bytes_per_row)
            
            return info
            
        except Exception as e:
            self.logger.error(f"Failed to get dataset info: {e}")
            return {'exists': True, 'error': str(e)}
    
    def suggest_processing_strategy(self, dataset_path: str) -> Dict[str, Any]:
        """Suggest optimal processing strategy based on dataset characteristics"""
        
        info = self.get_dataset_info(dataset_path)
        
        if not info.get('exists'):
            return {'strategy': 'file_not_found'}
        
        size_gb = info.get('size_gb', 0)
        estimated_rows = info.get('estimated_rows', 0)
        
        suggestions = {
            'processing_strategy': 'unknown',
            'recommended_chunk_size': self.chunk_size,
            'memory_efficient': False,
            'cloud_storage_recommended': False,
            'format_optimization_recommended': False,
            'rationale': []
        }
        
        # Strategy based on size
        if size_gb < 1:
            suggestions['processing_strategy'] = 'load_full'
            suggestions['rationale'].append('Small dataset - can load entirely into memory')
        
        elif size_gb < 5:
            suggestions['processing_strategy'] = 'chunked_processing'
            suggestions['memory_efficient'] = True
            suggestions['recommended_chunk_size'] = min(self.chunk_size, estimated_rows // 10) if estimated_rows else self.chunk_size
            suggestions['rationale'].append('Medium dataset - use chunked processing')
        
        else:
            suggestions['processing_strategy'] = 'streaming_with_cloud'
            suggestions['memory_efficient'] = True
            suggestions['cloud_storage_recommended'] = True
            suggestions['recommended_chunk_size'] = min(self.chunk_size // 2, 5000)
            suggestions['rationale'].append('Large dataset - use streaming with cloud storage')
        
        # Format optimization
        if info.get('format') == '.csv' and size_gb > 0.5:
            suggestions['format_optimization_recommended'] = True
            suggestions['rationale'].append('CSV format inefficient for large datasets - consider Parquet')
        
        # Compression recommendation
        if not info.get('compressed') and size_gb > 1:
            suggestions['rationale'].append('Dataset compression recommended for storage efficiency')
        
        return suggestions


def create_cloud_config_template() -> Dict[str, Any]:
    """Create a template configuration for cloud dataset management"""
    return {
        # Memory and performance settings
        'max_memory_usage_gb': 4,
        'chunk_size_rows': 10000,
        'enable_compression': True,
        'max_cache_size_gb': 10,
        
        # AWS S3 configuration
        'aws_access_key_id': 'your_aws_access_key',
        'aws_secret_access_key': 'your_aws_secret_key', 
        'aws_region': 'us-east-1',
        'aws_bucket_name': 'your-blockchain-datasets',
        
        # Google Cloud Storage
        'gcp_credentials_path': '/path/to/service-account.json',
        'gcp_bucket_name': 'your-blockchain-datasets',
        
        # Azure Blob Storage
        'azure_connection_string': 'your_azure_connection_string',
        'azure_container_name': 'blockchain-datasets',
        
        # Dataset URLs (for automatic downloading)
        'dataset_urls': {
            'ethereum_fraud': 'https://www.kaggle.com/datasets/vagifa/ethereum-frauddetection-dataset',
            'elliptic_plus': 'https://github.com/git-disl/EllipticPlusPlus',
            'elliptic2': 'http://elliptic.co/elliptic2'
        }
    }