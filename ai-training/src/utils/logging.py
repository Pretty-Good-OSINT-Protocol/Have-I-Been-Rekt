"""
Logging configuration and utilities for the AI training system.
Provides structured logging with different output formats and log levels.
"""

import logging
import logging.handlers
import sys
import json
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

import structlog


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        # Create base log entry
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add any extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'getMessage', 'exc_info',
                          'exc_text', 'stack_info']:
                log_entry[key] = value
        
        return json.dumps(log_entry)


class ColoredFormatter(logging.Formatter):
    """Colored console formatter for development"""
    
    # Color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }
    
    def format(self, record: logging.LogRecord) -> str:
        # Add color
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{color}{record.levelname}{self.COLORS['RESET']}"
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        
        # Create formatted message
        return f"{timestamp} {record.levelname:<8} {record.name:<20} {record.getMessage()}"


def setup_logging(config: Dict[str, Any]) -> logging.Logger:
    """Set up logging configuration"""
    
    log_level = config.get('level', 'INFO').upper()
    log_format = config.get('format', 'structured')
    log_file = config.get('file', './logs/collector.log')
    max_size_mb = config.get('max_size_mb', 100)
    backup_count = config.get('backup_count', 5)
    
    # Create log directory if it doesn't exist
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure structlog for structured logging
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer() if log_format == 'structured' else structlog.dev.ConsoleRenderer(colors=True)
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Get root logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    if log_format == 'structured':
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(ColoredFormatter())
    
    console_handler.setLevel(getattr(logging, log_level))
    logger.addHandler(console_handler)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_size_mb * 1024 * 1024,  # Convert MB to bytes
        backupCount=backup_count
    )
    file_handler.setFormatter(JSONFormatter())
    file_handler.setLevel(logging.DEBUG)  # Always log everything to file
    logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a structured logger instance"""
    return structlog.get_logger(name)


class LoggingMixin:
    """Mixin class to add logging capabilities to any class"""
    
    @property
    def logger(self) -> structlog.BoundLogger:
        """Get logger for this class"""
        if not hasattr(self, '_logger'):
            self._logger = get_logger(self.__class__.__name__)
        return self._logger
    
    def log_api_call(self, url: str, method: str = 'GET', status_code: Optional[int] = None, 
                     response_time_ms: Optional[float] = None, error: Optional[str] = None):
        """Log API call details"""
        self.logger.info(
            "API call completed",
            url=url,
            method=method,
            status_code=status_code,
            response_time_ms=response_time_ms,
            error=error
        )
    
    def log_analysis_result(self, address: str, risk_score: float, risk_level: str,
                           processing_time_ms: int, source_count: int):
        """Log analysis result details"""
        self.logger.info(
            "Analysis completed",
            address=address,
            risk_score=risk_score,
            risk_level=risk_level,
            processing_time_ms=processing_time_ms,
            source_count=source_count
        )
    
    def log_cache_performance(self, cache_hits: int, cache_misses: int, hit_rate: float):
        """Log cache performance metrics"""
        self.logger.info(
            "Cache performance",
            cache_hits=cache_hits,
            cache_misses=cache_misses,
            hit_rate=hit_rate
        )
    
    def log_rate_limit(self, source: str, delay_seconds: float):
        """Log rate limiting delays"""
        self.logger.warning(
            "Rate limit delay applied",
            source=source,
            delay_seconds=delay_seconds
        )
    
    def log_error_with_context(self, error: Exception, context: Dict[str, Any]):
        """Log error with additional context"""
        self.logger.error(
            "Operation failed",
            error=str(error),
            error_type=error.__class__.__name__,
            **context
        )


class PerformanceLogger:
    """Context manager for logging performance metrics"""
    
    def __init__(self, logger: structlog.BoundLogger, operation: str, **context):
        self.logger = logger
        self.operation = operation
        self.context = context
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.utcnow()
        self.logger.debug(
            f"{self.operation} started",
            **self.context
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        end_time = datetime.utcnow()
        duration_ms = (end_time - self.start_time).total_seconds() * 1000
        
        if exc_type is None:
            self.logger.info(
                f"{self.operation} completed",
                duration_ms=duration_ms,
                **self.context
            )
        else:
            self.logger.error(
                f"{self.operation} failed",
                duration_ms=duration_ms,
                error=str(exc_val),
                error_type=exc_type.__name__ if exc_type else None,
                **self.context
            )
    
    def add_context(self, **kwargs):
        """Add additional context to the log"""
        self.context.update(kwargs)


def log_function_call(func):
    """Decorator to log function calls with arguments and results"""
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__ + '.' + func.__qualname__)
        
        # Log function entry
        logger.debug(
            f"Function {func.__name__} called",
            args=str(args)[:200],  # Limit arg length
            kwargs=str(kwargs)[:200]
        )
        
        start_time = datetime.utcnow()
        try:
            result = func(*args, **kwargs)
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            logger.debug(
                f"Function {func.__name__} completed",
                duration_ms=duration_ms,
                result_type=type(result).__name__
            )
            
            return result
        except Exception as e:
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            logger.error(
                f"Function {func.__name__} failed",
                duration_ms=duration_ms,
                error=str(e),
                error_type=e.__class__.__name__
            )
            raise
    
    return wrapper


class MetricsCollector:
    """Collects and logs application metrics"""
    
    def __init__(self):
        self.metrics = {}
        self.logger = get_logger(self.__class__.__name__)
    
    def increment(self, metric_name: str, value: int = 1, **tags):
        """Increment a counter metric"""
        key = self._make_key(metric_name, tags)
        self.metrics[key] = self.metrics.get(key, 0) + value
    
    def set_gauge(self, metric_name: str, value: float, **tags):
        """Set a gauge metric"""
        key = self._make_key(metric_name, tags)
        self.metrics[key] = value
    
    def record_timing(self, metric_name: str, duration_ms: float, **tags):
        """Record a timing metric"""
        key = self._make_key(metric_name, tags)
        if key not in self.metrics:
            self.metrics[key] = []
        self.metrics[key].append(duration_ms)
    
    def _make_key(self, metric_name: str, tags: Dict[str, Any]) -> str:
        """Create a metric key from name and tags"""
        if tags:
            tag_str = ','.join(f"{k}={v}" for k, v in sorted(tags.items()))
            return f"{metric_name}[{tag_str}]"
        return metric_name
    
    def log_metrics(self):
        """Log all collected metrics"""
        if not self.metrics:
            return
        
        self.logger.info(
            "Application metrics",
            metrics=self.metrics
        )
    
    def reset_metrics(self):
        """Reset all metrics"""
        self.metrics.clear()


# Global metrics collector
_metrics_collector = MetricsCollector()


def get_metrics_collector() -> MetricsCollector:
    """Get global metrics collector instance"""
    return _metrics_collector