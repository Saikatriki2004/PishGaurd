"""
Observability Module - Production-grade logging, metrics, and rate limiting.

Phase 4 improvements:
1. Structured JSON logging for log aggregation (ELK, Splunk, etc.)
2. Prometheus metrics for monitoring dashboards
3. Rate limiting configuration

Usage:
    from src.observability import setup_logging, get_metrics, get_limiter
"""

import logging
import sys
import os
from datetime import datetime
from typing import Optional, Dict, Any

# Structured JSON logging
try:
    from pythonjsonlogger import jsonlogger
    JSON_LOGGING_AVAILABLE = True
except ImportError:
    JSON_LOGGING_AVAILABLE = False

# ============================================================================
# STRUCTURED LOGGING
# ============================================================================

class PhishingLogFormatter(logging.Formatter):
    """
    Custom formatter that adds phishing-specific context to log records.
    Falls back to standard formatting if json logger not available.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        # Add timestamp
        record.timestamp = datetime.utcnow().isoformat() + "Z"
        record.service = "phishing-detector"
        
        return super().format(record)


class StructuredJsonFormatter(jsonlogger.JsonFormatter if JSON_LOGGING_AVAILABLE else logging.Formatter):
    """
    JSON formatter for structured logging.
    Compatible with ELK Stack, Splunk, CloudWatch, etc.
    """
    
    def add_fields(self, log_record: Dict, record: logging.LogRecord, message_dict: Dict) -> None:
        super().add_fields(log_record, record, message_dict)
        
        # Add standard fields
        log_record['timestamp'] = datetime.utcnow().isoformat() + "Z"
        log_record['service'] = "phishing-detector"
        log_record['level'] = record.levelname
        log_record['logger'] = record.name
        
        # Add request context if available
        if hasattr(record, 'url'):
            log_record['url'] = record.url
        if hasattr(record, 'verdict'):
            log_record['verdict'] = record.verdict
        if hasattr(record, 'risk_score'):
            log_record['risk_score'] = record.risk_score
        if hasattr(record, 'latency_ms'):
            log_record['latency_ms'] = record.latency_ms


def setup_logging(
    level: int = logging.INFO,
    json_format: bool = True,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Configure structured logging for the application.
    
    Args:
        level: Logging level (default: INFO)
        json_format: Use JSON format for log aggregation (default: True)
        log_file: Optional file path for file logging
        
    Returns:
        Configured root logger
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    if json_format and JSON_LOGGING_AVAILABLE:
        formatter = StructuredJsonFormatter(
            '%(timestamp)s %(level)s %(name)s %(message)s'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    return root_logger


# ============================================================================
# PROMETHEUS METRICS
# ============================================================================

class PhishingMetrics:
    """
    Prometheus metrics collector for phishing detection.
    
    Exposes:
    - Request counts by verdict
    - Latency histograms
    - Cache hit/miss rates
    - Blocklist match counts
    - Feature extraction failures
    """
    
    def __init__(self):
        self._enabled = False
        self._metrics = {}
        
        try:
            from prometheus_client import Counter, Histogram, Gauge, Info
            
            # Request metrics
            self.requests_total = Counter(
                'phishing_requests_total',
                'Total number of URL analysis requests',
                ['verdict', 'source']
            )
            
            self.request_latency = Histogram(
                'phishing_request_latency_seconds',
                'Request latency in seconds',
                ['endpoint'],
                buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
            )
            
            # Cache metrics
            self.cache_hits = Counter(
                'phishing_cache_hits_total',
                'Number of cache hits'
            )
            
            self.cache_misses = Counter(
                'phishing_cache_misses_total',
                'Number of cache misses'
            )
            
            # Detection metrics
            self.blocklist_matches = Counter(
                'phishing_blocklist_matches_total',
                'Number of blocklist matches',
                ['source']
            )
            
            self.trusted_domain_bypasses = Counter(
                'phishing_trusted_domain_bypasses_total',
                'Number of trusted domain bypasses'
            )
            
            # Feature extraction metrics
            self.feature_extraction_failures = Counter(
                'phishing_feature_extraction_failures_total',
                'Number of feature extraction failures',
                ['failure_type']
            )
            
            # Model metrics
            self.model_info = Info(
                'phishing_model',
                'Information about the current model'
            )
            
            # Active requests gauge
            self.active_requests = Gauge(
                'phishing_active_requests',
                'Number of currently active requests'
            )
            
            self._enabled = True
            
        except ImportError:
            pass
    
    @property
    def enabled(self) -> bool:
        return self._enabled
    
    def record_request(self, verdict: str, source: str = "single") -> None:
        """Record a completed request."""
        if self._enabled:
            self.requests_total.labels(verdict=verdict, source=source).inc()
    
    def record_cache_hit(self) -> None:
        """Record a cache hit."""
        if self._enabled:
            self.cache_hits.inc()
    
    def record_cache_miss(self) -> None:
        """Record a cache miss."""
        if self._enabled:
            self.cache_misses.inc()
    
    def record_blocklist_match(self, source: str = "unknown") -> None:
        """Record a blocklist match."""
        if self._enabled:
            self.blocklist_matches.labels(source=source).inc()
    
    def record_trusted_bypass(self) -> None:
        """Record a trusted domain bypass."""
        if self._enabled:
            self.trusted_domain_bypasses.inc()
    
    def record_feature_failure(self, failure_type: str) -> None:
        """Record a feature extraction failure."""
        if self._enabled:
            self.feature_extraction_failures.labels(failure_type=failure_type).inc()
    
    def set_model_info(self, version: str, accuracy: float) -> None:
        """Set model information."""
        if self._enabled:
            self.model_info.info({
                'version': version,
                'accuracy': str(accuracy)
            })


# Singleton metrics instance
_metrics: Optional[PhishingMetrics] = None


def get_metrics() -> PhishingMetrics:
    """Get or create the metrics singleton."""
    global _metrics
    if _metrics is None:
        _metrics = PhishingMetrics()
    return _metrics


# ============================================================================
# RATE LIMITING
# ============================================================================

def setup_rate_limiter(app):
    """
    Configure rate limiter with Redis support and fail-open behavior.
    
    Environment Variables:
        RATELIMIT_STORAGE_URI: Redis URI (e.g., "redis://localhost:6379")
                               Falls back to "memory://" for single-process
    
    Behavior:
        - Default limit: 100 per hour
        - On Redis failure: Logs warning and ALLOWS request (fail-open)
        - Memory storage: Warning logged (doesn't work across workers)
    
    Args:
        app: Flask application instance
        
    Returns:
        Limiter instance or None if unavailable
    """
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        
        storage_uri = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
        
        # Redis connection options for resilience
        storage_options = {}
        if storage_uri.startswith("redis://"):
            storage_options = {
                "socket_connect_timeout": 1,
                "socket_timeout": 1,
            }
            logging.info(f"[RATE_LIMIT] Using Redis storage: {storage_uri.split('@')[-1]}")
        else:
            logging.warning(
                "[RATE_LIMIT] Using memory:// - limits NOT shared across workers. "
                "Set RATELIMIT_STORAGE_URI=redis://... for production."
            )
        
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["100 per hour"],
            storage_uri=storage_uri,
            storage_options=storage_options,
            strategy="fixed-window",
            swallow_errors=True,  # FAIL-OPEN: Redis down → allow request + log
        )
        
        return limiter
        
    except ImportError:
        logging.warning("[RATE_LIMIT] flask-limiter not installed, rate limiting disabled")
        return None


# Rate limit constants for endpoint decorators
RATE_LIMITS = {
    "scan": "30 per minute",
    "batch_scan": "5 per minute",
    "health": "exempt",
    "api": "100 per hour"
}


# ============================================================================
# PROMETHEUS ENDPOINT SETUP
# ============================================================================

def setup_prometheus_endpoint(app):
    """
    Add /metrics endpoint for Prometheus scraping.
    
    Args:
        app: Flask application instance
    """
    try:
        from prometheus_flask_exporter import PrometheusMetrics
        
        metrics = PrometheusMetrics(app)
        
        # Add default labels
        metrics.info('phishing_app_info', 'Application info', version='4.0')
        
        return metrics
        
    except ImportError:
        logging.warning("[OBSERVABILITY] prometheus-flask-exporter not installed")
        return None
