"""
Explanation Telemetry Module

PURPOSE:
    Record aggregate, anonymous metrics about explanation outputs to detect:
    - Dependency failures (WHOIS, DNS, HTTP)
    - Model degradation
    - Shifts in attacker behavior

SAFETY RULES:
    1. Telemetry must NEVER affect prediction outcome
    2. Telemetry failures must NOT crash the app
    3. Telemetry is strictly observational
    4. NO PII, URLs, domains, IPs, or raw features stored

DATA COLLECTED (aggregate only):
    - Verdict distribution
    - Analysis completion rates
    - Allowlist override frequency
    - Signal type frequency (capped at top 10)

ASYNC AUDIT LOGGING (XAI):
    Uses QueueHandler/QueueListener for true non-blocking I/O.
    Records top 3 features per request to JSONL audit file.
"""

import json
import os
import queue
import logging
import threading
import atexit
from datetime import datetime, timezone
from collections import Counter
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler

logger = logging.getLogger(__name__)


# ============================================================================
# ASYNC AUDIT LOGGER (QueueHandler Pattern)
# ============================================================================

AUDIT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "audit")
os.makedirs(AUDIT_DIR, exist_ok=True)

_audit_queue: queue.Queue = queue.Queue(-1)  # Unbounded queue
_audit_listener: Optional[QueueListener] = None
_audit_logger: Optional[logging.Logger] = None


def _init_audit_logger() -> logging.Logger:
    """
    Initialize async audit logger with QueueHandler.
    
    Architecture:
        Request Thread → QueueHandler → Queue → QueueListener → RotatingFileHandler
                        (non-blocking)         (background thread)
    """
    global _audit_listener, _audit_logger
    
    if _audit_logger is not None:
        return _audit_logger
    
    _audit_logger = logging.getLogger("xai_audit")
    _audit_logger.setLevel(logging.INFO)
    _audit_logger.propagate = False  # Don't bubble to root logger
    
    # Frontend: QueueHandler (non-blocking, just puts to queue)
    queue_handler = QueueHandler(_audit_queue)
    _audit_logger.addHandler(queue_handler)
    
    # Backend: Actual file handler (runs in background thread via QueueListener)
    if os.getenv("TELEMETRY_TO_STDOUT", "false").lower() == "true":
        backend_handler = logging.StreamHandler()
    else:
        backend_handler = RotatingFileHandler(
            os.path.join(AUDIT_DIR, "xai_telemetry.jsonl"),
            maxBytes=10 * 1024 * 1024,  # 10MB per file
            backupCount=5,
            encoding="utf-8"
        )
    backend_handler.setFormatter(logging.Formatter("%(message)s"))
    
    # QueueListener: Processes queue in dedicated background thread
    _audit_listener = QueueListener(
        _audit_queue, 
        backend_handler, 
        respect_handler_level=True
    )
    _audit_listener.start()
    
    # Graceful shutdown
    atexit.register(_shutdown_audit_logger)
    
    logger.info("[TELEMETRY] Async audit logger initialized")
    return _audit_logger


def _shutdown_audit_logger():
    """Stop queue listener gracefully on process exit."""
    global _audit_listener
    if _audit_listener:
        _audit_listener.stop()
        _audit_listener = None
        logger.info("[TELEMETRY] Audit logger shutdown complete")


def _record_audit_log(
    verdict: str,
    drift_status: str,
    top_features: List[Dict[str, str]]
) -> None:
    """
    Record XAI audit entry (non-blocking, fire-and-forget).
    
    Args:
        verdict: SAFE, SUSPICIOUS, or PHISHING
        drift_status: none, warning, or significant
        top_features: List of {"feature": str, "impact": str}
    """
    try:
        record = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "verdict": verdict,
            "drift": drift_status,
            "top_3": top_features
        }
        _init_audit_logger().info(json.dumps(record, separators=(",", ":")))
    except Exception:
        pass  # Never block request path

# ============================================================================
# CONFIGURATION
# ============================================================================

METRICS_FILE = "explanation_metrics.json"
FLUSH_INTERVAL_SCANS = 100  # Flush after every N scans
TOP_SIGNALS_LIMIT = 10  # Cap signal frequency maps


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ExplanationMetrics:
    """
    Aggregate metrics for explanation telemetry.
    
    NO PII. NO URLS. NO IDENTIFYING DATA.
    """
    # Core counters
    total_scans: int = 0
    scans_by_verdict: Dict[str, int] = field(default_factory=lambda: {
        "SAFE": 0, "SUSPICIOUS": 0, "PHISHING": 0
    })
    
    # Analysis quality
    scans_with_complete_analysis: int = 0
    scans_with_incomplete_analysis: int = 0
    
    # Allowlist behavior
    scans_with_allowlist_override: int = 0
    scans_without_allowlist_override: int = 0
    
    # Drift tracking
    scans_by_drift_status: Dict[str, int] = field(default_factory=lambda: {
        "none": 0, "warning": 0, "significant": 0
    })
    
    # Signal counts (aggregate)
    total_risk_signals: int = 0
    total_positive_signals: int = 0
    total_inconclusive_signals: int = 0
    
    # Top signals (frequency limited)
    top_risk_signals: Dict[str, int] = field(default_factory=dict)
    top_inconclusive_checks: Dict[str, int] = field(default_factory=dict)
    
    # Metadata
    collection_start: str = ""
    last_updated: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# TELEMETRY RECORDER
# ============================================================================

class ExplanationTelemetry:
    """
    Thread-safe telemetry recorder for explanation outputs.
    
    USAGE:
        telemetry = ExplanationTelemetry()
        telemetry.record(explanation, verdict, drift_status)
        
    SAFETY:
        - All operations are fail-safe (catch-all exceptions)
        - No blocking operations in critical path
        - Automatic flush on shutdown
    """
    
    def __init__(self, metrics_path: str = METRICS_FILE):
        """
        Initialize telemetry.
        
        Args:
            metrics_path: Path to metrics JSON file
        """
        self.metrics_path = metrics_path
        self._lock = threading.Lock()
        self._scan_count_since_flush = 0
        
        # Load existing metrics or create new
        self.metrics = self._load_or_create_metrics()
        
        # Register shutdown hook
        atexit.register(self._flush_on_exit)
        
        logger.info("[TELEMETRY] Explanation telemetry initialized")
    
    def _load_or_create_metrics(self) -> ExplanationMetrics:
        """Load existing metrics or create new."""
        if os.path.exists(self.metrics_path):
            try:
                with open(self.metrics_path, 'r') as f:
                    data = json.load(f)
                return ExplanationMetrics(
                    total_scans=data.get("total_scans", 0),
                    scans_by_verdict=data.get("scans_by_verdict", {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING": 0}),
                    scans_with_complete_analysis=data.get("scans_with_complete_analysis", 0),
                    scans_with_incomplete_analysis=data.get("scans_with_incomplete_analysis", 0),
                    scans_with_allowlist_override=data.get("scans_with_allowlist_override", 0),
                    scans_without_allowlist_override=data.get("scans_without_allowlist_override", 0),
                    scans_by_drift_status=data.get("scans_by_drift_status", {"none": 0, "warning": 0, "significant": 0}),
                    total_risk_signals=data.get("total_risk_signals", 0),
                    total_positive_signals=data.get("total_positive_signals", 0),
                    total_inconclusive_signals=data.get("total_inconclusive_signals", 0),
                    top_risk_signals=data.get("top_risk_signals", {}),
                    top_inconclusive_checks=data.get("top_inconclusive_checks", {}),
                    collection_start=data.get("collection_start", datetime.now(timezone.utc).isoformat()),
                    last_updated=data.get("last_updated", "")
                )
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"[TELEMETRY] Could not load metrics: {e}, creating new")
        
        return ExplanationMetrics(
            collection_start=datetime.now(timezone.utc).isoformat()
        )
    
    def record(
        self,
        explanation: Dict[str, Any],
        verdict: str,
        drift_status: str = "none"
    ) -> None:
        """
        Record telemetry for a single explanation.
        
        SAFETY: This method is fail-safe and will not raise exceptions.
        
        Args:
            explanation: The explanation dict from decision_pipeline
            verdict: "SAFE", "SUSPICIOUS", or "PHISHING"
            drift_status: "none", "warning", or "significant"
        """
        try:
            with self._lock:
                self._record_unsafe(explanation, verdict, drift_status)
                
                # Periodic flush
                self._scan_count_since_flush += 1
                if self._scan_count_since_flush >= FLUSH_INTERVAL_SCANS:
                    self._flush_unsafe()
                    self._scan_count_since_flush = 0
                    
        except Exception as e:
            # SAFETY: Never crash on telemetry failure
            logger.warning(f"[TELEMETRY] Record failed (non-blocking): {e}")
    
    def _record_unsafe(
        self,
        explanation: Dict[str, Any],
        verdict: str,
        drift_status: str
    ) -> None:
        """
        Internal record logic (not thread-safe, called with lock held).
        """
        m = self.metrics
        
        # Core counters
        m.total_scans += 1
        
        # Verdict
        if verdict in m.scans_by_verdict:
            m.scans_by_verdict[verdict] += 1
        
        # Analysis completion
        if explanation.get("analysis_complete", True):
            m.scans_with_complete_analysis += 1
        else:
            m.scans_with_incomplete_analysis += 1
        
        # Allowlist
        if explanation.get("allowlist_override", False):
            m.scans_with_allowlist_override += 1
        else:
            m.scans_without_allowlist_override += 1
        
        # Drift
        if drift_status in m.scans_by_drift_status:
            m.scans_by_drift_status[drift_status] += 1
        
        # Signal counts
        risk_signals = explanation.get("risk", [])
        positive_signals = explanation.get("positive", [])
        inconclusive_signals = explanation.get("inconclusive", [])
        
        m.total_risk_signals += len(risk_signals)
        m.total_positive_signals += len(positive_signals)
        m.total_inconclusive_signals += len(inconclusive_signals)
        
        # Top signals (sanitized - extract only signal types, not values)
        for signal in risk_signals:
            signal_type = self._sanitize_signal(signal)
            if signal_type:
                m.top_risk_signals[signal_type] = m.top_risk_signals.get(signal_type, 0) + 1
        
        for signal in inconclusive_signals:
            signal_type = self._sanitize_signal(signal)
            if signal_type:
                m.top_inconclusive_checks[signal_type] = m.top_inconclusive_checks.get(signal_type, 0) + 1
        
        # Trim to top N
        m.top_risk_signals = self._trim_to_top_n(m.top_risk_signals, TOP_SIGNALS_LIMIT)
        m.top_inconclusive_checks = self._trim_to_top_n(m.top_inconclusive_checks, TOP_SIGNALS_LIMIT)
        
        # Update timestamp
        m.last_updated = datetime.now(timezone.utc).isoformat()
    
    def _sanitize_signal(self, signal: str) -> Optional[str]:
        """
        Extract signal type, removing any identifying information.
        
        Examples:
            "Domain age: 2 days" → "domain_age"
            "WHOIS lookup failed" → "whois_failed"
            "Using HTTPS" → "https_detected"
        """
        if not isinstance(signal, str):
            return None
        
        # Extract key phrase only (before any colon or specific value)
        signal_lower = signal.lower().strip()
        
        # Common signal patterns
        if "whois" in signal_lower and "failed" in signal_lower:
            return "whois_failed"
        elif "dns" in signal_lower and "failed" in signal_lower:
            return "dns_failed"
        elif "http" in signal_lower and "failed" in signal_lower:
            return "http_failed"
        elif "domain age" in signal_lower:
            return "domain_age"
        elif "https" in signal_lower:
            return "https_status"
        elif "ssl" in signal_lower or "certificate" in signal_lower:
            return "ssl_certificate"
        elif "trusted" in signal_lower or "allowlist" in signal_lower:
            return "trusted_domain"
        elif "redirect" in signal_lower:
            return "redirect_detected"
        elif "suspicious" in signal_lower:
            return "suspicious_pattern"
        elif "ip" in signal_lower and "address" in signal_lower:
            return "ip_address_pattern"
        elif "shortener" in signal_lower or "short" in signal_lower:
            return "url_shortener"
        elif "form" in signal_lower:
            return "form_detected"
        elif "iframe" in signal_lower:
            return "iframe_detected"
        else:
            # Generic category
            return "other_signal"
    
    def _trim_to_top_n(self, counter: Dict[str, int], n: int) -> Dict[str, int]:
        """Keep only top N items by count."""
        if len(counter) <= n:
            return counter
        sorted_items = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_items[:n])
    
    def _flush_unsafe(self) -> None:
        """Flush metrics to disk (not thread-safe)."""
        try:
            with open(self.metrics_path, 'w') as f:
                json.dump(self.metrics.to_dict(), f, indent=2)
            logger.debug("[TELEMETRY] Metrics flushed to disk")
        except IOError as e:
            logger.warning(f"[TELEMETRY] Flush failed: {e}")
    
    def flush(self) -> None:
        """Thread-safe flush to disk."""
        with self._lock:
            self._flush_unsafe()
    
    def _flush_on_exit(self) -> None:
        """Flush on process shutdown."""
        try:
            self.flush()
            logger.info("[TELEMETRY] Final flush completed on shutdown")
        except Exception as e:
            logger.warning(f"[TELEMETRY] Shutdown flush failed: {e}")
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get current metrics summary.
        
        Returns:
            Dict with key metrics for monitoring
        """
        with self._lock:
            m = self.metrics
            
            # Calculate rates
            total = m.total_scans or 1  # Avoid division by zero
            
            return {
                "total_scans": m.total_scans,
                "verdict_distribution": {
                    k: f"{v/total*100:.1f}%" for k, v in m.scans_by_verdict.items()
                },
                "incomplete_analysis_rate": f"{m.scans_with_incomplete_analysis/total*100:.1f}%",
                "allowlist_override_rate": f"{m.scans_with_allowlist_override/total*100:.1f}%",
                "drift_status_distribution": m.scans_by_drift_status,
                "avg_risk_signals_per_scan": round(m.total_risk_signals / total, 2),
                "top_risk_signals": list(m.top_risk_signals.keys())[:5],
                "top_inconclusive_checks": list(m.top_inconclusive_checks.keys())[:5],
                "collection_period": {
                    "start": m.collection_start,
                    "last_updated": m.last_updated
                }
            }
    
    def reset_metrics(self) -> None:
        """Reset all metrics (for testing or new collection period)."""
        with self._lock:
            self.metrics = ExplanationMetrics(
                collection_start=datetime.now(timezone.utc).isoformat()
            )
            self._flush_unsafe()


# ============================================================================
# SINGLETON INSTANCE
# ============================================================================

_telemetry_instance: Optional[ExplanationTelemetry] = None


def get_telemetry() -> ExplanationTelemetry:
    """Get or create the singleton telemetry instance."""
    global _telemetry_instance
    if _telemetry_instance is None:
        _telemetry_instance = ExplanationTelemetry()
    return _telemetry_instance


def record_explanation_telemetry(
    explanation: Dict[str, Any],
    verdict: str,
    drift_status: str = "none"
) -> None:
    """
    Convenience function to record telemetry.
    
    SAFETY: This function is fail-safe and will not raise exceptions.
    
    Records:
        1. Aggregate metrics (sync, batched flush)
        2. XAI audit log (async via QueueHandler - non-blocking)
    
    Args:
        explanation: The explanation dict from decision_pipeline
        verdict: "SAFE", "SUSPICIOUS", or "PHISHING"  
        drift_status: "none", "warning", or "significant"
    """
    try:
        # Record aggregate metrics (existing behavior)
        get_telemetry().record(explanation, verdict, drift_status)
        
        # Record async XAI audit log (non-blocking)
        top_features = [
            {"feature": f, "impact": "High"}
            for f in explanation.get("risk", [])[:3]
        ] or [
            {"feature": f, "impact": "Positive"}
            for f in explanation.get("positive", [])[:3]
        ]
        _record_audit_log(verdict, drift_status, top_features)
        
    except Exception as e:
        # NEVER crash on telemetry
        logger.warning(f"[TELEMETRY] Record failed (non-blocking): {e}")


# ============================================================================
# CLI
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Explanation Telemetry CLI")
    parser.add_argument("--summary", action="store_true", help="Show metrics summary")
    parser.add_argument("--reset", action="store_true", help="Reset metrics")
    parser.add_argument("--path", type=str, default=METRICS_FILE, help="Metrics file path")
    
    args = parser.parse_args()
    
    telemetry = ExplanationTelemetry(args.path)
    
    if args.summary:
        summary = telemetry.get_summary()
        print(json.dumps(summary, indent=2))
    
    elif args.reset:
        telemetry.reset_metrics()
        print("Metrics reset")
    
    else:
        parser.print_help()
