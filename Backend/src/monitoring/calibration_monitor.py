"""
Calibration Monitoring Module

PURPOSE:
    Ensure that "Risk Assessment" percentages remain meaningful over time.
    Monitor model calibration and detect drift that could lead to unreliable predictions.

WHAT THIS MODULE PROVIDES:
    1. Training-time calibration metrics (Brier score, reliability curve)
    2. Runtime drift detection (overconfidence, probability collapse)
    3. Health status API for monitoring systems

CALIBRATION HEALTH STATES:
    - healthy: Calibration metrics are within acceptable ranges
    - degraded: Metrics show significant drift, confidence should be reduced
    - unknown: No baseline metrics available, cannot assess health

SECURITY IMPLICATIONS:
    - Degraded calibration can ONLY downgrade confidence
    - Degraded calibration can NEVER escalate severity
    - Unknown calibration displays uncertainty warning
"""

import json
import os
import logging
import numpy as np
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================

# Brier score thresholds
BRIER_SCORE_HEALTHY_MAX = 0.25  # Below this is healthy
BRIER_SCORE_DEGRADED_MAX = 0.35  # Above this is critically degraded

# Calibration error thresholds (mean absolute deviation from perfect calibration)
CALIBRATION_ERROR_HEALTHY_MAX = 0.10
CALIBRATION_ERROR_DEGRADED_MAX = 0.20

# Probability collapse detection
COLLAPSE_VARIANCE_THRESHOLD = 0.01  # If variance < this, probabilities have collapsed
COLLAPSE_EXTREME_THRESHOLD = 0.95  # If > 80% of probs are above this or below 0.05

# Number of bins for reliability curve
NUM_RELIABILITY_BINS = 10

# Default metrics file path
DEFAULT_METRICS_PATH = "calibration_metrics.json"


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ReliabilityCurve:
    """
    Reliability curve data for calibration visualization.
    
    A perfectly calibrated model has observed_frequency == expected_confidence for each bin.
    """
    bins: List[float] = field(default_factory=list)  # Bin upper bounds [0.1, 0.2, ..., 1.0]
    observed_frequency: List[float] = field(default_factory=list)  # Actual positive rate in each bin
    expected_confidence: List[float] = field(default_factory=list)  # Mean predicted probability in each bin
    samples_per_bin: List[int] = field(default_factory=list)  # Number of samples in each bin
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CalibrationMetrics:
    """
    Complete calibration metrics for a model.
    """
    # Health status
    calibration_status: str = "unknown"  # "healthy", "degraded", "unknown"
    
    # Core metrics
    brier_score: float = 0.0
    calibration_error: float = 0.0  # Mean absolute calibration error
    
    # Reliability curve
    reliability_curve: Optional[ReliabilityCurve] = None
    
    # Metadata
    timestamp: str = ""
    model_version: str = ""
    sample_count: int = 0
    
    # Thresholds used (for transparency)
    thresholds: Dict[str, float] = field(default_factory=dict)
    
    # Warnings
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "calibration_status": self.calibration_status,
            "brier_score": round(self.brier_score, 4),
            "calibration_error": round(self.calibration_error, 4),
            "reliability_curve": self.reliability_curve.to_dict() if self.reliability_curve else None,
            "timestamp": self.timestamp,
            "model_version": self.model_version,
            "sample_count": self.sample_count,
            "thresholds": self.thresholds,
            "warnings": self.warnings
        }
        return result


# ============================================================================
# CALIBRATION MONITOR CLASS
# ============================================================================

class CalibrationMonitor:
    """
    Monitor model calibration and detect drift.
    
    USAGE:
        # During training:
        monitor = CalibrationMonitor()
        metrics = monitor.compute_calibration_metrics(y_true, y_prob)
        monitor.save_metrics(metrics)
        
        # At runtime:
        health = monitor.check_calibration_health()
        if health == "degraded":
            # Apply confidence penalty
    """
    
    def __init__(self, metrics_path: str = DEFAULT_METRICS_PATH):
        """
        Initialize the calibration monitor.
        
        Args:
            metrics_path: Path to the calibration metrics JSON file
        """
        self.metrics_path = metrics_path
        self._cached_metrics: Optional[CalibrationMetrics] = None
        logger.info(f"[CALIBRATION] Monitor initialized with metrics path: {metrics_path}")
    
    def compute_calibration_metrics(
        self, 
        y_true: np.ndarray, 
        y_prob: np.ndarray,
        model_version: str = "2.0"
    ) -> CalibrationMetrics:
        """
        Compute comprehensive calibration metrics from predictions and labels.
        
        This should be called during training/validation to establish baseline.
        
        Args:
            y_true: True binary labels (0 or 1, where 1 = phishing)
            y_prob: Predicted probabilities for the positive class (phishing)
            model_version: Version string for the model
            
        Returns:
            CalibrationMetrics with all computed values
        """
        y_true = np.asarray(y_true).flatten()
        y_prob = np.asarray(y_prob).flatten()
        
        if len(y_true) != len(y_prob):
            raise ValueError("y_true and y_prob must have the same length")
        
        if len(y_true) == 0:
            logger.warning("[CALIBRATION] Empty arrays provided, returning unknown status")
            return CalibrationMetrics(
                calibration_status="unknown",
                timestamp=datetime.now(timezone.utc).isoformat(),
                model_version=model_version,
                warnings=["No samples provided for calibration"]
            )
        
        # Compute Brier score
        # Brier score = mean((predicted_prob - actual_outcome)^2)
        brier_score = float(np.mean((y_prob - y_true) ** 2))
        
        # Compute reliability curve
        reliability_curve = self._compute_reliability_curve(y_true, y_prob)
        
        # Compute mean absolute calibration error
        calibration_error = self._compute_calibration_error(reliability_curve)
        
        # Determine health status
        status, warnings = self._determine_health_status(brier_score, calibration_error, y_prob)
        
        metrics = CalibrationMetrics(
            calibration_status=status,
            brier_score=brier_score,
            calibration_error=calibration_error,
            reliability_curve=reliability_curve,
            timestamp=datetime.now(timezone.utc).isoformat(),
            model_version=model_version,
            sample_count=len(y_true),
            thresholds={
                "brier_score_healthy_max": BRIER_SCORE_HEALTHY_MAX,
                "brier_score_degraded_max": BRIER_SCORE_DEGRADED_MAX,
                "calibration_error_healthy_max": CALIBRATION_ERROR_HEALTHY_MAX,
                "calibration_error_degraded_max": CALIBRATION_ERROR_DEGRADED_MAX,
                "collapse_variance_threshold": COLLAPSE_VARIANCE_THRESHOLD
            },
            warnings=warnings
        )
        
        logger.info(f"[CALIBRATION] Computed metrics: status={status}, brier={brier_score:.4f}, error={calibration_error:.4f}")
        return metrics
    
    def _compute_reliability_curve(
        self, 
        y_true: np.ndarray, 
        y_prob: np.ndarray
    ) -> ReliabilityCurve:
        """
        Compute binned reliability curve.
        
        Divides predictions into NUM_RELIABILITY_BINS bins and computes
        the observed frequency vs expected confidence in each bin.
        """
        bins = np.linspace(0, 1, NUM_RELIABILITY_BINS + 1)
        bin_uppers = bins[1:].tolist()
        
        observed_frequency = []
        expected_confidence = []
        samples_per_bin = []
        
        for i in range(NUM_RELIABILITY_BINS):
            lower = bins[i]
            upper = bins[i + 1]
            
            # Find samples in this bin
            if i == NUM_RELIABILITY_BINS - 1:
                # Last bin includes upper bound
                mask = (y_prob >= lower) & (y_prob <= upper)
            else:
                mask = (y_prob >= lower) & (y_prob < upper)
            
            bin_true = y_true[mask]
            bin_prob = y_prob[mask]
            
            n_samples = len(bin_true)
            samples_per_bin.append(n_samples)
            
            if n_samples > 0:
                observed_frequency.append(float(np.mean(bin_true)))
                expected_confidence.append(float(np.mean(bin_prob)))
            else:
                observed_frequency.append(0.0)
                expected_confidence.append((lower + upper) / 2)
        
        return ReliabilityCurve(
            bins=bin_uppers,
            observed_frequency=observed_frequency,
            expected_confidence=expected_confidence,
            samples_per_bin=samples_per_bin
        )
    
    def _compute_calibration_error(self, reliability_curve: ReliabilityCurve) -> float:
        """
        Compute mean absolute calibration error from reliability curve.
        
        This is the weighted mean absolute difference between observed and expected.
        """
        total_samples = sum(reliability_curve.samples_per_bin)
        if total_samples == 0:
            return 0.0
        
        weighted_error = 0.0
        for i in range(len(reliability_curve.bins)):
            n = reliability_curve.samples_per_bin[i]
            if n > 0:
                error = abs(
                    reliability_curve.observed_frequency[i] - 
                    reliability_curve.expected_confidence[i]
                )
                weighted_error += n * error
        
        return weighted_error / total_samples
    
    def _determine_health_status(
        self, 
        brier_score: float, 
        calibration_error: float,
        y_prob: np.ndarray
    ) -> Tuple[str, List[str]]:
        """
        Determine overall calibration health status.
        
        Returns:
            Tuple of (status, warnings)
        """
        warnings = []
        
        # Check for probability collapse
        prob_variance = float(np.var(y_prob))
        extreme_ratio = float(np.mean((y_prob < 0.05) | (y_prob > 0.95)))
        
        if prob_variance < COLLAPSE_VARIANCE_THRESHOLD:
            warnings.append(f"Probability collapse detected: variance={prob_variance:.4f}")
            return "degraded", warnings
        
        if extreme_ratio > 0.80:
            warnings.append(f"Extreme probability concentration: {extreme_ratio*100:.1f}% at extremes")
            return "degraded", warnings
        
        # Check Brier score
        if brier_score > BRIER_SCORE_DEGRADED_MAX:
            warnings.append(f"Brier score critically high: {brier_score:.4f} > {BRIER_SCORE_DEGRADED_MAX}")
            return "degraded", warnings
        
        if brier_score > BRIER_SCORE_HEALTHY_MAX:
            warnings.append(f"Brier score elevated: {brier_score:.4f} > {BRIER_SCORE_HEALTHY_MAX}")
        
        # Check calibration error
        if calibration_error > CALIBRATION_ERROR_DEGRADED_MAX:
            warnings.append(f"Calibration error critically high: {calibration_error:.4f}")
            return "degraded", warnings
        
        if calibration_error > CALIBRATION_ERROR_HEALTHY_MAX:
            warnings.append(f"Calibration error elevated: {calibration_error:.4f}")
        
        # Determine final status
        if brier_score <= BRIER_SCORE_HEALTHY_MAX and calibration_error <= CALIBRATION_ERROR_HEALTHY_MAX:
            return "healthy", warnings
        else:
            # Elevated but not critically degraded
            warnings.append("Calibration metrics are elevated but within acceptable range")
            return "healthy", warnings
    
    def save_metrics(self, metrics: CalibrationMetrics, path: Optional[str] = None) -> None:
        """
        Save calibration metrics to JSON file.
        
        Args:
            metrics: CalibrationMetrics to save
            path: Optional path override (uses self.metrics_path by default)
        """
        save_path = path or self.metrics_path
        
        with open(save_path, 'w') as f:
            json.dump(metrics.to_dict(), f, indent=2)
        
        logger.info(f"[CALIBRATION] Saved metrics to {save_path}")
    
    def load_metrics(self, path: Optional[str] = None) -> Optional[CalibrationMetrics]:
        """
        Load calibration metrics from JSON file.
        
        Args:
            path: Optional path override (uses self.metrics_path by default)
            
        Returns:
            CalibrationMetrics if file exists and is valid, None otherwise
        """
        load_path = path or self.metrics_path
        
        if not os.path.exists(load_path):
            logger.warning(f"[CALIBRATION] Metrics file not found: {load_path}")
            return None
        
        try:
            with open(load_path, 'r') as f:
                data = json.load(f)
            
            # Reconstruct reliability curve
            reliability_data = data.get("reliability_curve")
            reliability_curve = None
            if reliability_data:
                reliability_curve = ReliabilityCurve(**reliability_data)
            
            metrics = CalibrationMetrics(
                calibration_status=data.get("calibration_status", "unknown"),
                brier_score=data.get("brier_score", 0.0),
                calibration_error=data.get("calibration_error", 0.0),
                reliability_curve=reliability_curve,
                timestamp=data.get("timestamp", ""),
                model_version=data.get("model_version", ""),
                sample_count=data.get("sample_count", 0),
                thresholds=data.get("thresholds", {}),
                warnings=data.get("warnings", [])
            )
            
            self._cached_metrics = metrics
            return metrics
            
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"[CALIBRATION] Error loading metrics: {e}")
            return None
    
    def check_calibration_health(self) -> str:
        """
        Get the current calibration health status.
        
        Returns:
            "healthy", "degraded", or "unknown"
            
        IMPORTANT:
            - degraded: Apply confidence penalty, NEVER escalate severity
            - unknown: Display uncertainty warning, NEVER escalate severity
        """
        if self._cached_metrics is None:
            self._cached_metrics = self.load_metrics()
        
        if self._cached_metrics is None:
            return "unknown"
        
        return self._cached_metrics.calibration_status
    
    def detect_overconfidence_drift(self, recent_probs: np.ndarray) -> bool:
        """
        Detect if recent predictions show overconfidence drift.
        
        Overconfidence: model predicts probabilities near 0 or 1 too frequently.
        
        Args:
            recent_probs: Array of recent prediction probabilities
            
        Returns:
            True if overconfidence drift is detected
        """
        if len(recent_probs) < 10:
            return False  # Not enough data
        
        recent_probs = np.asarray(recent_probs)
        
        # Check if too many predictions are at extremes
        extreme_count = np.sum((recent_probs < 0.05) | (recent_probs > 0.95))
        extreme_ratio = extreme_count / len(recent_probs)
        
        if extreme_ratio > 0.80:
            logger.warning(f"[CALIBRATION] Overconfidence drift detected: {extreme_ratio*100:.1f}% extreme predictions")
            return True
        
        return False
    
    def detect_probability_collapse(self, recent_probs: np.ndarray) -> bool:
        """
        Detect if predictions have collapsed to a single value.
        
        Collapse: model always predicts the same probability (no discrimination).
        
        Args:
            recent_probs: Array of recent prediction probabilities
            
        Returns:
            True if probability collapse is detected
        """
        if len(recent_probs) < 10:
            return False  # Not enough data
        
        recent_probs = np.asarray(recent_probs)
        variance = np.var(recent_probs)
        
        if variance < COLLAPSE_VARIANCE_THRESHOLD:
            logger.warning(f"[CALIBRATION] Probability collapse detected: variance={variance:.6f}")
            return True
        
        return False
    
    def get_confidence_penalty(self) -> float:
        """
        Get the confidence penalty to apply based on calibration health.
        
        Returns:
            Float between 0.0 (no penalty) and 0.3 (max penalty)
            
        CRITICAL: This penalty can only REDUCE confidence, never increase it.
        """
        status = self.check_calibration_health()
        
        if status == "healthy":
            return 0.0
        elif status == "degraded":
            return 0.20  # 20% confidence reduction
        else:  # unknown
            return 0.10  # 10% confidence reduction for uncertainty
    
    def get_calibration_report(self) -> Dict[str, Any]:
        """
        Get a full calibration report for monitoring/debugging.
        
        Returns:
            Dict with all calibration information
        """
        metrics = self._cached_metrics
        if metrics is None:
            metrics = self.load_metrics()
        
        if metrics is None:
            return {
                "status": "unknown",
                "message": "No calibration metrics available",
                "penalty": self.get_confidence_penalty(),
                "recommendations": ["Run model training to generate calibration metrics"]
            }
        
        report = metrics.to_dict()
        report["penalty"] = self.get_confidence_penalty()
        
        # Add recommendations
        recommendations = []
        if metrics.calibration_status == "degraded":
            recommendations.append("Consider retraining the model with fresh data")
            recommendations.append("Review feature distribution for drift")
        
        if metrics.warnings:
            recommendations.extend(metrics.warnings)
        
        report["recommendations"] = recommendations
        return report


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

_default_monitor: Optional[CalibrationMonitor] = None


def get_calibration_monitor() -> CalibrationMonitor:
    """Get the default CalibrationMonitor instance."""
    global _default_monitor
    if _default_monitor is None:
        _default_monitor = CalibrationMonitor()
    return _default_monitor


def get_calibration_status() -> str:
    """Convenience function to get current calibration status."""
    return get_calibration_monitor().check_calibration_health()


def get_calibration_penalty() -> float:
    """Convenience function to get current confidence penalty."""
    return get_calibration_monitor().get_confidence_penalty()


# ============================================================================
# MAIN EXECUTION (for generating initial metrics)
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Calibration Monitor CLI")
    parser.add_argument("--generate-example", action="store_true", 
                        help="Generate example calibration metrics file")
    parser.add_argument("--check-health", action="store_true",
                        help="Check current calibration health")
    parser.add_argument("--path", type=str, default=DEFAULT_METRICS_PATH,
                        help="Path to metrics file")
    
    args = parser.parse_args()
    
    monitor = CalibrationMonitor(args.path)
    
    if args.generate_example:
        print("[*] Generating example calibration metrics...")
        
        # Generate synthetic data for demonstration
        np.random.seed(42)
        n_samples = 1000
        
        # Simulate reasonably calibrated predictions
        y_true = np.random.binomial(1, 0.3, n_samples)  # 30% positive rate
        
        # Add some noise to predictions to simulate calibration
        y_prob = np.clip(
            y_true + np.random.normal(0, 0.2, n_samples),
            0.01, 0.99
        )
        
        metrics = monitor.compute_calibration_metrics(y_true, y_prob, model_version="2.0")
        monitor.save_metrics(metrics)
        
        print(f"[+] Metrics saved to {args.path}")
        print(f"[+] Status: {metrics.calibration_status}")
        print(f"[+] Brier Score: {metrics.brier_score:.4f}")
        print(f"[+] Calibration Error: {metrics.calibration_error:.4f}")
        
    elif args.check_health:
        status = monitor.check_calibration_health()
        penalty = monitor.get_confidence_penalty()
        
        print(f"[*] Calibration Status: {status}")
        print(f"[*] Confidence Penalty: {penalty:.0%}")
        
        report = monitor.get_calibration_report()
        if report.get("recommendations"):
            print("\n[!] Recommendations:")
            for rec in report["recommendations"]:
                print(f"    - {rec}")
    
    else:
        parser.print_help()
