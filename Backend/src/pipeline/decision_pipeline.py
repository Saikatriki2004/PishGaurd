"""
Decision Pipeline - Central orchestrator for phishing detection.

This module enforces the COMPLETE decision pipeline in the EXACT order required:

1. URL validation (SSRF protection)
2. Trusted domain gate (PRE-ML) - BYPASSES ML for known-safe domains
3. Feature extraction with failure tracking
4. Network failure masking (neutral values)
5. Calibrated ML inference ONLY
6. Tri-state thresholds (SAFE/SUSPICIOUS/PHISHING)
7. Drift-aware confidence adjustment
8. Explanation generation

CRITICAL RULES:
- Trusted domains NEVER get phishing verdicts
- Network failures NEVER indicate phishing
- Only calibrated models are used
- Drift can only DOWNGRADE confidence
"""

import logging
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import numpy as np
from cachetools import TTLCache
from threading import Lock

from src.governance.trusted_domains import TrustedDomainChecker, TrustCheckResult
from src.features.feature_extractor import FeatureExtractor, FailureFlags
from src.training import model_trainer

# Lazy import for blocklist to avoid circular imports
def get_blocklist_checker():
    """Lazy load blocklist checker."""
    try:
        from src.governance.blocklist import is_blocked
        return is_blocked
    except ImportError:
        logger.warning("[PIPELINE] Blocklist module not available")
        return None

logger = logging.getLogger(__name__)

# ============================================================================
# ANALYSIS CACHE (P0 Speed Improvement)
# ============================================================================
# Cache analysis results for 1 hour to avoid re-analyzing the same URL
ANALYSIS_CACHE = TTLCache(maxsize=10000, ttl=3600)
CACHE_LOCK = Lock()


class Verdict(Enum):
    """Tri-state verdict for phishing detection."""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"


# ============================================================================
# DECISION THRESHOLDS (NON-NEGOTIABLE)
# ============================================================================
PHISHING_THRESHOLD = 0.85   # prob >= 0.85 → PHISHING
SUSPICIOUS_THRESHOLD = 0.55  # 0.55 <= prob < 0.85 → SUSPICIOUS
# prob < 0.55 → SAFE

# Maximum risk score for trusted domains
TRUSTED_DOMAIN_MAX_RISK = 30.0

# Confidence penalty for network failures
NETWORK_FAILURE_PENALTY = 0.15


@dataclass
class AnalysisResult:
    """Complete result from the decision pipeline."""
    
    # Core verdict
    verdict: Verdict
    risk_score: float  # 0-100 scale
    
    # Trust gate
    is_trusted_domain: bool
    trust_check: Optional[TrustCheckResult] = None
    
    # Feature data
    features: List[int] = field(default_factory=list)
    failure_flags: Optional[FailureFlags] = None
    
    # Explanations
    explanation: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    
    # Metadata
    url: str = ""
    ml_bypassed: bool = False
    calibrated_probability: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "verdict": self.verdict.value,
            "risk_score": round(self.risk_score, 1),
            "is_trusted_domain": self.is_trusted_domain,
            "trust_info": self.trust_check.to_dict() if self.trust_check else None,
            "features": self.features,
            "failure_report": self.failure_flags.to_dict() if self.failure_flags else None,
            "explanation": self.explanation,
            "warnings": self.warnings,
            "url": self.url,
            "ml_bypassed": self.ml_bypassed,
            "calibrated_probability": round(self.calibrated_probability, 4)
        }


class DecisionPipeline:
    """
    Central orchestrator enforcing the complete phishing detection pipeline.
    
    PIPELINE ORDER:
    1. URL validation
    2. Trusted domain gate (PRE-ML)
    3. Feature extraction
    4. Network failure masking
    5. Calibrated ML inference
    6. Tri-state thresholds
    7. Drift-aware adjustment
    8. Explanation generation
    """
    
    def __init__(self):
        """Initialize the decision pipeline."""
        self.trusted_checker = TrustedDomainChecker()
        
        # Load calibrated model (will fail if not calibrated)
        model_trainer.ensure_model_exists()
        self.model = model_trainer.load_model()
        self.feature_schema = model_trainer.get_feature_schema()
        
        logger.info("[PIPELINE] Decision pipeline initialized with calibrated model")
    
    def analyze(self, url: str, bypass_cache: bool = False) -> AnalysisResult:
        """
        Analyze a URL through the complete decision pipeline.
        
        Args:
            url: URL to analyze
            bypass_cache: If True, skip cache lookup (for fresh analysis)
            
        Returns:
            AnalysisResult with verdict, risk score, and explanations
        """
        # ================================================================
        # STEP 0: CACHE LOOKUP (P0 Speed Improvement)
        # ================================================================
        cache_key = hashlib.md5(url.lower().strip().encode()).hexdigest()
        
        if not bypass_cache:
            with CACHE_LOCK:
                if cache_key in ANALYSIS_CACHE:
                    cached = ANALYSIS_CACHE[cache_key]
                    logger.debug(f"[PIPELINE] Cache hit for {url}")
                    return cached
        
        result = AnalysisResult(
            verdict=Verdict.SAFE,
            risk_score=0.0,
            is_trusted_domain=False,
            url=url
        )
        
        # ================================================================
        # STEP 1: URL VALIDATION (handled by FeatureExtractor)
        # ================================================================
        # SSRF protection is in FeatureExtractor._validate_url()
        
        # ================================================================
        # STEP 2: TRUSTED DOMAIN GATE (PRE-ML)
        # ================================================================
        trust_result = self.trusted_checker.check(url)
        result.trust_check = trust_result
        result.is_trusted_domain = trust_result.is_trusted
        
        if trust_result.is_trusted:
            # CRITICAL: Skip ML entirely for trusted domains
            result.verdict = Verdict.SAFE
            result.risk_score = min(15.0, TRUSTED_DOMAIN_MAX_RISK)  # Very low risk
            result.ml_bypassed = True
            result.explanation = {
                "summary": f"This domain is on a trusted allowlist. ML checks were bypassed.",
                "positive": [trust_result.reason],
                "risk": [],  # NEVER shown for trusted domains
                "inconclusive": [],
                "analysis_complete": True,
                "allowlist_override": True
            }
            result.warnings = []
            
            logger.info(f"[PIPELINE] Trusted domain bypass: {url} → SAFE")
            return result
        
        # ================================================================
        # STEP 2.5: BLOCKLIST CHECK (EARLY EXIT)
        # ================================================================
        blocklist_check = get_blocklist_checker()
        if blocklist_check:
            try:
                block_result = blocklist_check(url)
                if block_result.is_blocked:
                    result.verdict = Verdict.PHISHING
                    result.risk_score = 95.0 if block_result.confidence > 0.9 else 85.0
                    result.ml_bypassed = True
                    result.explanation = {
                        "summary": "This URL is on a known phishing blocklist.",
                        "positive": [],
                        "risk": [f"Matched blocklist: {block_result.source}"],
                        "inconclusive": [],
                        "analysis_complete": True,
                        "allowlist_override": False,
                        "blocklist_match": True
                    }
                    
                    # Cache the result
                    with CACHE_LOCK:
                        ANALYSIS_CACHE[cache_key] = result
                    
                    logger.info(f"[PIPELINE] Blocklist hit: {url} -> PHISHING")
                    return result
            except Exception as e:
                logger.warning(f"[PIPELINE] Blocklist check failed: {e}")
        
        # ================================================================
        # STEP 3: FEATURE EXTRACTION
        # ================================================================
        try:
            extractor = FeatureExtractor(url)
            result.features = extractor.get_features()
            result.failure_flags = extractor.failure_flags
            
            # Get explanations from extractor
            feature_explanations = extractor.get_feature_explanations()
            
        except ValueError as e:
            # Invalid URL (SSRF blocked, etc.)
            result.verdict = Verdict.SUSPICIOUS
            result.risk_score = 50.0
            result.warnings.append(f"URL validation failed: {str(e)}")
            result.explanation = {
                "summary": "Could not analyze URL due to validation failure.",
                "positive": [],
                "risk": [f"URL validation failed: {str(e)}"],
                "inconclusive": ["Full URL analysis could not be completed"],
                "analysis_complete": False,
                "allowlist_override": False
            }
            return result
        
        # ================================================================
        # STEP 4: NETWORK FAILURE MASKING
        # ================================================================
        # Features already use 0 (neutral) for failures
        # Add failure indicators for the model
        failure_indicators = result.failure_flags.get_failure_indicators()
        features_with_indicators = result.features + failure_indicators
        
        # Track if significant failures occurred
        if result.failure_flags.any_failed():
            result.warnings.append(
                "Some security checks could not complete due to network issues. "
                "Analysis may be incomplete."
            )
        
        # ================================================================
        # STEP 5: CALIBRATED ML INFERENCE
        # ================================================================
        X = np.array(features_with_indicators).reshape(1, -1)
        
        # Get calibrated probability
        proba = self.model.predict_proba(X)[0]
        
        # proba[0] = P(class=-1) = P(phishing)
        # proba[1] = P(class=1) = P(legitimate)
        phishing_prob = proba[0] if self.model.classes_[0] == -1 else proba[1]
        result.calibrated_probability = phishing_prob
        
        # Convert to risk score (0-100)
        risk_score = phishing_prob * 100
        
        # ================================================================
        # STEP 6: TRI-STATE THRESHOLD APPLICATION
        # ================================================================
        if phishing_prob >= PHISHING_THRESHOLD:
            verdict = Verdict.PHISHING
        elif phishing_prob >= SUSPICIOUS_THRESHOLD:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.SAFE
        
        # ================================================================
        # STEP 7: DRIFT-AWARE CONFIDENCE ADJUSTMENT
        # ================================================================
        # Drift can only DOWNGRADE, never escalate
        confidence_penalty = 0.0
        
        # Apply penalty for network failures (uncertainty)
        if result.failure_flags.http_failed:
            confidence_penalty += NETWORK_FAILURE_PENALTY * 0.5
        if result.failure_flags.whois_failed:
            confidence_penalty += NETWORK_FAILURE_PENALTY * 0.3
        if result.failure_flags.dns_failed:
            confidence_penalty += NETWORK_FAILURE_PENALTY * 0.2
        
        # Adjust risk score (can only go DOWN for failures)
        if confidence_penalty > 0:
            # Reduce certainty of phishing verdict
            if verdict == Verdict.PHISHING:
                risk_score = risk_score * (1 - confidence_penalty)
                # Re-evaluate verdict after adjustment
                if risk_score / 100 < PHISHING_THRESHOLD:
                    verdict = Verdict.SUSPICIOUS
                    result.warnings.append(
                        "Verdict downgraded from PHISHING to SUSPICIOUS "
                        "due to incomplete analysis."
                    )
        
        result.verdict = verdict
        result.risk_score = risk_score
        
        # ================================================================
        # STEP 8: EXPLANATION GENERATION (Canonical Schema)
        # ================================================================
        # Convert feature explanations to canonical string arrays
        positive_signals = []
        risk_signals = []
        inconclusive_checks = []
        
        # Extract positive signals (safety indicators)
        for signal in feature_explanations.get("safe_signals", []):
            if isinstance(signal, dict):
                positive_signals.append(signal.get("description", signal.get("name", "Unknown safety indicator")))
            else:
                positive_signals.append(str(signal))
        
        # Extract risk signals (phishing indicators)
        for signal in feature_explanations.get("phishing_signals", []):
            if isinstance(signal, dict):
                risk_signals.append(signal.get("description", signal.get("name", "Unknown risk indicator")))
            else:
                risk_signals.append(str(signal))
        
        # Extract inconclusive checks (failed features)
        for feature in feature_explanations.get("failed_features", []):
            if isinstance(feature, dict):
                name = feature.get("name", "Unknown check")
                reason = feature.get("reason", "could not be completed")
                inconclusive_checks.append(f"{name}: {reason}")
            else:
                inconclusive_checks.append(str(feature))
        
        # Determine if analysis is complete
        analysis_complete = not result.failure_flags.any_failed() if result.failure_flags else True
        
        result.explanation = {
            "summary": self._generate_summary(verdict, risk_score, feature_explanations),
            "positive": positive_signals[:5],  # Max 5 items
            "risk": risk_signals[:5],  # Max 5 items
            "inconclusive": inconclusive_checks,
            "analysis_complete": analysis_complete,
            "allowlist_override": False
        }
        
        # ================================================================
        # STEP 9: SAFETY INVARIANT CHECK (FAIL-CLOSED)
        # ================================================================
        # Report verdict to governance controller
        # This will TRIGGER FREEZE if trusted domain gets PHISHING
        if result.is_trusted_domain:
            try:
                from src.governance.safety_governance import report_verdict_for_trusted_domain
                report_verdict_for_trusted_domain(
                    domain=result.trust_check.registered_domain if result.trust_check else url,
                    verdict=verdict.value,
                    risk_score=risk_score
                )
            except ImportError:
                # Safety governance not installed - log warning
                logger.warning("[PIPELINE] Safety governance module not available")
        
        logger.info(f"[PIPELINE] {url} → {verdict.value} ({risk_score:.1f}%)")
        
        # ================================================================
        # STEP 10: CACHE RESULT (P0 Speed Improvement)
        # ================================================================
        with CACHE_LOCK:
            ANALYSIS_CACHE[cache_key] = result
        
        return result
    
    def _generate_summary(
        self, 
        verdict: Verdict, 
        risk_score: float,
        explanations: Dict[str, Any]
    ) -> str:
        """Generate human-readable summary."""
        phishing_count = explanations.get("total_phishing", 0)
        safe_count = explanations.get("total_safe", 0)
        failed_count = explanations.get("total_failed", 0)
        
        if verdict == Verdict.SAFE:
            return (
                f"No significant phishing indicators detected. "
                f"Found {safe_count} safety indicators."
            )
        elif verdict == Verdict.SUSPICIOUS:
            return (
                f"Some concerning patterns detected ({phishing_count} warnings). "
                f"Exercise caution when visiting this site."
            )
        else:  # PHISHING
            return (
                f"Multiple phishing indicators detected ({phishing_count} warnings). "
                f"This site may be attempting to steal your information."
            )
    
    def get_risk_level_description(self, risk_score: float) -> str:
        """Get human-readable risk level."""
        if risk_score >= 85:
            return "Critical Risk"
        elif risk_score >= 70:
            return "High Risk"
        elif risk_score >= 55:
            return "Elevated Risk"
        elif risk_score >= 30:
            return "Low Risk"
        else:
            return "Minimal Risk"


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

_pipeline: Optional[DecisionPipeline] = None


def get_pipeline() -> DecisionPipeline:
    """Get or create the global decision pipeline instance."""
    global _pipeline
    if _pipeline is None:
        _pipeline = DecisionPipeline()
    return _pipeline


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Convenience function to analyze a URL.
    
    Returns a JSON-serializable dict with the analysis result.
    """
    pipeline = get_pipeline()
    result = pipeline.analyze(url)
    return result.to_dict()
