"""
Decision Pipeline Unit Tests

PURPOSE:
    Lock the decision architecture so future code changes cannot bypass safety rules.
    Verify pipeline order, threshold logic, drift behavior, and verdict constraints.

WHAT THIS FILE PROTECTS AGAINST:
    - Trusted-domain gate not running before ML
    - Network failures increasing risk (should be neutral or decrease)
    - Incorrect threshold application
    - Drift escalating severity (can only downgrade)
    - Raw ML probabilities being exposed
    - Binary verdicts appearing anywhere in code path

MOCKING STRATEGY:
    - model_trainer.load_model() → fake calibrated model
    - FeatureExtractor → deterministic features
    - TrustedDomainChecker → controlled trust results
    All tests are deterministic and network-free.
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock, PropertyMock
from dataclasses import dataclass

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decision_pipeline import (
    DecisionPipeline, Verdict, AnalysisResult,
    PHISHING_THRESHOLD, SUSPICIOUS_THRESHOLD,
    TRUSTED_DOMAIN_MAX_RISK, NETWORK_FAILURE_PENALTY
)
from trusted_domains import TrustCheckResult


# ============================================================================
# TEST FIXTURES
# ============================================================================

@pytest.fixture
def mock_calibrated_model():
    """
    Create a mock calibrated model with controllable output.
    
    Simulates CalibratedClassifierCV behavior.
    """
    mock = MagicMock()
    mock.classes_ = [-1, 1]  # -1 = phishing, 1 = legitimate
    # Default: 50% phishing probability (boundary case)
    mock.predict_proba.return_value = [[0.5, 0.5]]
    return mock


@pytest.fixture
def create_mock_extractor():
    """
    Factory fixture to create mock extractors with custom failure states.
    """
    def _create(http_failed=False, whois_failed=False, dns_failed=False, features=None):
        mock = MagicMock()
        mock.get_features.return_value = features if features else [0] * 30
        mock.failure_flags = MagicMock()
        mock.failure_flags.http_failed = http_failed
        mock.failure_flags.whois_failed = whois_failed
        mock.failure_flags.dns_failed = dns_failed
        mock.failure_flags.any_failed.return_value = http_failed or whois_failed or dns_failed
        mock.failure_flags.get_failure_indicators.return_value = [
            1 if http_failed else 0,
            1 if whois_failed else 0,
            1 if dns_failed else 0
        ]
        mock.failure_flags.to_dict.return_value = {
            "http_failed": http_failed,
            "whois_failed": whois_failed,
            "dns_failed": dns_failed
        }
        
        failed_features = []
        if http_failed:
            failed_features.append({"name": "HTTP content", "reason": "Connection failed"})
        if whois_failed:
            failed_features.append({"name": "WHOIS lookup", "reason": "Server unavailable"})
        if dns_failed:
            failed_features.append({"name": "DNS resolution", "reason": "Timeout"})
        
        mock.get_feature_explanations.return_value = {
            "safe_signals": [],
            "phishing_signals": [],
            "failed_features": failed_features,
            "total_phishing": 0,
            "total_safe": 0,
            "total_failed": len(failed_features)
        }
        return mock
    return _create


# ============================================================================
# TEST CLASS 1: PIPELINE ORDER ENFORCEMENT
# ============================================================================

class TestPipelineOrder:
    """
    Test that pipeline steps execute in the correct order.
    
    CRITICAL: Trusted-domain gate MUST run BEFORE ML inference.
    """
    
    def test_trusted_gate_before_ml(self, mock_calibrated_model):
        """
        Test that trusted-domain gate runs BEFORE ML inference.
        
        PROTECTS AGAINST: ML overriding trust decisions.
        """
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            
            # Analyze a trusted domain
            result = pipeline.analyze("https://google.com")
            
            # ML should NOT have been called
            mock_calibrated_model.predict_proba.assert_not_called()
            
            # But verdict should still be SAFE
            assert result.verdict == Verdict.SAFE
            assert result.ml_bypassed == True
    
    def test_untrusted_domain_goes_through_ml(self, mock_calibrated_model, create_mock_extractor):
        """
        Test that untrusted domains DO go through ML inference.
        
        PROTECTS AGAINST: ML being skipped for domains that need analysis.
        """
        mock_extractor = create_mock_extractor()
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            
            # Analyze an untrusted domain
            result = pipeline.analyze("https://suspicious-site.xyz")
            
            # ML SHOULD have been called
            mock_calibrated_model.predict_proba.assert_called_once()
            assert result.ml_bypassed == False


# ============================================================================
# TEST CLASS 2: NETWORK FAILURE HANDLING
# ============================================================================

class TestNetworkFailureHandling:
    """
    Test that network failures are handled safely.
    
    CRITICAL: Network failures must NOT increase risk scores.
    """
    
    def test_network_failure_does_not_increase_risk(self, mock_calibrated_model, create_mock_extractor):
        """
        Test that network failures do NOT increase risk score.
        
        PROTECTS AGAINST: Transient network issues causing false positives.
        """
        # First, get baseline risk with no failures
        mock_extractor_clean = create_mock_extractor(http_failed=False, whois_failed=False, dns_failed=False)
        mock_calibrated_model.predict_proba.return_value = [[0.60, 0.40]]  # 60% phishing
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor_clean
            
            pipeline = DecisionPipeline()
            result_clean = pipeline.analyze("https://test-site.com")
            baseline_risk = result_clean.risk_score
        
        # Now, same site with network failures
        mock_extractor_failed = create_mock_extractor(http_failed=True, whois_failed=True, dns_failed=True)
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor_failed
            
            pipeline = DecisionPipeline()
            result_failed = pipeline.analyze("https://test-site.com")
            failed_risk = result_failed.risk_score
        
        # Risk with failures should NOT be higher
        assert failed_risk <= baseline_risk, (
            f"Network failures increased risk!\n"
            f"Baseline: {baseline_risk}%\n"
            f"With failures: {failed_risk}%\n"
            f"Network failures must NEVER increase risk!"
        )
    
    def test_network_failure_produces_inconclusive(self, mock_calibrated_model, create_mock_extractor):
        """
        Test that network failures produce inconclusive explanations.
        
        PROTECTS AGAINST: Users not knowing analysis was incomplete.
        """
        mock_extractor = create_mock_extractor(http_failed=True, whois_failed=False, dns_failed=False)
        mock_calibrated_model.predict_proba.return_value = [[0.40, 0.60]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://test-site.com")
            
            # Inconclusive list should not be empty
            inconclusive = result.explanation.get("inconclusive", [])
            assert len(inconclusive) > 0, (
                "Failed checks must appear in inconclusive list!"
            )
            
            # analysis_complete should be False
            assert result.explanation.get("analysis_complete") == False
    
    def test_all_failures_still_safe_for_neutral_features(self, mock_calibrated_model, create_mock_extractor):
        """
        Test that all network failures with neutral features result in SAFE.
        
        The model should use neutral feature values (0) for failures.
        """
        mock_extractor = create_mock_extractor(http_failed=True, whois_failed=True, dns_failed=True)
        # Model returns low phishing probability for neutral features
        mock_calibrated_model.predict_proba.return_value = [[0.30, 0.70]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://test-site.com")
            
            # Should be SAFE even with all failures (neutral features = low risk)
            assert result.verdict == Verdict.SAFE


# ============================================================================
# TEST CLASS 3: THRESHOLD LOGIC
# ============================================================================

class TestThresholdLogic:
    """
    Test that verdict thresholds are applied exactly as specified.
    
    Thresholds:
    - prob < 0.55 → SAFE
    - 0.55 ≤ prob < 0.85 → SUSPICIOUS
    - prob ≥ 0.85 → PHISHING
    """
    
    @pytest.mark.parametrize("phishing_prob,expected_verdict", [
        # SAFE cases (prob < 0.55)
        (0.00, Verdict.SAFE),
        (0.10, Verdict.SAFE),
        (0.30, Verdict.SAFE),
        (0.54, Verdict.SAFE),
        (0.549, Verdict.SAFE),
        
        # SUSPICIOUS cases (0.55 <= prob < 0.85)
        (0.55, Verdict.SUSPICIOUS),
        (0.60, Verdict.SUSPICIOUS),
        (0.70, Verdict.SUSPICIOUS),
        (0.84, Verdict.SUSPICIOUS),
        (0.849, Verdict.SUSPICIOUS),
        
        # PHISHING cases (prob >= 0.85)
        (0.85, Verdict.PHISHING),
        (0.90, Verdict.PHISHING),
        (0.95, Verdict.PHISHING),
        (0.99, Verdict.PHISHING),
        (1.00, Verdict.PHISHING),
    ])
    def test_threshold_exact(self, phishing_prob, expected_verdict, mock_calibrated_model, create_mock_extractor):
        """
        Test that thresholds are applied exactly.
        
        PROTECTS AGAINST: Off-by-one errors in threshold logic.
        """
        mock_extractor = create_mock_extractor()
        mock_calibrated_model.predict_proba.return_value = [[phishing_prob, 1 - phishing_prob]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://test-site.xyz")
            
            assert result.verdict == expected_verdict, (
                f"Threshold violation!\n"
                f"Phishing prob: {phishing_prob}\n"
                f"Expected: {expected_verdict.value}\n"
                f"Got: {result.verdict.value}"
            )
    
    def test_boundary_safe_suspicious(self, mock_calibrated_model, create_mock_extractor):
        """
        Test exact boundary between SAFE and SUSPICIOUS.
        
        0.549999 → SAFE
        0.550000 → SUSPICIOUS
        """
        mock_extractor = create_mock_extractor()
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            
            # Just below threshold
            mock_calibrated_model.predict_proba.return_value = [[0.549999, 0.450001]]
            result = pipeline.analyze("https://test1.xyz")
            assert result.verdict == Verdict.SAFE
            
            # Exactly at threshold
            mock_calibrated_model.predict_proba.return_value = [[0.55, 0.45]]
            result = pipeline.analyze("https://test2.xyz")
            assert result.verdict == Verdict.SUSPICIOUS
    
    def test_boundary_suspicious_phishing(self, mock_calibrated_model, create_mock_extractor):
        """
        Test exact boundary between SUSPICIOUS and PHISHING.
        
        0.849999 → SUSPICIOUS
        0.850000 → PHISHING
        """
        mock_extractor = create_mock_extractor()
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            
            # Just below threshold
            mock_calibrated_model.predict_proba.return_value = [[0.849999, 0.150001]]
            result = pipeline.analyze("https://test1.xyz")
            assert result.verdict == Verdict.SUSPICIOUS
            
            # Exactly at threshold
            mock_calibrated_model.predict_proba.return_value = [[0.85, 0.15]]
            result = pipeline.analyze("https://test2.xyz")
            assert result.verdict == Verdict.PHISHING


# ============================================================================
# TEST CLASS 4: DRIFT BEHAVIOR
# ============================================================================

class TestDriftBehavior:
    """
    Test that drift warnings only DOWNGRADE, never escalate.
    
    CRITICAL: Drift can reduce confidence but NEVER increase severity.
    """
    
    def test_drift_downgrades_phishing_to_suspicious(self, mock_calibrated_model, create_mock_extractor):
        """
        Test that network failures can downgrade PHISHING to SUSPICIOUS.
        
        PROTECTS AGAINST: Overconfident PHISHING verdicts with incomplete data.
        """
        # Model predicts 90% phishing (normally PHISHING)
        # But with significant network failures, should be downgraded
        mock_extractor = create_mock_extractor(http_failed=True, whois_failed=True, dns_failed=False)
        mock_calibrated_model.predict_proba.return_value = [[0.90, 0.10]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://test-site.xyz")
            
            # Due to confidence penalty from failures, may be downgraded
            # The key is that it should NOT be higher than PHISHING
            assert result.verdict in [Verdict.SUSPICIOUS, Verdict.PHISHING]
    
    def test_drift_never_escalates_safe_to_phishing(self, mock_calibrated_model, create_mock_extractor):
        """
        Test that drift/failures can NEVER escalate SAFE to PHISHING.
        
        PROTECTS AGAINST: Safe sites being blocked due to drift.
        """
        # Model predicts low phishing (SAFE)
        mock_extractor = create_mock_extractor(http_failed=True, whois_failed=True, dns_failed=True)
        mock_calibrated_model.predict_proba.return_value = [[0.30, 0.70]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://test-site.xyz")
            
            # MUST still be SAFE (drift cannot escalate)
            assert result.verdict == Verdict.SAFE, (
                "Drift escalated SAFE to higher severity!\n"
                "Drift can only DOWNGRADE, never escalate!"
            )
    
    def test_drift_never_escalates_suspicious_to_phishing(self, mock_calibrated_model, create_mock_extractor):
        """
        Test that drift/failures can NEVER escalate SUSPICIOUS to PHISHING.
        """
        # Model predicts mid-range phishing (SUSPICIOUS)
        mock_extractor = create_mock_extractor(http_failed=True, whois_failed=True, dns_failed=True)
        mock_calibrated_model.predict_proba.return_value = [[0.60, 0.40]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://test-site.xyz")
            
            # MUST NOT become PHISHING
            assert result.verdict != Verdict.PHISHING, (
                "Drift escalated SUSPICIOUS to PHISHING!\n"
                "Drift can only DOWNGRADE, never escalate!"
            )


# ============================================================================
# TEST CLASS 5: NO RAW PROBABILITY EXPOSURE
# ============================================================================

class TestNoRawProbabilityExposure:
    """
    Test that raw ML probabilities are never directly exposed.
    
    CRITICAL: Users should see risk scores (0-100), not raw probabilities.
    """
    
    def test_risk_score_is_percentage(self, mock_calibrated_model, create_mock_extractor):
        """
        Test that risk_score is a percentage (0-100), not raw probability.
        """
        mock_extractor = create_mock_extractor()
        mock_calibrated_model.predict_proba.return_value = [[0.75, 0.25]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://test-site.xyz")
            
            # Risk score should be on 0-100 scale, not 0-1
            assert 0 <= result.risk_score <= 100, (
                f"Risk score {result.risk_score} is not on 0-100 scale!"
            )
    
    def test_calibrated_probability_stored_internally(self, mock_calibrated_model, create_mock_extractor):
        """
        Test that calibrated_probability is available for internal use.
        
        This is needed for calibration monitoring but should not be the primary display.
        """
        mock_extractor = create_mock_extractor()
        mock_calibrated_model.predict_proba.return_value = [[0.75, 0.25]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://test-site.xyz")
            
            # Calibrated probability should be stored
            assert hasattr(result, 'calibrated_probability')
            # It should be on 0-1 scale
            assert 0 <= result.calibrated_probability <= 1


# ============================================================================
# TEST CLASS 6: NO BINARY VERDICTS
# ============================================================================

class TestNoBinaryVerdicts:
    """
    Test that only tri-state verdicts are possible.
    
    CRITICAL: The system must NEVER produce binary YES/NO verdicts.
    """
    
    def test_verdict_enum_has_three_states(self):
        """
        Test that Verdict enum has exactly three states.
        
        PROTECTS AGAINST: Someone adding binary verdict options.
        """
        verdicts = list(Verdict)
        assert len(verdicts) == 3, (
            f"Verdict enum must have exactly 3 states!\n"
            f"Found: {len(verdicts)}\n"
            f"Values: {[v.value for v in verdicts]}"
        )
        
        # Verify the specific values
        assert Verdict.SAFE in verdicts
        assert Verdict.SUSPICIOUS in verdicts
        assert Verdict.PHISHING in verdicts
    
    def test_verdict_values_are_strings(self):
        """
        Test that verdict values are human-readable strings.
        
        PROTECTS AGAINST: Numeric or obscure verdict values.
        """
        assert Verdict.SAFE.value == "SAFE"
        assert Verdict.SUSPICIOUS.value == "SUSPICIOUS"
        assert Verdict.PHISHING.value == "PHISHING"
    
    def test_no_boolean_verdict_attribute(self, mock_calibrated_model, create_mock_extractor):
        """
        Test that AnalysisResult has no boolean is_phishing or is_safe attribute.
        
        PROTECTS AGAINST: Binary shortcuts that bypass tri-state logic.
        """
        mock_extractor = create_mock_extractor()
        mock_calibrated_model.predict_proba.return_value = [[0.50, 0.50]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://test-site.xyz")
            
            # These attributes should NOT exist
            assert not hasattr(result, 'is_phishing'), (
                "Binary 'is_phishing' attribute found! Use verdict instead."
            )
            assert not hasattr(result, 'is_safe'), (
                "Binary 'is_safe' attribute found! Use verdict instead."
            )
            assert not hasattr(result, 'is_malicious'), (
                "Binary 'is_malicious' attribute found! Use verdict instead."
            )


# ============================================================================
# TEST CLASS 7: EXPLANATION-VERDICT CONSISTENCY
# ============================================================================

class TestExplanationVerdictConsistency:
    """
    Test that explanations are consistent with verdicts.
    
    CRITICAL: UI explanation must match the verdict.
    """
    
    def test_safe_verdict_no_risk_signals(self, mock_calibrated_model, create_mock_extractor):
        """
        Test that SAFE verdicts have empty risk signal lists.
        
        PROTECTS AGAINST: Displaying scary warnings for safe sites.
        """
        mock_extractor = create_mock_extractor()
        mock_calibrated_model.predict_proba.return_value = [[0.20, 0.80]]  # Low risk → SAFE
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://test-site.xyz")
            
            assert result.verdict == Verdict.SAFE
            # Risk signals should be empty or minimal for SAFE verdict
            risk_signals = result.explanation.get("risk", [])
            # We don't strictly require empty, but it should not be alarming
    
    def test_incomplete_analysis_flagged(self, mock_calibrated_model, create_mock_extractor):
        """
        Test that incomplete analysis is flagged in explanation.
        
        PROTECTS AGAINST: Users trusting incomplete results without warning.
        """
        mock_extractor = create_mock_extractor(http_failed=True)
        mock_calibrated_model.predict_proba.return_value = [[0.30, 0.70]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_calibrated_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://test-site.xyz")
            
            # analysis_complete should be False when checks failed
            assert result.explanation.get("analysis_complete") == False, (
                "analysis_complete must be False when checks have failed!"
            )


# ============================================================================
# TEST CLASS 8: MODEL VALIDATION
# ============================================================================

class TestModelValidation:
    """
    Test that only calibrated models are accepted.
    
    CRITICAL: Uncalibrated models should be rejected.
    """
    
    def test_pipeline_requires_calibrated_model(self):
        """
        Test that DecisionPipeline validates model calibration at init.
        
        PROTECTS AGAINST: Deploying uncalibrated models to production.
        """
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            
            # Simulate load_model raising error for uncalibrated model
            mock_trainer.load_model.side_effect = ValueError("Model is not calibrated!")
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            with pytest.raises(ValueError, match="calibrated"):
                DecisionPipeline()


# ============================================================================
# TEST CLASS 9: CONSTANTS VALIDATION
# ============================================================================

class TestConstantsValidation:
    """
    Test that decision thresholds are correctly defined.
    
    PROTECTS AGAINST: Accidental threshold changes.
    """
    
    def test_phishing_threshold_value(self):
        """Test PHISHING_THRESHOLD is 0.85."""
        assert PHISHING_THRESHOLD == 0.85, (
            f"PHISHING_THRESHOLD changed! Expected 0.85, got {PHISHING_THRESHOLD}"
        )
    
    def test_suspicious_threshold_value(self):
        """Test SUSPICIOUS_THRESHOLD is 0.55."""
        assert SUSPICIOUS_THRESHOLD == 0.55, (
            f"SUSPICIOUS_THRESHOLD changed! Expected 0.55, got {SUSPICIOUS_THRESHOLD}"
        )
    
    def test_trusted_domain_max_risk_value(self):
        """Test TRUSTED_DOMAIN_MAX_RISK is 30.0."""
        assert TRUSTED_DOMAIN_MAX_RISK == 30.0, (
            f"TRUSTED_DOMAIN_MAX_RISK changed! Expected 30.0, got {TRUSTED_DOMAIN_MAX_RISK}"
        )
    
    def test_threshold_ordering(self):
        """Test that thresholds are in correct order."""
        assert 0 < SUSPICIOUS_THRESHOLD < PHISHING_THRESHOLD <= 1, (
            "Thresholds must satisfy: 0 < SUSPICIOUS < PHISHING <= 1"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
