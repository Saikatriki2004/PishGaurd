"""
False-Positive Regression Test Suite

PURPOSE:
    Ensure that previously-fixed false positives (e.g., google.com) can NEVER reappear.
    Any trusted domain receiving a PHISHING verdict FAILS the entire test suite.

WHAT THIS FILE PROTECTS AGAINST:
    - Trusted domains being classified as PHISHING
    - Risk scores exceeding safe thresholds for allowlisted domains  
    - Risk signals being displayed for trusted domains
    - ML inference running when it should be bypassed
    - Look-alike domains bypassing security checks

CRITICAL INVARIANTS:
    1. Trusted domain → SAFE verdict (NEVER PHISHING)
    2. Trusted domain → risk_score ≤ 30.0
    3. Trusted domain → explanation.risk == []
    4. Trusted domain → ml_bypassed == True
    5. Look-alike domains → NOT trusted (ML must run)
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock
from dataclasses import dataclass
from typing import List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trusted_domains import TrustedDomainChecker, TrustCheckResult, TRUSTED_DOMAINS
from decision_pipeline import (
    DecisionPipeline, Verdict, AnalysisResult, 
    TRUSTED_DOMAIN_MAX_RISK, PHISHING_THRESHOLD, SUSPICIOUS_THRESHOLD
)


# ============================================================================
# REGRESSION DATASET: TRUSTED DOMAINS
# ============================================================================
# These domains MUST ALWAYS be classified as SAFE with low risk scores.
# If any test fails, the CI pipeline MUST block deployment.
# ============================================================================

TRUSTED_DOMAIN_TEST_CASES = [
    # Format: (url, expected_verdict, max_risk_score, description)
    
    # --- Major Tech Giants (Critical) ---
    ("https://google.com", Verdict.SAFE, 30.0, "Google main domain"),
    ("https://www.google.com", Verdict.SAFE, 30.0, "Google with www"),
    ("https://accounts.google.com", Verdict.SAFE, 30.0, "Google accounts subdomain"),
    ("https://mail.google.com", Verdict.SAFE, 30.0, "Gmail subdomain"),
    ("https://docs.google.com", Verdict.SAFE, 30.0, "Google Docs subdomain"),
    ("https://drive.google.com", Verdict.SAFE, 30.0, "Google Drive subdomain"),
    
    # --- Development Platforms (Critical for developers) ---
    ("https://github.com", Verdict.SAFE, 30.0, "GitHub main domain"),
    ("https://www.github.com", Verdict.SAFE, 30.0, "GitHub with www"),
    ("https://raw.githubusercontent.com", Verdict.SAFE, 30.0, "GitHub raw content"),
    ("https://gist.github.com", Verdict.SAFE, 30.0, "GitHub Gist subdomain"),
    
    # --- Microsoft Ecosystem ---
    ("https://microsoft.com", Verdict.SAFE, 30.0, "Microsoft main domain"),
    ("https://login.microsoftonline.com", Verdict.SAFE, 30.0, "Microsoft login"),
    ("https://outlook.com", Verdict.SAFE, 30.0, "Outlook main domain"),
    ("https://office.com", Verdict.SAFE, 30.0, "Office main domain"),
    
    # --- Amazon/AWS ---
    ("https://amazon.com", Verdict.SAFE, 30.0, "Amazon main domain"),
    ("https://www.amazon.com", Verdict.SAFE, 30.0, "Amazon with www"),
    ("https://aws.amazon.com", Verdict.SAFE, 30.0, "AWS subdomain"),
    
    # --- Social Media ---
    ("https://facebook.com", Verdict.SAFE, 30.0, "Facebook main domain"),
    ("https://www.facebook.com", Verdict.SAFE, 30.0, "Facebook with www"),
    ("https://linkedin.com", Verdict.SAFE, 30.0, "LinkedIn main domain"),
    ("https://twitter.com", Verdict.SAFE, 30.0, "Twitter main domain"),
    
    # --- Financial (High-risk for false positives) ---
    ("https://paypal.com", Verdict.SAFE, 30.0, "PayPal main domain"),
    ("https://stripe.com", Verdict.SAFE, 30.0, "Stripe main domain"),
]

GOVERNMENT_TLD_TEST_CASES = [
    # Format: (url, expected_verdict, max_risk_score, description)
    ("https://usa.gov", Verdict.SAFE, 30.0, "USA.gov - government TLD"),
    ("https://irs.gov", Verdict.SAFE, 30.0, "IRS - government TLD"),
    ("https://whitehouse.gov", Verdict.SAFE, 30.0, "White House - government TLD"),
]


# ============================================================================
# REGRESSION DATASET: LOOK-ALIKE DOMAINS (MUST FAIL TRUST CHECK)
# ============================================================================
# These domains look like trusted domains but are NOT. 
# The system MUST NOT trust them.
# ============================================================================

LOOK_ALIKE_DOMAINS = [
    # Format: (url, description)
    ("https://google.com.evil-site.xyz", "Google look-alike with malicious suffix"),
    ("https://github.com.login.badactor.ru", "GitHub phishing look-alike"),
    ("https://microsoft-login.com", "Microsoft typosquat"),
    ("https://g00gle.com", "Google homograph attack"),
    ("https://amaz0n.com", "Amazon typosquat with zero"),
    ("https://faceb00k.com", "Facebook typosquat"),
    ("https://paypa1.com", "PayPal typosquat with number 1"),
]


# ============================================================================
# REGRESSION DATASET: EDGE CASES
# ============================================================================
# These are legitimate sites that might trigger false positives due to
# network failures, unusual patterns, or incomplete analysis.
# ============================================================================

EDGE_CASE_SCENARIOS = [
    # Format: (scenario_name, mock_config, expected_max_verdict)
    ("redirect_heavy_site", {"redirect_count": 5}, Verdict.SUSPICIOUS),
    ("blocked_whois", {"whois_failed": True}, Verdict.SUSPICIOUS),
    ("blocked_http", {"http_failed": True}, Verdict.SUSPICIOUS),
    ("all_network_failed", {"http_failed": True, "whois_failed": True, "dns_failed": True}, Verdict.SUSPICIOUS),
]


# ============================================================================
# TEST FIXTURES
# ============================================================================

@pytest.fixture
def trusted_checker():
    """Create a TrustedDomainChecker instance for testing."""
    return TrustedDomainChecker()


@pytest.fixture
def mock_model():
    """
    Create a mock calibrated model that returns controlled probabilities.
    
    This mock ensures tests are deterministic and don't require actual ML inference.
    """
    mock = MagicMock()
    mock.classes_ = [-1, 1]  # -1 = phishing, 1 = legitimate
    # Default: return low phishing probability (0.3)
    mock.predict_proba.return_value = [[0.3, 0.7]]
    return mock


@pytest.fixture
def mock_feature_extractor():
    """
    Create a mock FeatureExtractor that returns neutral features.
    
    This prevents network calls during testing.
    """
    mock = MagicMock()
    mock.get_features.return_value = [0] * 30  # Neutral features
    mock.failure_flags = MagicMock()
    mock.failure_flags.http_failed = False
    mock.failure_flags.whois_failed = False
    mock.failure_flags.dns_failed = False
    mock.failure_flags.any_failed.return_value = False
    mock.failure_flags.get_failure_indicators.return_value = [0, 0, 0]
    mock.failure_flags.to_dict.return_value = {}
    mock.get_feature_explanations.return_value = {
        "safe_signals": [],
        "phishing_signals": [],
        "failed_features": [],
        "total_phishing": 0,
        "total_safe": 0,
        "total_failed": 0
    }
    return mock


# ============================================================================
# PART 1: TRUSTED DOMAIN VERDICT TESTS
# ============================================================================

class TestTrustedDomainVerdicts:
    """
    Test that all trusted domains receive SAFE verdicts.
    
    CRITICAL: If ANY test in this class fails, deployment MUST be blocked.
    """
    
    @pytest.mark.parametrize("url,expected_verdict,max_risk,description", TRUSTED_DOMAIN_TEST_CASES)
    def test_trusted_domain_verdict(self, url, expected_verdict, max_risk, description, mock_model, mock_feature_extractor):
        """
        Test that trusted domains ALWAYS receive SAFE verdict.
        
        PROTECTS AGAINST: Trusted domains being classified as PHISHING/SUSPICIOUS.
        """
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze(url)
            
            # CRITICAL ASSERTION: Verdict must be SAFE
            assert result.verdict == expected_verdict, (
                f"REGRESSION FAILURE: {description}\n"
                f"URL: {url}\n"
                f"Expected: {expected_verdict.value}\n"
                f"Got: {result.verdict.value}\n"
                f"This is a CRITICAL safety violation!"
            )
    
    @pytest.mark.parametrize("url,expected_verdict,max_risk,description", TRUSTED_DOMAIN_TEST_CASES)
    def test_trusted_domain_risk_cap(self, url, expected_verdict, max_risk, description, mock_model, mock_feature_extractor):
        """
        Test that trusted domains have risk scores ≤ 30%.
        
        PROTECTS AGAINST: High risk scores on legitimate sites causing user alarm.
        """
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze(url)
            
            assert result.risk_score <= max_risk, (
                f"REGRESSION FAILURE: {description}\n"
                f"URL: {url}\n"
                f"Expected risk ≤ {max_risk}%\n"
                f"Got: {result.risk_score}%\n"
                f"Trusted domains must have low risk scores!"
            )
    
    @pytest.mark.parametrize("url,expected_verdict,max_risk,description", TRUSTED_DOMAIN_TEST_CASES)
    def test_trusted_domain_no_risk_signals(self, url, expected_verdict, max_risk, description, mock_model, mock_feature_extractor):
        """
        Test that trusted domains show NO risk signals in explanation.
        
        PROTECTS AGAINST: Displaying scary warnings on legitimate sites.
        """
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze(url)
            
            risk_signals = result.explanation.get("risk", [])
            assert len(risk_signals) == 0, (
                f"REGRESSION FAILURE: {description}\n"
                f"URL: {url}\n"
                f"Expected NO risk signals for trusted domain\n"
                f"Got: {risk_signals}\n"
                f"Trusted domains must never display risk signals!"
            )
    
    @pytest.mark.parametrize("url,expected_verdict,max_risk,description", TRUSTED_DOMAIN_TEST_CASES)
    def test_trusted_domain_ml_bypassed(self, url, expected_verdict, max_risk, description, mock_model, mock_feature_extractor):
        """
        Test that ML inference is bypassed for trusted domains.
        
        PROTECTS AGAINST: Unnecessary ML calls and potential false positives from model.
        """
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze(url)
            
            assert result.ml_bypassed == True, (
                f"REGRESSION FAILURE: {description}\n"
                f"URL: {url}\n"
                f"Expected ml_bypassed=True\n"
                f"Got: ml_bypassed={result.ml_bypassed}\n"
                f"Trusted domains must bypass ML inference!"
            )
    
    @pytest.mark.parametrize("url,expected_verdict,max_risk,description", TRUSTED_DOMAIN_TEST_CASES)
    def test_trusted_domain_allowlist_override(self, url, expected_verdict, max_risk, description, mock_model, mock_feature_extractor):
        """
        Test that trusted domains have allowlist_override flag set.
        
        PROTECTS AGAINST: UI not showing trust indicator to users.
        """
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze(url)
            
            allowlist_override = result.explanation.get("allowlist_override", False)
            assert allowlist_override == True, (
                f"REGRESSION FAILURE: {description}\n"
                f"URL: {url}\n"
                f"Expected allowlist_override=True\n"
                f"Got: allowlist_override={allowlist_override}"
            )


class TestGovernmentTLDs:
    """
    Test that government TLDs (.gov) are trusted.
    
    CRITICAL: Government sites often have patterns that trigger ML false positives.
    """
    
    @pytest.mark.parametrize("url,expected_verdict,max_risk,description", GOVERNMENT_TLD_TEST_CASES)
    def test_gov_tld_trusted(self, url, expected_verdict, max_risk, description, mock_model, mock_feature_extractor):
        """
        Test that .gov TLDs receive SAFE verdict via TLD-based trust.
        
        PROTECTS AGAINST: Government sites being flagged as phishing.
        """
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze(url)
            
            assert result.verdict == expected_verdict, (
                f"REGRESSION FAILURE: {description}\n"
                f"URL: {url}\n"
                f"Government TLDs must be trusted!\n"
                f"Expected: {expected_verdict.value}\n"
                f"Got: {result.verdict.value}"
            )


# ============================================================================
# PART 2: LOOK-ALIKE DOMAIN TESTS (MUST FAIL TRUST)
# ============================================================================

class TestLookAlikeDomains:
    """
    Test that look-alike domains are NOT trusted.
    
    CRITICAL: Phishers often use domains that look like trusted ones.
    The system MUST detect these and NOT trust them.
    """
    
    @pytest.mark.parametrize("url,description", LOOK_ALIKE_DOMAINS)
    def test_look_alike_not_trusted(self, url, description, trusted_checker):
        """
        Test that look-alike domains fail the trust check.
        
        PROTECTS AGAINST: Phishing domains bypassing security via name confusion.
        """
        result = trusted_checker.check(url)
        
        assert result.is_trusted == False, (
            f"SECURITY FAILURE: {description}\n"
            f"URL: {url}\n"
            f"This domain MUST NOT be trusted!\n"
            f"Matched domain: {result.matched_domain}"
        )
    
    @pytest.mark.parametrize("url,description", LOOK_ALIKE_DOMAINS)
    def test_look_alike_triggers_ml(self, url, description, mock_model, mock_feature_extractor):
        """
        Test that look-alike domains go through ML analysis.
        
        PROTECTS AGAINST: Phishing sites bypassing ML entirely.
        """
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_feature_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze(url)
            
            # For look-alike domains, ML should NOT be bypassed
            assert result.ml_bypassed == False, (
                f"SECURITY FAILURE: {description}\n"
                f"URL: {url}\n"
                f"Look-alike domains MUST go through ML analysis!\n"
                f"ml_bypassed should be False"
            )


# ============================================================================
# PART 3: EDGE CASE TESTS
# ============================================================================

class TestEdgeCases:
    """
    Test edge cases: network failures, redirects, partial analysis.
    
    These cases MUST NOT result in PHISHING verdicts due to incomplete data.
    """
    
    def test_network_failure_not_phishing(self, mock_model):
        """
        Test that network failures don't escalate to PHISHING.
        
        PROTECTS AGAINST: Blocking legitimate sites due to transient network issues.
        """
        # Create mock with all network failures
        mock_extractor = MagicMock()
        mock_extractor.get_features.return_value = [0] * 30
        mock_extractor.failure_flags = MagicMock()
        mock_extractor.failure_flags.http_failed = True
        mock_extractor.failure_flags.whois_failed = True
        mock_extractor.failure_flags.dns_failed = True
        mock_extractor.failure_flags.any_failed.return_value = True
        mock_extractor.failure_flags.get_failure_indicators.return_value = [1, 1, 1]
        mock_extractor.failure_flags.to_dict.return_value = {
            "http_failed": True,
            "whois_failed": True,
            "dns_failed": True
        }
        mock_extractor.get_feature_explanations.return_value = {
            "safe_signals": [],
            "phishing_signals": [],
            "failed_features": [
                {"name": "HTTP check", "reason": "Connection timeout"},
                {"name": "WHOIS lookup", "reason": "Server unavailable"},
                {"name": "DNS resolution", "reason": "Timeout"}
            ],
            "total_phishing": 0,
            "total_safe": 0,
            "total_failed": 3
        }
        
        # Model returns high phishing probability (would normally be PHISHING)
        mock_model.predict_proba.return_value = [[0.90, 0.10]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://example.com")
            
            # Due to network failures, PHISHING should be downgraded
            # Note: The actual behavior depends on implementation, 
            # but it should NOT be PHISHING with high confidence when analysis is incomplete
            assert result.verdict in [Verdict.SAFE, Verdict.SUSPICIOUS], (
                f"Network failures should not result in PHISHING verdict!\n"
                f"Got: {result.verdict.value}\n"
                f"Incomplete analysis must be treated conservatively."
            )
    
    def test_inconclusive_checks_displayed(self, mock_model):
        """
        Test that failed checks appear in inconclusive list.
        
        PROTECTS AGAINST: Users not knowing analysis was incomplete.
        """
        mock_extractor = MagicMock()
        mock_extractor.get_features.return_value = [0] * 30
        mock_extractor.failure_flags = MagicMock()
        mock_extractor.failure_flags.http_failed = True
        mock_extractor.failure_flags.whois_failed = False
        mock_extractor.failure_flags.dns_failed = False
        mock_extractor.failure_flags.any_failed.return_value = True
        mock_extractor.failure_flags.get_failure_indicators.return_value = [1, 0, 0]
        mock_extractor.failure_flags.to_dict.return_value = {"http_failed": True}
        mock_extractor.get_feature_explanations.return_value = {
            "safe_signals": [],
            "phishing_signals": [],
            "failed_features": [
                {"name": "HTTP content analysis", "reason": "Connection refused"}
            ],
            "total_phishing": 0,
            "total_safe": 0,
            "total_failed": 1
        }
        
        mock_model.predict_proba.return_value = [[0.40, 0.60]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_extractor
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://example.com")
            
            inconclusive = result.explanation.get("inconclusive", [])
            assert len(inconclusive) > 0, (
                "Failed checks must appear in inconclusive list!\n"
                "Users need to know when analysis is incomplete."
            )
            
            analysis_complete = result.explanation.get("analysis_complete", True)
            assert analysis_complete == False, (
                "analysis_complete must be False when checks failed!"
            )


# ============================================================================
# PART 4: SAFETY INVARIANT TESTS
# ============================================================================

class TestSafetyInvariants:
    """
    Test fundamental safety invariants that must NEVER be violated.
    
    These are the absolute non-negotiables of the system.
    """
    
    def test_trusted_domain_never_phishing(self, mock_model):
        """
        CRITICAL TEST: A trusted domain must NEVER receive PHISHING verdict,
        regardless of what the model predicts.
        
        This test simulates a scenario where the ML model predicts high
        phishing probability, but the domain is trusted.
        """
        # Model predicts 95% phishing (very high)
        mock_model.predict_proba.return_value = [[0.95, 0.05]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            
            # Even with high phishing prediction, google.com MUST be SAFE
            result = pipeline.analyze("https://google.com")
            
            assert result.verdict == Verdict.SAFE, (
                "CRITICAL SAFETY VIOLATION!\n"
                "Trusted domain received PHISHING verdict!\n"
                f"URL: google.com\n"
                f"Verdict: {result.verdict.value}\n"
                "This MUST NEVER happen in production!"
            )
            
            assert result.ml_bypassed == True, (
                "CRITICAL SAFETY VIOLATION!\n"
                "ML should be bypassed for trusted domains!"
            )
    
    def test_model_never_called_for_trusted(self, mock_model):
        """
        Test that model.predict_proba is NEVER called for trusted domains.
        
        PROTECTS AGAINST: ML interference with trust decisions.
        """
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://google.com")
            
            # Model should NOT have been called
            mock_model.predict_proba.assert_not_called()
    
    def test_risk_score_capped_for_trusted(self, mock_model):
        """
        Test that risk scores are always capped at TRUSTED_DOMAIN_MAX_RISK for trusted domains.
        """
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            
            for domain in ["google.com", "github.com", "microsoft.com"]:
                result = pipeline.analyze(f"https://{domain}")
                assert result.risk_score <= TRUSTED_DOMAIN_MAX_RISK, (
                    f"Risk score {result.risk_score} exceeds max {TRUSTED_DOMAIN_MAX_RISK} for {domain}"
                )


# ============================================================================
# PART 5: ALLOWLIST COMPLETENESS TESTS
# ============================================================================

class TestAllowlistCompleteness:
    """
    Test that critical domains are in the allowlist.
    
    PROTECTS AGAINST: Major sites being incorrectly flagged.
    """
    
    CRITICAL_DOMAINS = [
        "google.com",
        "github.com",
        "microsoft.com",
        "amazon.com",
        "facebook.com",
        "apple.com",
        "netflix.com",
        "paypal.com",
        "linkedin.com",
        "twitter.com",
        "youtube.com",
        "wikipedia.org",
    ]
    
    def test_critical_domains_in_allowlist(self, trusted_checker):
        """
        Test that all critical domains are in the trusted allowlist.
        """
        for domain in self.CRITICAL_DOMAINS:
            result = trusted_checker.check(domain)
            assert result.is_trusted == True, (
                f"CRITICAL DOMAIN MISSING FROM ALLOWLIST!\n"
                f"Domain: {domain}\n"
                f"This domain MUST be in TRUSTED_DOMAINS!"
            )


# ============================================================================
# FAIL-FAST ASSERTIONS
# ============================================================================

def pytest_configure(config):
    """
    Configure pytest to fail fast on critical tests.
    """
    config.addinivalue_line(
        "markers", "critical: mark test as critical safety test"
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
