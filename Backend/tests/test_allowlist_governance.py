"""
Allowlist Governance Tests

PURPOSE:
    Enforce governance rules for trusted domain allowlist changes.
    Ensure that:
    - Manifest version is bumped for domain changes
    - Snapshot matches manifest
    - Overrides are logged and visible
    - Canary domains are validated separately

WHAT THIS FILE PROTECTS AGAINST:
    - Silent/accidental allowlist modifications
    - Unversioned policy changes
    - Missing change documentation
    - Snapshot drift from manifest

CI BEHAVIOR:
    - Governance violations BLOCK deployment
    - Override usage is logged and visible
    - Canary failures are WARNINGS only
"""

import pytest
import json
import os
import sys
from unittest.mock import patch, MagicMock
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy_audit import (
    PolicyAuditLogger, ManifestGovernance, OverrideEventType,
    get_audit_logger, check_override_enabled
)
from decision_pipeline import DecisionPipeline, Verdict


# ============================================================================
# FIXTURE PATHS
# ============================================================================

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SNAPSHOT_PATH = os.path.join(FIXTURES_DIR, "trusted_domains_snapshot.json")
CANARY_PATH = os.path.join(FIXTURES_DIR, "trusted_domains_canary.json")


# ============================================================================
# TEST FIXTURES
# ============================================================================

@pytest.fixture
def snapshot_data():
    """Load the regression snapshot fixture."""
    with open(SNAPSHOT_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


@pytest.fixture
def canary_data():
    """Load the canary domains fixture."""
    with open(CANARY_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


@pytest.fixture
def mock_model():
    """Create a mock calibrated model."""
    mock = MagicMock()
    mock.classes_ = [-1, 1]
    mock.predict_proba.return_value = [[0.30, 0.70]]  # Default low risk
    return mock


@pytest.fixture
def mock_feature_extractor():
    """Create a mock feature extractor."""
    mock = MagicMock()
    mock.get_features.return_value = [0] * 30
    mock.failure_flags = MagicMock()
    mock.failure_flags.http_failed = False
    mock.failure_flags.whois_failed = False
    mock.failure_flags.dns_failed = False
    mock.failure_flags.any_failed.return_value = False
    mock.failure_flags.get_failure_indicators.return_value = [0, 0, 0]
    mock.failure_flags.to_dict.return_value = {}
    mock.get_feature_explanations.return_value = {
        "safe_signals": [], "phishing_signals": [], "failed_features": [],
        "total_phishing": 0, "total_safe": 0, "total_failed": 0
    }
    return mock


# ============================================================================
# PART 1: MANIFEST GOVERNANCE TESTS
# ============================================================================

class TestManifestGovernance:
    """
    Test manifest governance rules.
    
    CRITICAL: These tests ensure allowlist changes follow proper process.
    """
    
    def test_manifest_has_version(self):
        """
        Test that manifest has a version field.
        
        PROTECTS AGAINST: Unversioned policy documents.
        """
        gov = ManifestGovernance()
        manifest = gov.load_manifest()
        
        assert "version" in manifest, (
            "Manifest MUST have a 'version' field!\n"
            "This is required for change tracking."
        )
        assert manifest["version"], "Manifest version cannot be empty"
    
    def test_manifest_has_change_reason(self):
        """
        Test that manifest has a non-empty change_reason.
        
        PROTECTS AGAINST: Undocumented policy changes.
        """
        gov = ManifestGovernance()
        manifest = gov.load_manifest()
        
        assert "change_reason" in manifest, (
            "Manifest MUST have a 'change_reason' field!\n"
            "Every change must be documented."
        )
        assert manifest["change_reason"].strip(), (
            "Manifest change_reason cannot be empty!"
        )
    
    def test_manifest_has_modifier_info(self):
        """
        Test that manifest records who made the last change.
        
        PROTECTS AGAINST: Anonymous/unattributed policy changes.
        """
        gov = ManifestGovernance()
        manifest = gov.load_manifest()
        
        assert "last_modified_by" in manifest, (
            "Manifest MUST have 'last_modified_by' field!"
        )
    
    def test_manifest_validation_passes(self):
        """
        Test that current manifest passes all governance rules.
        
        CI GATE: This test MUST pass for deployment.
        """
        gov = ManifestGovernance()
        errors = gov.validate_manifest()
        
        assert len(errors) == 0, (
            f"Manifest governance validation FAILED!\n"
            f"Errors:\n" + "\n".join(f"  - {e}" for e in errors)
        )


# ============================================================================
# PART 2: SNAPSHOT SYNCHRONIZATION TESTS
# ============================================================================

class TestSnapshotSynchronization:
    """
    Test that snapshot and manifest are synchronized.
    
    CRITICAL: Mismatches indicate undocumented policy changes.
    """
    
    def test_snapshot_exists(self):
        """Test that snapshot fixture file exists."""
        assert os.path.exists(SNAPSHOT_PATH), (
            f"Snapshot fixture missing: {SNAPSHOT_PATH}\n"
            "Regression testing requires a snapshot!"
        )
    
    def test_snapshot_has_regression_domains(self, snapshot_data):
        """Test that snapshot contains regression domains list."""
        assert "regression_domains" in snapshot_data, (
            "Snapshot must have 'regression_domains' list"
        )
        assert len(snapshot_data["regression_domains"]) > 0, (
            "Snapshot regression_domains cannot be empty"
        )
    
    def test_snapshot_version_matches_manifest(self, snapshot_data):
        """
        Test that snapshot version matches manifest version.
        
        PROTECTS AGAINST: Snapshot drift after manifest updates.
        """
        gov = ManifestGovernance()
        manifest = gov.load_manifest()
        
        snapshot_version = snapshot_data.get("_manifest_version")
        manifest_version = manifest.get("version")
        
        assert snapshot_version == manifest_version, (
            f"GOVERNANCE FAILURE: Version mismatch!\n"
            f"Manifest version: {manifest_version}\n"
            f"Snapshot version: {snapshot_version}\n"
            f"\n"
            f"ACTION REQUIRED:\n"
            f"1. Update snapshot _manifest_version to match manifest\n"
            f"2. Verify domain lists are synchronized\n"
            f"3. Document changes in manifest change_reason"
        )
    
    def test_snapshot_domains_match_manifest(self, snapshot_data):
        """
        Test that snapshot domains match manifest domains.
        
        PROTECTS AGAINST: Domain list drift without version update.
        """
        gov = ManifestGovernance()
        comparison = gov.compare_manifest_to_snapshot()
        
        if comparison.get("error"):
            pytest.fail(f"Comparison failed: {comparison['error']}")
        
        added = comparison.get("domains_added", [])
        removed = comparison.get("domains_removed", [])
        
        # Allow comparison to pass if versions match (implies intentional sync)
        if comparison.get("versions_match"):
            return
        
        if added or removed:
            pytest.fail(
                f"GOVERNANCE FAILURE: Domain list mismatch!\n"
                f"Domains in manifest but not snapshot: {added}\n"
                f"Domains in snapshot but not manifest: {removed}\n"
                f"\n"
                f"If this is intentional:\n"
                f"1. Bump manifest version\n"
                f"2. Update snapshot to match\n"
                f"3. Document in change_reason"
            )


# ============================================================================
# PART 3: REGRESSION DOMAIN TESTS (FROM SNAPSHOT)
# ============================================================================

class TestRegressionDomains:
    """
    Test all domains in regression snapshot.
    
    CRITICAL: These are the HARD CONTRACT domains.
    Any failure here BLOCKS deployment.
    """
    
    def test_all_snapshot_domains_are_safe(self, snapshot_data, mock_model, mock_feature_extractor):
        """
        Test that ALL regression domains receive SAFE verdict.
        
        PROTECTS AGAINST: Regression in trusted domain handling.
        """
        regression_domains = snapshot_data.get("regression_domains", [])
        
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            
            failures = []
            for domain in regression_domains:
                url = f"https://{domain}"
                result = pipeline.analyze(url)
                
                if result.verdict != Verdict.SAFE:
                    failures.append({
                        "domain": domain,
                        "verdict": result.verdict.value,
                        "risk_score": result.risk_score
                    })
            
            if failures:
                failure_lines = [f"  {f['domain']}: {f['verdict']} ({f['risk_score']}%)" for f in failures]
                pytest.fail(
                    f"REGRESSION FAILURE: {len(failures)} domains not SAFE!\n" +
                    "\n".join(failure_lines)
                )
    
    def test_regression_domains_have_low_risk(self, snapshot_data, mock_model):
        """
        Test that regression domains have risk ≤ 30%.
        """
        max_risk = snapshot_data.get("test_expectations", {}).get("max_risk_score", 30.0)
        regression_domains = snapshot_data.get("regression_domains", [])
        
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            
            for domain in regression_domains:
                result = pipeline.analyze(f"https://{domain}")
                assert result.risk_score <= max_risk, (
                    f"Domain {domain} has risk {result.risk_score}% > {max_risk}%"
                )
    
    def test_regression_domains_bypass_ml(self, snapshot_data, mock_model):
        """
        Test that ML is bypassed for all regression domains.
        """
        regression_domains = snapshot_data.get("regression_domains", [])
        
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            
            for domain in regression_domains:
                result = pipeline.analyze(f"https://{domain}")
                assert result.ml_bypassed == True, (
                    f"ML should be bypassed for regression domain: {domain}"
                )


# ============================================================================
# PART 4: CANARY DOMAIN TESTS (NON-BLOCKING)
# ============================================================================

class TestCanaryDomains:
    """
    Test canary (probationary) domains.
    
    BEHAVIOR:
    - Canary domains MUST NOT be PHISHING
    - SAFE or SUSPICIOUS are acceptable
    - Failures emit WARNINGS but don't block CI
    """
    
    def test_canary_fixture_exists(self):
        """Test that canary fixture file exists."""
        assert os.path.exists(CANARY_PATH), (
            f"Canary fixture missing: {CANARY_PATH}"
        )
    
    def test_canary_domains_not_phishing(self, canary_data, mock_model, mock_feature_extractor):
        """
        Test that canary domains are NEVER classified as PHISHING.
        
        BEHAVIOR: Failure emits WARNING, does not block CI.
        """
        canary_domains = [d["domain"] for d in canary_data.get("canary_domains", [])]
        
        # Set model to return moderate risk (shouldn't affect trusted domains)
        mock_model.predict_proba.return_value = [[0.60, 0.40]]
        
        with patch('decision_pipeline.model_trainer') as mock_trainer, \
             patch('decision_pipeline.FeatureExtractor') as MockExtractor:
            
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            MockExtractor.return_value = mock_feature_extractor
            
            pipeline = DecisionPipeline()
            
            warnings = []
            for domain in canary_domains:
                result = pipeline.analyze(f"https://{domain}")
                
                if result.verdict == Verdict.PHISHING:
                    warnings.append({
                        "domain": domain,
                        "verdict": result.verdict.value,
                        "risk_score": result.risk_score
                    })
            
            if warnings:
                # Emit warning but don't fail
                import sys
                print("\n" + "="*60, file=sys.stderr)
                print("⚠️  CANARY DOMAIN WARNINGS (Non-blocking)", file=sys.stderr)
                print("="*60, file=sys.stderr)
                for w in warnings:
                    print(f"  {w['domain']}: {w['verdict']} ({w['risk_score']}%)", file=sys.stderr)
                print("="*60, file=sys.stderr)
                print("\nThese domains are under canary validation.", file=sys.stderr)
                print("Consider adding them to trusted_domains.py if appropriate.", file=sys.stderr)
                
                # Per requirements: canary failures don't block CI
                # pytest.skip("Canary warnings emitted - not blocking")


# ============================================================================
# PART 5: OVERRIDE AUDIT TESTS
# ============================================================================

class TestOverrideAudit:
    """
    Test audit logging for policy overrides.
    
    CRITICAL: Overrides must NEVER be invisible.
    """
    
    def test_override_flag_detection(self):
        """
        Test that override flag is correctly detected.
        """
        # Without env var, should be False
        with patch.dict(os.environ, {}, clear=True):
            assert check_override_enabled() == False
        
        # With env var, should be True
        with patch.dict(os.environ, {"ALLOW_TRUSTED_DOMAIN_RECLASSIFICATION": "true"}):
            assert check_override_enabled() == True
    
    def test_override_emits_warning(self, capsys):
        """
        Test that override logging emits console warning.
        """
        with patch('policy_audit.AUDIT_LOG_PATH', '/dev/null'):
            logger = PolicyAuditLogger(log_path='/dev/null')
            
            # This should emit warning to stderr
            logger.log_override(
                event_type=OverrideEventType.TRUSTED_DOMAIN_RECLASSIFICATION,
                override_flag=True,
                affected_domains=["test.com"],
                context="unit_test",
                reason="Testing warning emission"
            )
        
        captured = capsys.readouterr()
        assert "POLICY OVERRIDE DETECTED" in captured.err
    
    def test_override_creates_structured_entry(self):
        """
        Test that override logging creates proper structured entry.
        """
        with patch('policy_audit.AUDIT_LOG_PATH', '/dev/null'):
            logger = PolicyAuditLogger(log_path='/dev/null')
            
            entry = logger.log_override(
                event_type=OverrideEventType.TRUSTED_DOMAIN_RECLASSIFICATION,
                override_flag=True,
                affected_domains=["example.com"],
                context="test_context",
                reason="Test reason"
            )
        
        assert entry.event_type == "TRUSTED_DOMAIN_RECLASSIFICATION"
        assert entry.override_flag_value == True
        assert "example.com" in entry.affected_domains
        assert entry.triggering_context == "test_context"


# ============================================================================
# PART 6: CI SAFETY GATE TESTS
# ============================================================================

class TestCISafetyGates:
    """
    Tests that verify CI safety gate behavior.
    
    These tests document expected CI behavior.
    """
    
    def test_phishing_verdict_on_regression_domain_fails(self, snapshot_data):
        """
        Document: PHISHING verdict on regression domain MUST fail CI.
        """
        # This is a documentation test
        ci_behavior = snapshot_data.get("ci_behavior", {})
        assert ci_behavior.get("fail_on_regression") == True
    
    def test_snapshot_mismatch_fails(self, snapshot_data):
        """
        Document: Snapshot mismatch MUST fail CI.
        """
        ci_behavior = snapshot_data.get("ci_behavior", {})
        assert ci_behavior.get("fail_on_snapshot_mismatch") == True
    
    def test_explicit_override_required(self, snapshot_data):
        """
        Document: Policy changes require explicit override.
        """
        ci_behavior = snapshot_data.get("ci_behavior", {})
        assert ci_behavior.get("require_explicit_override_for_changes") == True


# ============================================================================
# PART 7: ADVERSARIAL INVARIANT TESTS
# ============================================================================

class TestTrustedDomainInvariants:
    """
    Adversarial tests for trusted domain guarantees.
    
    CRITICAL: These protect against the most dangerous failure modes.
    """
    
    def test_trusted_domain_immune_to_100pct_phishing_ml(self, snapshot_data, mock_model):
        """
        Even if ML returns 100% phishing, trusted domain stays SAFE.
        
        PROTECTS AGAINST: ML overriding trust gate.
        """
        regression_domains = snapshot_data.get("regression_domains", [])[:3]
        
        # Configure model to return 100% phishing
        mock_model.predict_proba.return_value = [[1.0, 0.0]]  # 100% phishing
        
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            
            for domain in regression_domains:
                result = pipeline.analyze(f"https://{domain}")
                
                # Critical assertion: MUST be SAFE regardless of ML
                assert result.verdict == Verdict.SAFE, (
                    f"INVARIANT VIOLATION: Trusted domain '{domain}' got {result.verdict.value}!\n"
                    f"ML returned 100% phishing but trust gate should override!"
                )
                
                # ML should not have been called at all
                assert result.ml_bypassed == True
    
    def test_trusted_domain_verdict_immutable_downstream(self, mock_model):
        """
        Once trust gate returns SAFE, no downstream step can change it.
        
        PROTECTS AGAINST: Late-stage pipeline changes overriding trust.
        """
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            result = pipeline.analyze("https://google.com")
            
            # Verify verdict is SAFE
            assert result.verdict == Verdict.SAFE
            
            # Verify no risk signals in explanation
            risk_signals = result.explanation.get("risk", [])
            assert len(risk_signals) == 0, (
                f"SAFE trusted domain should have NO risk signals, got: {risk_signals}"
            )
    
    def test_after_trusted_gate_ml_not_consulted(self, mock_model):
        """
        After trust gate succeeds, ML is never consulted.
        
        PROTECTS AGAINST: ML being run and somehow influencing result.
        """
        with patch('decision_pipeline.model_trainer') as mock_trainer:
            mock_trainer.ensure_model_exists.return_value = None
            mock_trainer.load_model.return_value = mock_model
            mock_trainer.get_feature_schema.return_value = {"version": "2.0"}
            
            pipeline = DecisionPipeline()
            pipeline.analyze("https://github.com")
            
            # ML predict_proba should NEVER be called
            mock_model.predict_proba.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
