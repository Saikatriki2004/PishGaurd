"""
Governance Enforcement Tests

PURPOSE:
    Verify that governance rules are correctly enforced.
    These tests validate executable policy, not documentation.

WHAT THIS FILE PROTECTS AGAINST:
    - Unauthorized overrides
    - Premature canary promotions
    - Calibration status being ignored
    - Safety budget violations going undetected
    - Policy-code divergence

CRITICAL: These tests are part of CI safety gates.
"""

import pytest
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import tempfile
import shutil

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from governance_engine import (
    GovernanceEngine, Override, CanarySignal, SafetyBudgetStatus,
    OverrideAuthority, OverrideType,
    CANARY_MIN_PASSES, CANARY_MIN_SAMPLE_SIZE, SAFETY_BUDGET_LIMITS
)


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def temp_state_dir():
    """Create a temporary directory for governance state."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def governance_engine(temp_state_dir):
    """Create a clean governance engine for testing."""
    # Create required directory structure
    os.makedirs(os.path.join(temp_state_dir, "tests", "fixtures"), exist_ok=True)
    
    # Create minimal manifest
    manifest = {
        "version": "test-v1",
        "change_reason": "Test manifest",
        "last_modified_by": "test"
    }
    with open(os.path.join(temp_state_dir, "trusted_domains_manifest.json"), 'w') as f:
        json.dump(manifest, f)
    
    # Create minimal snapshot
    snapshot = {
        "_manifest_version": "test-v1",
        "regression_domains": ["google.com"]
    }
    with open(os.path.join(temp_state_dir, "tests", "fixtures", "trusted_domains_snapshot.json"), 'w') as f:
        json.dump(snapshot, f)
    
    return GovernanceEngine(temp_state_dir)


# ============================================================================
# TEST CLASS 1: OVERRIDE AUTHORITY BOUNDARIES
# ============================================================================

class TestOverrideAuthority:
    """
    Test that override authority boundaries are enforced.
    
    RULES:
    - PERMANENT: SECURITY_TEAM + review_ticket
    - EMERGENCY: SECURITY_TEAM or ON_CALL
    - TESTING: CI_SYSTEM only
    """
    
    def test_permanent_requires_security_team(self, governance_engine):
        """
        Test that PERMANENT overrides require SECURITY_TEAM authority.
        """
        with pytest.raises(ValueError, match="require SECURITY_TEAM"):
            governance_engine.request_override(
                override_type=OverrideType.PERMANENT,
                authority=OverrideAuthority.ON_CALL,  # Wrong authority
                affected_domains=["test.com"],
                reason="Test",
                approved_by="tester"
            )
    
    def test_permanent_requires_review_ticket(self, governance_engine):
        """
        Test that PERMANENT overrides require a review_ticket.
        """
        with pytest.raises(ValueError, match="require a review_ticket"):
            governance_engine.request_override(
                override_type=OverrideType.PERMANENT,
                authority=OverrideAuthority.SECURITY_TEAM,
                affected_domains=["test.com"],
                reason="Test",
                approved_by="tester",
                review_ticket=None  # Missing ticket
            )
    
    def test_permanent_override_succeeds_with_proper_authority(self, governance_engine):
        """
        Test that PERMANENT override succeeds with correct authority.
        """
        override = governance_engine.request_override(
            override_type=OverrideType.PERMANENT,
            authority=OverrideAuthority.SECURITY_TEAM,
            affected_domains=["test.com"],
            reason="Valid permanent change",
            approved_by="security-lead",
            review_ticket="SEC-123"
        )
        
        assert override is not None
        assert override.override_type == "permanent"
        assert override.expires_at is None  # Permanent = no expiration
    
    def test_emergency_has_expiration(self, governance_engine):
        """
        Test that EMERGENCY overrides automatically expire.
        """
        override = governance_engine.request_override(
            override_type=OverrideType.EMERGENCY,
            authority=OverrideAuthority.ON_CALL,
            affected_domains=["test.com"],
            reason="Production incident",
            approved_by="on-call-engineer"
        )
        
        assert override.expires_at is not None
        # Should expire within 24 hours
        expiry = datetime.fromisoformat(override.expires_at.replace('Z', '+00:00'))
        max_expiry = datetime.now(timezone.utc) + timedelta(hours=24) + timedelta(minutes=1)
        assert expiry <= max_expiry
    
    def test_testing_override_only_ci_system(self, governance_engine):
        """
        Test that TESTING overrides are CI_SYSTEM only.
        """
        with pytest.raises(ValueError, match="CI_SYSTEM only"):
            governance_engine.request_override(
                override_type=OverrideType.TESTING,
                authority=OverrideAuthority.SECURITY_TEAM,  # Wrong
                affected_domains=["test.com"],
                reason="Test",
                approved_by="tester"
            )
    
    def test_expired_override_becomes_inactive(self, governance_engine):
        """
        Test that expired overrides are marked inactive.
        """
        # Create override with immediate expiration
        override = Override(
            override_id="TEST-001",
            override_type="testing",
            authority="ci-system",
            created_at=datetime.now(timezone.utc).isoformat(),
            expires_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            affected_domains=["test.com"],
            reason="Test",
            approved_by="ci",
            review_ticket=None,
            is_active=True
        )
        governance_engine.overrides.append(override)
        
        # Get active overrides should mark it inactive
        active = governance_engine.get_active_overrides()
        
        assert override.override_id not in [o.override_id for o in active]


# ============================================================================
# TEST CLASS 2: CANARY PROMOTION ENFORCEMENT
# ============================================================================

class TestCanaryPromotion:
    """
    Test canary domain promotion rules.
    
    RULES:
    - Minimum consecutive passes required
    - Minimum sample size required
    - 100% pass rate required
    - Explicit approval metadata required
    """
    
    def test_canary_needs_minimum_passes(self, governance_engine):
        """
        Test that canary needs minimum consecutive passes.
        """
        # Record only 2 passes (need 5)
        for _ in range(2):
            governance_engine.record_canary_result("newdomain.com", "SAFE")
        
        eligibility = governance_engine.check_promotion_eligibility("newdomain.com")
        
        assert eligibility["eligible"] == False
        assert "consecutive passes" in eligibility["reason"]
    
    def test_canary_needs_sample_volume(self, governance_engine):
        """
        Test that canary needs sufficient sample size.
        """
        # Record enough passes but low sample size
        for _ in range(10):
            governance_engine.record_canary_result("newdomain.com", "SAFE", sample_size=1)
        
        signal = governance_engine.canary_signals["newdomain.com"]
        
        # Has enough passes but not enough sample volume
        assert signal.test_runs >= CANARY_MIN_PASSES
        assert signal.sample_size < CANARY_MIN_SAMPLE_SIZE
        
        eligibility = governance_engine.check_promotion_eligibility("newdomain.com")
        assert eligibility["eligible"] == False
    
    def test_canary_failure_resets_consecutive(self, governance_engine):
        """
        Test that a PHISHING result resets consecutive pass count.
        """
        # Build up passes
        for _ in range(4):
            governance_engine.record_canary_result("newdomain.com", "SAFE", sample_size=30)
        
        signal = governance_engine.canary_signals["newdomain.com"]
        assert signal.consecutive_passes == 4
        
        # One failure resets
        governance_engine.record_canary_result("newdomain.com", "PHISHING", sample_size=10)
        
        assert signal.consecutive_passes == 0
        assert signal.failures == 1
    
    def test_canary_promotable_with_full_criteria(self, governance_engine):
        """
        Test that canary is promotable when all criteria met.
        """
        # Record enough passes with enough samples
        for _ in range(CANARY_MIN_PASSES):
            governance_engine.record_canary_result(
                "newdomain.com", "SAFE", 
                sample_size=CANARY_MIN_SAMPLE_SIZE // CANARY_MIN_PASSES + 1
            )
        
        eligibility = governance_engine.check_promotion_eligibility("newdomain.com")
        
        assert eligibility["eligible"] == True
        assert eligibility["requires_approval"] == True
    
    def test_promotion_requires_approval_metadata(self, governance_engine):
        """
        Test that promotion requires explicit approval metadata.
        """
        # Make domain promotable
        for _ in range(CANARY_MIN_PASSES):
            governance_engine.record_canary_result(
                "newdomain.com", "SAFE",
                sample_size=CANARY_MIN_SAMPLE_SIZE // CANARY_MIN_PASSES + 1
            )
        
        # Promote with metadata
        result = governance_engine.promote_canary(
            domain="newdomain.com",
            approved_by="security-lead",
            review_ticket="SEC-456"
        )
        
        assert result["approved_by"] == "security-lead"
        assert result["review_ticket"] == "SEC-456"


# ============================================================================
# TEST CLASS 3: CALIBRATION AS POLICY INPUT
# ============================================================================

class TestCalibrationPolicy:
    """
    Test that calibration status affects policy.
    
    RULES:
    - healthy: No restrictions
    - degraded: PHISHING → SUSPICIOUS
    - unknown: PHISHING → SUSPICIOUS + warning
    """
    
    def test_healthy_calibration_no_restriction(self, governance_engine):
        """
        Test that healthy calibration doesn't restrict verdicts.
        """
        adjustment = governance_engine.get_calibration_policy_adjustment("healthy")
        
        assert adjustment["confidence_penalty"] == 0.0
        assert adjustment["restrict_phishing"] == False
    
    def test_degraded_calibration_restricts_phishing(self, governance_engine):
        """
        Test that degraded calibration restricts PHISHING verdicts.
        """
        adjustment = governance_engine.get_calibration_policy_adjustment("degraded")
        
        assert adjustment["restrict_phishing"] == True
        assert adjustment["confidence_penalty"] > 0
    
    def test_unknown_calibration_restricts_phishing(self, governance_engine):
        """
        Test that unknown calibration restricts PHISHING verdicts.
        """
        adjustment = governance_engine.get_calibration_policy_adjustment("unknown")
        
        assert adjustment["restrict_phishing"] == True
        assert adjustment["require_warning"] == True
    
    def test_phishing_downgraded_on_degraded(self, governance_engine):
        """
        Test that PHISHING becomes SUSPICIOUS when calibration degraded.
        """
        result = governance_engine.apply_calibration_restriction("PHISHING", "degraded")
        
        assert result == "SUSPICIOUS"
    
    def test_safe_not_affected_by_calibration(self, governance_engine):
        """
        Test that SAFE verdict is not affected by calibration.
        """
        result = governance_engine.apply_calibration_restriction("SAFE", "degraded")
        
        assert result == "SAFE"  # Not changed


# ============================================================================
# TEST CLASS 4: SAFETY BUDGETS & ESCALATION
# ============================================================================

class TestSafetyBudgets:
    """
    Test safety budget enforcement and escalation.
    
    RULES:
    - SUSPICIOUS on trusted = immediate freeze
    - Override budget has limits
    - Canary failures have limits
    """
    
    def test_suspicious_on_trusted_triggers_freeze(self, governance_engine):
        """
        Test that SUSPICIOUS on trusted domain triggers immediate freeze.
        """
        governance_engine.record_safety_event("suspicious_on_trusted")
        
        assert governance_engine.safety_budget.is_frozen == True
        assert "SUSPICIOUS verdict on trusted" in governance_engine.safety_budget.freeze_reason
    
    def test_override_budget_limit_enforced(self, governance_engine):
        """
        Test that override budget limit is enforced.
        """
        # Use up budget
        for i in range(SAFETY_BUDGET_LIMITS["overrides_per_window"]):
            governance_engine.request_override(
                override_type=OverrideType.EMERGENCY,
                authority=OverrideAuthority.ON_CALL,
                affected_domains=[f"test{i}.com"],
                reason=f"Test override {i}",
                approved_by="on-call"
            )
        
        # Next one should fail
        with pytest.raises(ValueError, match="budget exceeded"):
            governance_engine.request_override(
                override_type=OverrideType.EMERGENCY,
                authority=OverrideAuthority.ON_CALL,
                affected_domains=["onemore.com"],
                reason="Over budget",
                approved_by="on-call"
            )
    
    def test_frozen_system_blocks_overrides(self, governance_engine):
        """
        Test that frozen system blocks all overrides.
        """
        # Trigger freeze
        governance_engine.record_safety_event("suspicious_on_trusted")
        
        # Try to create override
        with pytest.raises(ValueError, match="frozen"):
            governance_engine.request_override(
                override_type=OverrideType.PERMANENT,
                authority=OverrideAuthority.SECURITY_TEAM,
                affected_domains=["test.com"],
                reason="Test",
                approved_by="tester",
                review_ticket="SEC-999"
            )
    
    def test_freeze_lift_requires_documentation(self, governance_engine):
        """
        Test that lifting freeze requires proper documentation.
        """
        # Trigger freeze
        governance_engine.record_safety_event("suspicious_on_trusted")
        assert governance_engine.safety_budget.is_frozen == True
        
        # Lift freeze with documentation
        governance_engine.lift_freeze(
            lifted_by="security-lead",
            resolution="Root cause identified and fixed",
            review_ticket="SEC-888"
        )
        
        assert governance_engine.safety_budget.is_frozen == False


# ============================================================================
# TEST CLASS 5: POLICY-AS-CODE VERIFICATION
# ============================================================================

class TestPolicyConsistency:
    """
    Test policy-as-code consistency verification.
    """
    
    def test_consistent_state_passes(self, governance_engine):
        """
        Test that consistent state passes verification.
        """
        result = governance_engine.verify_policy_consistency()
        
        assert result["consistent"] == True
        assert len(result["errors"]) == 0
    
    def test_version_mismatch_detected(self, governance_engine, temp_state_dir):
        """
        Test that manifest/snapshot version mismatch is detected.
        """
        # Update snapshot to different version
        snapshot_path = os.path.join(temp_state_dir, "tests", "fixtures", "trusted_domains_snapshot.json")
        with open(snapshot_path, 'r') as f:
            snapshot = json.load(f)
        snapshot["_manifest_version"] = "different-version"
        with open(snapshot_path, 'w') as f:
            json.dump(snapshot, f)
        
        result = governance_engine.verify_policy_consistency()
        
        assert result["consistent"] == False
        assert any("mismatch" in e.lower() for e in result["errors"])
    
    def test_missing_manifest_detected(self, temp_state_dir):
        """
        Test that missing manifest is detected.
        """
        # Remove manifest
        os.makedirs(os.path.join(temp_state_dir, "tests", "fixtures"), exist_ok=True)
        snapshot = {"_manifest_version": "v1", "regression_domains": []}
        with open(os.path.join(temp_state_dir, "tests", "fixtures", "trusted_domains_snapshot.json"), 'w') as f:
            json.dump(snapshot, f)
        
        engine = GovernanceEngine(temp_state_dir)
        result = engine.verify_policy_consistency()
        
        assert result["consistent"] == False
        assert any("missing" in e.lower() for e in result["errors"])


# ============================================================================
# TEST CLASS 6: INVARIANT VERIFICATION
# ============================================================================

class TestSafetyInvariants:
    """
    Test that safety invariants are enforced.
    
    These are the NON-NEGOTIABLE rules.
    """
    
    def test_invariant_degraded_never_escalates(self, governance_engine):
        """
        INVARIANT: Degraded calibration can ONLY reduce confidence.
        """
        adjustment = governance_engine.get_calibration_policy_adjustment("degraded")
        
        # Penalty must be non-negative (always reduce, never increase)
        assert adjustment["confidence_penalty"] >= 0
        # Restriction must only downgrade
        assert adjustment["restrict_phishing"] == True  # Downgrade PHISHING
    
    def test_invariant_override_always_expires_or_reviewed(self, governance_engine):
        """
        INVARIANT: Every override either expires or requires review.
        """
        # EMERGENCY has expiration
        override = governance_engine.request_override(
            override_type=OverrideType.EMERGENCY,
            authority=OverrideAuthority.ON_CALL,
            affected_domains=["test.com"],
            reason="Emergency",
            approved_by="on-call"
        )
        assert override.expires_at is not None
        
        # PERMANENT requires review ticket
        override2 = governance_engine.request_override(
            override_type=OverrideType.PERMANENT,
            authority=OverrideAuthority.SECURITY_TEAM,
            affected_domains=["test2.com"],
            reason="Permanent",
            approved_by="security",
            review_ticket="SEC-123"
        )
        assert override2.review_ticket is not None
    
    def test_invariant_canary_never_auto_promotes(self, governance_engine):
        """
        INVARIANT: Canary promotion always requires explicit approval.
        """
        # Make domain promotable
        for _ in range(CANARY_MIN_PASSES):
            governance_engine.record_canary_result(
                "newdomain.com", "SAFE",
                sample_size=CANARY_MIN_SAMPLE_SIZE // CANARY_MIN_PASSES + 1
            )
        
        eligibility = governance_engine.check_promotion_eligibility("newdomain.com")
        
        # Must require approval
        assert eligibility["requires_approval"] == True
        assert "approval_metadata_required" in eligibility


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
