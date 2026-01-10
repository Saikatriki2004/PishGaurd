"""
Safety Governance Tests - Fail-Closed Behavior Verification

PURPOSE:
    Lock the safety governance invariants so future changes cannot:
    - Bypass the freeze protocol
    - Reset budgets on restart
    - Allow governance changes during freeze
    - Allow actions on UNKNOWN calibration

WHAT THESE TESTS PROTECT AGAINST:
    - Silent invariant violations
    - Governance operations during system freeze
    - Budget reset on service restart
    - Calibration bypass
"""

import pytest
import os
import sys
import json
import tempfile
import shutil
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safety_governance import (
    SafetyGovernanceController,
    GovernanceStatePersistence,
    FreezeState,
    FreezeReason,
    CalibrationStatus,
    HumanReviewType,
    SafetyBudgetState,
    DomainTrustRecord,
    SystemFrozenError,
    BudgetExhaustedError,
    InvariantViolationError,
    CalibrationViolationError,
    get_governance_controller,
    assert_system_operational,
    is_system_frozen,
)


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def temp_governance_dir(tmp_path):
    """Create temporary governance state directory."""
    gov_dir = tmp_path / "governance_state"
    gov_dir.mkdir()
    
    with patch('safety_governance.GOVERNANCE_STATE_DIR', str(gov_dir)), \
         patch('safety_governance.FREEZE_STATE_FILE', str(gov_dir / "freeze_state.json")), \
         patch('safety_governance.BUDGET_STATE_FILE', str(gov_dir / "safety_budget.json")), \
         patch('safety_governance.DOMAIN_TRUST_FILE', str(gov_dir / "domain_trust_timestamps.json")):
        yield gov_dir


@pytest.fixture
def fresh_controller(temp_governance_dir):
    """Create fresh governance controller with clean state."""
    return SafetyGovernanceController()


# ============================================================================
# TEST CLASS 1: FREEZE PROTOCOL
# ============================================================================

class TestFreezeProtocol:
    """Test system freeze behavior."""
    
    def test_initially_not_frozen(self, fresh_controller):
        """System starts in unfrozen state."""
        assert fresh_controller.is_frozen() == False
    
    def test_trigger_freeze_sets_frozen_state(self, fresh_controller):
        """Triggering freeze sets frozen state."""
        fresh_controller.trigger_freeze(
            reason=FreezeReason.TRUSTED_DOMAIN_PHISHING,
            triggered_by="test",
            incident_id="TEST-001"
        )
        
        assert fresh_controller.is_frozen() == True
    
    def test_freeze_persists_after_reload(self, temp_governance_dir):
        """Freeze state persists across controller instances."""
        # First controller - trigger freeze
        controller1 = SafetyGovernanceController()
        controller1.trigger_freeze(
            reason=FreezeReason.TRUSTED_DOMAIN_PHISHING,
            triggered_by="test",
            incident_id="TEST-001"
        )
        
        # Second controller - should still be frozen
        controller2 = SafetyGovernanceController()
        assert controller2.is_frozen() == True
    
    def test_frozen_state_blocks_operations(self, fresh_controller):
        """Frozen state blocks governance operations."""
        fresh_controller.trigger_freeze(
            reason=FreezeReason.MANUAL_FREEZE,
            triggered_by="test",
            incident_id="TEST-001"
        )
        
        with pytest.raises(SystemFrozenError):
            fresh_controller.assert_not_frozen("test_action")
    
    def test_resume_requires_incident_id(self, fresh_controller):
        """Resume requires incident ID."""
        fresh_controller.trigger_freeze(
            reason=FreezeReason.MANUAL_FREEZE,
            triggered_by="test",
            incident_id="TEST-001"
        )
        
        with pytest.raises(ValueError, match="incident_id"):
            fresh_controller.resume_from_freeze(
                resumed_by="test",
                incident_id="",
                justification="Test justification for resuming"
            )
    
    def test_resume_requires_justification(self, fresh_controller):
        """Resume requires detailed justification."""
        fresh_controller.trigger_freeze(
            reason=FreezeReason.MANUAL_FREEZE,
            triggered_by="test",
            incident_id="TEST-001"
        )
        
        with pytest.raises(ValueError, match="justification"):
            fresh_controller.resume_from_freeze(
                resumed_by="test",
                incident_id="TEST-002",
                justification="short"  # Too short
            )
    
    def test_successful_resume(self, fresh_controller):
        """Successful resume unfreezes system."""
        fresh_controller.trigger_freeze(
            reason=FreezeReason.MANUAL_FREEZE,
            triggered_by="test",
            incident_id="TEST-001"
        )
        
        fresh_controller.resume_from_freeze(
            resumed_by="test",
            incident_id="TEST-002",
            justification="Root cause identified and fixed. Verified by reviewing..."
        )
        
        assert fresh_controller.is_frozen() == False


# ============================================================================
# TEST CLASS 2: SAFETY BUDGET - MONOTONIC ACROSS DEPLOYMENTS
# ============================================================================

class TestSafetyBudgetPersistence:
    """Test that safety budgets persist across deployments."""
    
    def test_budget_persists_across_controller_instances(self, temp_governance_dir):
        """Budget count persists when controller is recreated."""
        controller1 = SafetyGovernanceController()
        
        # Consume some budget
        controller1.consume_override_budget("test1")
        controller1.consume_override_budget("test2")
        
        # Create new controller (simulating restart)
        controller2 = SafetyGovernanceController()
        state = controller2._persistence.load_budget_state()
        
        # Budget should NOT be reset
        assert state.override_count_hourly == 2
    
    def test_budget_exhaustion_triggers_freeze(self, temp_governance_dir):
        """Budget exhaustion triggers system freeze."""
        controller = SafetyGovernanceController()
        
        # Exhaust budget
        for i in range(5):
            controller.consume_override_budget(f"test{i}")
        
        # Next consume should trigger freeze
        with pytest.raises(BudgetExhaustedError):
            controller.consume_override_budget("trigger_freeze")
        
        assert controller.is_frozen() == True
    
    def test_restart_does_not_reset_budget(self, temp_governance_dir):
        """Restarting service does NOT reset budget."""
        controller1 = SafetyGovernanceController()
        
        # Use up budget
        for i in range(4):
            controller1.consume_override_budget(f"test{i}")
        
        # "Restart" - new controller instance
        controller2 = SafetyGovernanceController()
        state = controller2._persistence.load_budget_state()
        
        # Budget should show 4 consumed
        assert state.override_count_hourly == 4
    
    def test_manual_reset_requires_justification(self, fresh_controller):
        """Manual budget reset requires justification."""
        fresh_controller.consume_override_budget("test")
        
        with pytest.raises(ValueError, match="justification"):
            fresh_controller.reset_budget(
                reset_by="test",
                justification="short",  # Too short
                incident_id="TEST-001"
            )


# ============================================================================
# TEST CLASS 3: TRUSTED DOMAIN INVARIANT
# ============================================================================

class TestTrustedDomainInvariant:
    """Test that trusted domain phishing verdict triggers freeze."""
    
    def test_phishing_verdict_triggers_freeze(self, fresh_controller):
        """PHISHING verdict on trusted domain triggers immediate freeze."""
        with pytest.raises(InvariantViolationError):
            fresh_controller.report_trusted_domain_verdict(
                domain="google.com",
                verdict="PHISHING",
                risk_score=90.0
            )
        
        assert fresh_controller.is_frozen() == True
    
    def test_suspicious_verdict_logged_but_no_freeze(self, fresh_controller):
        """SUSPICIOUS verdict on trusted domain is logged but doesn't freeze."""
        fresh_controller.report_trusted_domain_verdict(
            domain="google.com",
            verdict="SUSPICIOUS",
            risk_score=60.0
        )
        
        # Should not freeze
        assert fresh_controller.is_frozen() == False
        
        # But count should be tracked
        state = fresh_controller._persistence.load_budget_state()
        assert state.suspicious_trusted_count == 1
    
    def test_safe_verdict_no_action(self, fresh_controller):
        """SAFE verdict on trusted domain has no action."""
        fresh_controller.report_trusted_domain_verdict(
            domain="google.com",
            verdict="SAFE",
            risk_score=15.0
        )
        
        assert fresh_controller.is_frozen() == False


# ============================================================================
# TEST CLASS 4: CALIBRATION-GOVERNANCE COUPLING
# ============================================================================

class TestCalibrationGovernanceCoupling:
    """Test calibration status blocks governance actions."""
    
    @pytest.mark.parametrize("action", [
        "canary_promotion",
        "allowlist_expansion",
        "permanent_override"
    ])
    def test_unhealthy_calibration_blocks_critical_actions(self, fresh_controller, action):
        """UNKNOWN calibration blocks critical governance actions."""
        allowed, reason = fresh_controller.check_calibration_allows_governance(
            CalibrationStatus.UNKNOWN,
            action
        )
        
        assert allowed == False
        assert "forbidden" in reason.lower() or "review" in reason.lower()
    
    def test_healthy_calibration_allows_all_actions(self, fresh_controller):
        """HEALTHY calibration allows all actions."""
        for action in ["canary_promotion", "allowlist_expansion", "permanent_override"]:
            allowed, reason = fresh_controller.check_calibration_allows_governance(
                CalibrationStatus.HEALTHY,
                action
            )
            assert allowed == True
    
    def test_assert_calibration_raises_on_violation(self, fresh_controller):
        """assert_calibration_allows raises on violation."""
        with pytest.raises(CalibrationViolationError):
            fresh_controller.assert_calibration_allows(
                CalibrationStatus.UNKNOWN,
                "canary_promotion"
            )


# ============================================================================
# TEST CLASS 5: TEMPORAL TRUST REVALIDATION
# ============================================================================

class TestTemporalTrustRevalidation:
    """Test domain trust expiry."""
    
    def test_new_domain_has_future_revalidation(self, fresh_controller):
        """Newly registered domain has revalidation date in future."""
        record = fresh_controller.register_trusted_domain(
            domain="example.com",
            reviewed_by="test"
        )
        
        assert not record.is_revalidation_overdue()
        assert record.days_until_revalidation() > 300  # ~1 year
    
    def test_overdue_domain_detected(self, temp_governance_dir):
        """Overdue domains are detected."""
        controller = SafetyGovernanceController()
        
        # Create expired record directly
        past_date = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
        expired_record = DomainTrustRecord(
            domain="expired.com",
            added_date=past_date,
            last_reviewed_date=past_date,
            reviewed_by="test",
            trust_level="full",
            revalidation_required_by=past_date  # Already past
        )
        
        records = {"expired.com": expired_record}
        controller._persistence.save_domain_trust(records)
        
        # Reload and check
        overdue = controller.get_domains_requiring_revalidation()
        assert len(overdue) == 1
        assert overdue[0].domain == "expired.com"
    
    def test_frozen_blocks_domain_registration(self, fresh_controller):
        """Cannot register domain when frozen."""
        fresh_controller.trigger_freeze(
            reason=FreezeReason.MANUAL_FREEZE,
            triggered_by="test",
            incident_id="TEST-001"
        )
        
        with pytest.raises(SystemFrozenError):
            fresh_controller.register_trusted_domain(
                domain="new.com",
                reviewed_by="test"
            )


# ============================================================================
# TEST CLASS 6: FAIL-CLOSED BEHAVIOR
# ============================================================================

class TestFailClosedBehavior:
    """Test that system fails closed, not gracefully."""
    
    def test_freeze_blocks_all_governance_operations(self, fresh_controller):
        """All governance operations blocked when frozen."""
        fresh_controller.trigger_freeze(
            reason=FreezeReason.MANUAL_FREEZE,
            triggered_by="test",
            incident_id="TEST-001"
        )
        
        operations = [
            lambda: fresh_controller.consume_override_budget("test"),
            lambda: fresh_controller.register_trusted_domain("test.com", "test"),
        ]
        
        for op in operations:
            with pytest.raises(SystemFrozenError):
                op()
    
    def test_invariant_violation_is_not_recoverable_automatically(self, fresh_controller):
        """Cannot auto-recover from invariant violation."""
        # Trigger invariant violation
        with pytest.raises(InvariantViolationError):
            fresh_controller.report_trusted_domain_verdict("test.com", "PHISHING", 90.0)
        
        # System is frozen
        assert fresh_controller.is_frozen() == True
        
        # Cannot be unfrozen without proper resume
        with pytest.raises(ValueError):
            fresh_controller.resume_from_freeze("test", "", "")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
