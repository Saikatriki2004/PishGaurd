"""
Safety Governance Module - Fail-Closed Safety Controls

PURPOSE:
    Enforce system-level safety invariants that HALT operation on violation.
    Safety violations are INCIDENTS, not bugs.

META-INVARIANT:
    If the system ever violates a protected safety invariant,
    normal operation must NOT resume automatically.

FREEZE TRIGGERS:
    1. Trusted domain receives PHISHING verdict
    2. Safety budget hard limit exceeded
    3. Calibration UNKNOWN + severity escalation attempted

WHILE FROZEN:
    - No overrides allowed
    - No promotions allowed
    - No manifest changes allowed

RESUME REQUIRES:
    - Explicit audit log entry
    - Named approver
    - Incident reference
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict, field
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum
from pathlib import Path
import threading

logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

GOVERNANCE_STATE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "governance_state"
)

FREEZE_STATE_FILE = os.path.join(GOVERNANCE_STATE_DIR, "freeze_state.json")
BUDGET_STATE_FILE = os.path.join(GOVERNANCE_STATE_DIR, "safety_budget.json")
DOMAIN_TRUST_FILE = os.path.join(GOVERNANCE_STATE_DIR, "domain_trust_timestamps.json")


# ============================================================================
# ENUMS
# ============================================================================

class FreezeReason(Enum):
    """Reasons for system freeze."""
    TRUSTED_DOMAIN_PHISHING = "TRUSTED_DOMAIN_PHISHING"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    CALIBRATION_ESCALATION = "CALIBRATION_ESCALATION"
    MANUAL_FREEZE = "MANUAL_FREEZE"


class CalibrationStatus(Enum):
    """Model calibration health status."""
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNKNOWN = "UNKNOWN"


class HumanReviewType(Enum):
    """Events requiring mandatory human review."""
    FREEZE_RESUME = "FREEZE_RESUME"
    BUDGET_RESET = "BUDGET_RESET"
    DOMAIN_REVALIDATION = "DOMAIN_REVALIDATION"
    PERMANENT_OVERRIDE = "PERMANENT_OVERRIDE"
    ALLOWLIST_EXPANSION = "ALLOWLIST_EXPANSION"
    CANARY_PROMOTION = "CANARY_PROMOTION"


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class FreezeState:
    """Persistent freeze state."""
    is_frozen: bool = False
    frozen_at: Optional[str] = None
    frozen_by: Optional[str] = None
    freeze_reason: Optional[str] = None
    incident_id: Optional[str] = None
    freeze_details: Dict[str, Any] = field(default_factory=dict)
    
    # Resume tracking
    resumed_at: Optional[str] = None
    resumed_by: Optional[str] = None
    resume_justification: Optional[str] = None
    resume_incident_id: Optional[str] = None


@dataclass
class SafetyBudgetState:
    """Persistent safety budget state - monotonic across deployments."""
    
    # Override tracking
    override_count_hourly: int = 0
    override_window_start: str = ""
    
    # Violation tracking
    suspicious_trusted_count: int = 0
    phishing_trusted_count: int = 0  # Should ALWAYS be 0
    
    # Budget limits
    MAX_OVERRIDES_PER_HOUR: int = 5
    MAX_SUSPICIOUS_TRUSTED_PER_DAY: int = 0  # Zero tolerance
    
    # Reset tracking
    last_reset_at: Optional[str] = None
    last_reset_by: Optional[str] = None
    last_reset_justification: Optional[str] = None
    
    def is_override_budget_exhausted(self) -> bool:
        """Check if override budget is exhausted."""
        return self.override_count_hourly >= self.MAX_OVERRIDES_PER_HOUR


@dataclass
class DomainTrustRecord:
    """Trust record with temporal validation."""
    domain: str
    added_date: str
    last_reviewed_date: str
    reviewed_by: str
    trust_level: str  # "full", "probation"
    revalidation_required_by: str
    
    def is_revalidation_overdue(self) -> bool:
        """Check if domain needs revalidation."""
        due_date = datetime.fromisoformat(self.revalidation_required_by)
        return datetime.now(timezone.utc) > due_date
    
    def days_until_revalidation(self) -> int:
        """Days until revalidation required."""
        due_date = datetime.fromisoformat(self.revalidation_required_by)
        delta = due_date - datetime.now(timezone.utc)
        return max(0, delta.days)


@dataclass
class HumanReviewRecord:
    """Record of required human review."""
    review_type: str
    required_at: str
    requires_evidence: List[str]
    prohibited_actions: List[str]
    completed_at: Optional[str] = None
    completed_by: Optional[str] = None
    review_notes: Optional[str] = None
    incident_reference: Optional[str] = None


# ============================================================================
# PERSISTENCE LAYER
# ============================================================================

class GovernanceStatePersistence:
    """Thread-safe, file-backed persistence for governance state."""
    
    def __init__(self):
        self._ensure_state_dir()
        self._lock = threading.Lock()
    
    def _ensure_state_dir(self) -> None:
        """Ensure governance state directory exists."""
        os.makedirs(GOVERNANCE_STATE_DIR, exist_ok=True)
    
    def _read_json(self, filepath: str) -> Dict[str, Any]:
        """Read JSON file with locking."""
        if not os.path.exists(filepath):
            return {}
        
        with self._lock:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                logger.error(f"[GOVERNANCE] Failed to read {filepath}")
                return {}
    
    def _write_json(self, filepath: str, data: Dict[str, Any]) -> None:
        """Write JSON file with locking."""
        with self._lock:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            except IOError as e:
                logger.critical(f"[GOVERNANCE] CRITICAL: Failed to write {filepath}: {e}")
                raise RuntimeError(f"Governance state persistence failure: {e}")
    
    def load_freeze_state(self) -> FreezeState:
        """Load freeze state from disk."""
        data = self._read_json(FREEZE_STATE_FILE)
        if not data:
            return FreezeState()
        return FreezeState(**data)
    
    def save_freeze_state(self, state: FreezeState) -> None:
        """Save freeze state to disk."""
        self._write_json(FREEZE_STATE_FILE, asdict(state))
    
    def load_budget_state(self) -> SafetyBudgetState:
        """Load budget state from disk."""
        data = self._read_json(BUDGET_STATE_FILE)
        if not data:
            return SafetyBudgetState()
        return SafetyBudgetState(**data)
    
    def save_budget_state(self, state: SafetyBudgetState) -> None:
        """Save budget state to disk."""
        self._write_json(BUDGET_STATE_FILE, asdict(state))
    
    def load_domain_trust(self) -> Dict[str, DomainTrustRecord]:
        """Load domain trust records from disk."""
        data = self._read_json(DOMAIN_TRUST_FILE)
        return {k: DomainTrustRecord(**v) for k, v in data.items()}
    
    def save_domain_trust(self, records: Dict[str, DomainTrustRecord]) -> None:
        """Save domain trust records to disk."""
        data = {k: asdict(v) for k, v in records.items()}
        self._write_json(DOMAIN_TRUST_FILE, data)


# ============================================================================
# SAFETY GOVERNANCE CONTROLLER
# ============================================================================

class SafetyGovernanceController:
    """
    Central controller for all safety governance.
    
    FAIL-CLOSED BEHAVIOR:
    - If state cannot be read, assume FROZEN
    - If state cannot be written, HALT operation
    - If budget cannot be verified, DENY action
    """
    
    # Trust revalidation window (12 months)
    TRUST_REVALIDATION_DAYS = 365
    
    def __init__(self):
        self._persistence = GovernanceStatePersistence()
        self._check_initial_state()
    
    def _check_initial_state(self) -> None:
        """Check state on startup. Log warnings for any issues."""
        freeze_state = self._persistence.load_freeze_state()
        if freeze_state.is_frozen:
            logger.critical(
                f"[GOVERNANCE] SYSTEM IS FROZEN. "
                f"Reason: {freeze_state.freeze_reason}. "
                f"Incident: {freeze_state.incident_id}"
            )
    
    # ========================================================================
    # FREEZE PROTOCOL
    # ========================================================================
    
    def is_frozen(self) -> bool:
        """Check if system is in frozen state."""
        state = self._persistence.load_freeze_state()
        return state.is_frozen
    
    def get_freeze_state(self) -> FreezeState:
        """Get current freeze state."""
        return self._persistence.load_freeze_state()
    
    def trigger_freeze(
        self,
        reason: FreezeReason,
        triggered_by: str,
        incident_id: str,
        details: Optional[Dict[str, Any]] = None
    ) -> FreezeState:
        """
        TRIGGER SYSTEM FREEZE.
        
        This is a CRITICAL operation. The system will not process
        any governance changes until explicitly resumed.
        """
        state = FreezeState(
            is_frozen=True,
            frozen_at=datetime.now(timezone.utc).isoformat(),
            frozen_by=triggered_by,
            freeze_reason=reason.value,
            incident_id=incident_id,
            freeze_details=details or {}
        )
        
        self._persistence.save_freeze_state(state)
        
        logger.critical(
            f"\n{'='*70}\n"
            f"🛑 SYSTEM FREEZE TRIGGERED\n"
            f"{'='*70}\n"
            f"Reason:     {reason.value}\n"
            f"Triggered:  {triggered_by}\n"
            f"Incident:   {incident_id}\n"
            f"Time:       {state.frozen_at}\n"
            f"{'='*70}\n"
            f"GOVERNANCE OPERATIONS ARE HALTED.\n"
            f"Manual intervention required to resume.\n"
            f"{'='*70}"
        )
        
        return state
    
    def resume_from_freeze(
        self,
        resumed_by: str,
        incident_id: str,
        justification: str
    ) -> FreezeState:
        """
        RESUME FROM FREEZE STATE.
        
        Requires explicit approval with incident reference.
        """
        state = self._persistence.load_freeze_state()
        
        if not state.is_frozen:
            raise ValueError("System is not frozen")
        
        if not incident_id:
            raise ValueError("Resume requires incident_id")
        
        if not justification or len(justification) < 20:
            raise ValueError("Resume requires detailed justification (min 20 chars)")
        
        state.is_frozen = False
        state.resumed_at = datetime.now(timezone.utc).isoformat()
        state.resumed_by = resumed_by
        state.resume_justification = justification
        state.resume_incident_id = incident_id
        
        self._persistence.save_freeze_state(state)
        
        logger.warning(
            f"\n{'='*70}\n"
            f"✅ SYSTEM RESUMED FROM FREEZE\n"
            f"{'='*70}\n"
            f"Resumed by: {resumed_by}\n"
            f"Incident:   {incident_id}\n"
            f"Original:   {state.freeze_reason}\n"
            f"{'='*70}"
        )
        
        return state
    
    def assert_not_frozen(self, action: str) -> None:
        """
        Assert system is not frozen before performing action.
        
        FAIL-CLOSED: Raises exception if frozen.
        """
        if self.is_frozen():
            state = self.get_freeze_state()
            raise SystemFrozenError(
                f"Action '{action}' blocked: System is FROZEN.\n"
                f"Reason: {state.freeze_reason}\n"
                f"Incident: {state.incident_id}\n"
                f"Frozen since: {state.frozen_at}"
            )
    
    # ========================================================================
    # SAFETY BUDGET
    # ========================================================================
    
    def check_override_budget(self) -> Tuple[bool, str]:
        """
        Check if override budget allows action.
        
        Returns: (allowed, reason)
        """
        state = self._persistence.load_budget_state()
        
        # Check if window has expired (reset hourly counter)
        if state.override_window_start:
            window_start = datetime.fromisoformat(state.override_window_start)
            if datetime.now(timezone.utc) - window_start > timedelta(hours=1):
                # Reset hourly counter (but NOT across deployments)
                state.override_count_hourly = 0
                state.override_window_start = datetime.now(timezone.utc).isoformat()
                self._persistence.save_budget_state(state)
        
        if state.is_override_budget_exhausted():
            return False, f"Override budget EXHAUSTED: {state.override_count_hourly}/{state.MAX_OVERRIDES_PER_HOUR} per hour"
        
        remaining = state.MAX_OVERRIDES_PER_HOUR - state.override_count_hourly
        return True, f"Budget remaining: {remaining}/{state.MAX_OVERRIDES_PER_HOUR}"
    
    def consume_override_budget(self, context: str) -> None:
        """
        Consume one override from budget.
        
        FAIL-CLOSED: Triggers freeze if budget exhausted.
        """
        self.assert_not_frozen("consume_override_budget")
        
        allowed, reason = self.check_override_budget()
        if not allowed:
            # Trigger freeze on budget exhaustion
            self.trigger_freeze(
                reason=FreezeReason.BUDGET_EXHAUSTED,
                triggered_by="SafetyGovernanceController",
                incident_id=f"BUDGET_EXHAUSTED_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                details={"context": context, "reason": reason}
            )
            raise BudgetExhaustedError(reason)
        
        state = self._persistence.load_budget_state()
        state.override_count_hourly += 1
        if not state.override_window_start:
            state.override_window_start = datetime.now(timezone.utc).isoformat()
        self._persistence.save_budget_state(state)
        
        logger.warning(
            f"[GOVERNANCE] Override budget consumed: {state.override_count_hourly}/{state.MAX_OVERRIDES_PER_HOUR}"
        )
    
    def reset_budget(self, reset_by: str, justification: str, incident_id: str) -> None:
        """
        Manually reset budget. Requires justification.
        """
        if not justification or len(justification) < 20:
            raise ValueError("Budget reset requires detailed justification (min 20 chars)")
        
        state = self._persistence.load_budget_state()
        state.override_count_hourly = 0
        state.last_reset_at = datetime.now(timezone.utc).isoformat()
        state.last_reset_by = reset_by
        state.last_reset_justification = f"[{incident_id}] {justification}"
        self._persistence.save_budget_state(state)
        
        logger.warning(f"[GOVERNANCE] Budget reset by {reset_by}: {justification}")
    
    def report_trusted_domain_verdict(
        self, 
        domain: str, 
        verdict: str,
        risk_score: float
    ) -> None:
        """
        Report a verdict for a trusted domain.
        
        INVARIANT: Trusted domains NEVER get PHISHING.
        """
        state = self._persistence.load_budget_state()
        
        if verdict == "PHISHING":
            # CRITICAL INVARIANT VIOLATION
            state.phishing_trusted_count += 1
            self._persistence.save_budget_state(state)
            
            # Trigger immediate freeze
            self.trigger_freeze(
                reason=FreezeReason.TRUSTED_DOMAIN_PHISHING,
                triggered_by="SafetyGovernanceController",
                incident_id=f"TRUSTED_PHISHING_{domain}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                details={"domain": domain, "verdict": verdict, "risk_score": risk_score}
            )
            
            raise InvariantViolationError(
                f"CRITICAL INVARIANT VIOLATION: Trusted domain '{domain}' received PHISHING verdict!"
            )
        
        if verdict == "SUSPICIOUS":
            state.suspicious_trusted_count += 1
            self._persistence.save_budget_state(state)
            
            logger.critical(
                f"[GOVERNANCE] WARNING: Trusted domain '{domain}' received SUSPICIOUS verdict. "
                f"This should not happen if trust gate is working correctly."
            )
    
    # ========================================================================
    # CALIBRATION-GOVERNANCE COUPLING
    # ========================================================================
    
    def check_calibration_allows_governance(
        self, 
        calibration_status: CalibrationStatus,
        action: str
    ) -> Tuple[bool, str]:
        """
        Check if calibration status allows governance action.
        
        If calibration != HEALTHY:
        - Canary promotions forbidden
        - Allowlist expansions forbidden
        - Permanent overrides forbidden
        """
        forbidden_actions = [
            "canary_promotion",
            "allowlist_expansion", 
            "permanent_override"
        ]
        
        if calibration_status == CalibrationStatus.HEALTHY:
            return True, "Calibration healthy, action allowed"
        
        if action in forbidden_actions:
            return False, f"Action '{action}' forbidden: Calibration status is {calibration_status.value}"
        
        if calibration_status == CalibrationStatus.UNKNOWN:
            return False, f"Action '{action}' requires human review: Calibration status UNKNOWN"
        
        # DEGRADED allows some actions with warning
        return True, f"Warning: Calibration is {calibration_status.value}"
    
    def assert_calibration_allows(
        self, 
        calibration_status: CalibrationStatus,
        action: str
    ) -> None:
        """Assert calibration allows action. FAIL-CLOSED."""
        allowed, reason = self.check_calibration_allows_governance(calibration_status, action)
        if not allowed:
            raise CalibrationViolationError(reason)
    
    # ========================================================================
    # TEMPORAL TRUST REVALIDATION
    # ========================================================================
    
    def get_domain_trust_status(self, domain: str) -> Optional[DomainTrustRecord]:
        """Get trust status for a domain."""
        records = self._persistence.load_domain_trust()
        return records.get(domain)
    
    def register_trusted_domain(
        self,
        domain: str,
        reviewed_by: str
    ) -> DomainTrustRecord:
        """Register or revalidate a trusted domain."""
        self.assert_not_frozen("register_trusted_domain")
        
        now = datetime.now(timezone.utc)
        revalidation_date = now + timedelta(days=self.TRUST_REVALIDATION_DAYS)
        
        record = DomainTrustRecord(
            domain=domain,
            added_date=now.isoformat(),
            last_reviewed_date=now.isoformat(),
            reviewed_by=reviewed_by,
            trust_level="full",
            revalidation_required_by=revalidation_date.isoformat()
        )
        
        records = self._persistence.load_domain_trust()
        records[domain] = record
        self._persistence.save_domain_trust(records)
        
        return record
    
    def get_domains_requiring_revalidation(self) -> List[DomainTrustRecord]:
        """Get all domains that need revalidation."""
        records = self._persistence.load_domain_trust()
        return [r for r in records.values() if r.is_revalidation_overdue()]
    
    def get_domains_approaching_revalidation(self, days_threshold: int = 30) -> List[DomainTrustRecord]:
        """Get domains approaching revalidation deadline."""
        records = self._persistence.load_domain_trust()
        return [r for r in records.values() if r.days_until_revalidation() <= days_threshold]
    
    def demote_to_probation(self, domain: str) -> DomainTrustRecord:
        """Demote domain to probation status."""
        records = self._persistence.load_domain_trust()
        if domain not in records:
            raise ValueError(f"Domain '{domain}' not found in trust records")
        
        record = records[domain]
        record.trust_level = "probation"
        self._persistence.save_domain_trust(records)
        
        logger.warning(f"[GOVERNANCE] Domain '{domain}' demoted to probation")
        return record
    
    # ========================================================================
    # HUMAN ESCALATION CONTRACT
    # ========================================================================
    
    def require_human_review(
        self,
        review_type: HumanReviewType,
        required_evidence: List[str],
        prohibited_actions: List[str]
    ) -> HumanReviewRecord:
        """Create human review requirement."""
        record = HumanReviewRecord(
            review_type=review_type.value,
            required_at=datetime.now(timezone.utc).isoformat(),
            requires_evidence=required_evidence,
            prohibited_actions=prohibited_actions
        )
        
        logger.warning(
            f"[GOVERNANCE] HUMAN REVIEW REQUIRED: {review_type.value}\n"
            f"Evidence needed: {required_evidence}\n"
            f"Prohibited until review: {prohibited_actions}"
        )
        
        return record
    
    def complete_human_review(
        self,
        review: HumanReviewRecord,
        completed_by: str,
        notes: str,
        incident_reference: Optional[str] = None
    ) -> HumanReviewRecord:
        """Complete a human review checkpoint."""
        review.completed_at = datetime.now(timezone.utc).isoformat()
        review.completed_by = completed_by
        review.review_notes = notes
        review.incident_reference = incident_reference
        
        logger.info(
            f"[GOVERNANCE] Human review completed: {review.review_type} by {completed_by}"
        )
        
        return review


# ============================================================================
# CUSTOM EXCEPTIONS
# ============================================================================

class GovernanceError(Exception):
    """Base exception for governance errors."""
    pass


class SystemFrozenError(GovernanceError):
    """System is in frozen state."""
    pass


class BudgetExhaustedError(GovernanceError):
    """Safety budget has been exhausted."""
    pass


class InvariantViolationError(GovernanceError):
    """A safety invariant has been violated."""
    pass


class CalibrationViolationError(GovernanceError):
    """Calibration status prevents action."""
    pass


class RevalidationRequiredError(GovernanceError):
    """Domain requires revalidation."""
    pass


# ============================================================================
# SINGLETON INSTANCE
# ============================================================================

_governance_controller: Optional[SafetyGovernanceController] = None


def get_governance_controller() -> SafetyGovernanceController:
    """Get the global SafetyGovernanceController instance."""
    global _governance_controller
    if _governance_controller is None:
        _governance_controller = SafetyGovernanceController()
    return _governance_controller


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def assert_system_operational() -> None:
    """Assert the system is operational (not frozen)."""
    get_governance_controller().assert_not_frozen("system_operation")


def report_verdict_for_trusted_domain(domain: str, verdict: str, risk_score: float) -> None:
    """Report a verdict for a trusted domain. May trigger freeze."""
    get_governance_controller().report_trusted_domain_verdict(domain, verdict, risk_score)


def consume_override() -> None:
    """Consume one override from budget."""
    get_governance_controller().consume_override_budget("override_requested")


def is_system_frozen() -> bool:
    """Check if system is frozen."""
    return get_governance_controller().is_frozen()
