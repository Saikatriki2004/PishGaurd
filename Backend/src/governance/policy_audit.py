"""
Policy Audit Logger

PURPOSE:
    Record and audit all policy override events for trusted-domain governance.
    Ensures that ANY use of ALLOW_TRUSTED_DOMAIN_RECLASSIFICATION is visible and reviewable.

AUDIT REQUIREMENTS:
    1. All overrides MUST be logged (append-only)
    2. Logs MUST include: timestamp, environment, override flag, affected domains
    3. Console warnings MUST be emitted for visibility
    4. CI summaries MUST clearly state when overrides are applied

SECURITY RATIONALE:
    Policy overrides are allowed — but they must NEVER be invisible.
    This module ensures every override leaves a permanent, reviewable trail.
"""

import os
import json
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

AUDIT_LOG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "audit",
    "policy_override.log"
)

# Environment detection
ENV_CI = "CI"
ENV_LOCAL = "LOCAL"
ENV_PROD = "PROD"


class OverrideEventType(Enum):
    """Types of policy override events."""
    TRUSTED_DOMAIN_RECLASSIFICATION = "TRUSTED_DOMAIN_RECLASSIFICATION"
    ALLOWLIST_MODIFICATION = "ALLOWLIST_MODIFICATION"
    CANARY_PROMOTION = "CANARY_PROMOTION"
    THRESHOLD_OVERRIDE = "THRESHOLD_OVERRIDE"
    MANIFEST_VERSION_MISMATCH = "MANIFEST_VERSION_MISMATCH"


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class AuditLogEntry:
    """
    Structured audit log entry for policy overrides.
    
    CRITICAL: All fields are required. Missing fields indicate a logging failure.
    """
    timestamp: str  # ISO 8601 UTC
    environment: str  # CI | LOCAL | PROD
    event_type: str  # From OverrideEventType
    override_flag_value: bool
    affected_domains: List[str]
    triggering_context: str  # Test name, pipeline stage, or user action
    reason: str
    additional_data: Dict[str, Any]
    
    def to_log_line(self) -> str:
        """Format as append-only log line."""
        return (
            f"{self.timestamp} | {self.environment} | {self.event_type} | "
            f"override={self.override_flag_value} | "
            f"domains={','.join(self.affected_domains[:5])}{'...' if len(self.affected_domains) > 5 else ''} | "
            f"context={self.triggering_context} | "
            f"reason={self.reason}"
        )
    
    def to_json(self) -> str:
        """Format as JSON for structured logging."""
        return json.dumps(asdict(self), indent=None)


# ============================================================================
# AUDIT LOGGER CLASS
# ============================================================================

class PolicyAuditLogger:
    """
    Append-only audit logger for policy override events.
    
    USAGE:
        logger = PolicyAuditLogger()
        logger.log_override(
            event_type=OverrideEventType.TRUSTED_DOMAIN_RECLASSIFICATION,
            override_flag=True,
            affected_domains=["example.com"],
            context="test_false_positive_regression",
            reason="Testing override mechanism"
        )
    
    CRITICAL BEHAVIORS:
        1. Every log operation appends to file (never overwrites)
        2. Console warnings are ALWAYS emitted
        3. CI environment gets explicit summary messages
    """
    
    def __init__(self, log_path: str = AUDIT_LOG_PATH):
        """
        Initialize the audit logger.
        
        Args:
            log_path: Path to the audit log file
        """
        self.log_path = log_path
        self._ensure_log_directory()
        self._environment = self._detect_environment()
        
        logger.info(f"[AUDIT] Policy audit logger initialized: {log_path}")
    
    def _ensure_log_directory(self) -> None:
        """Ensure audit log directory exists."""
        log_dir = os.path.dirname(self.log_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    
    def _detect_environment(self) -> str:
        """
        Detect the current execution environment.
        
        Returns:
            ENV_CI, ENV_LOCAL, or ENV_PROD
        """
        # Check for common CI environment variables
        ci_indicators = [
            "CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL",
            "TRAVIS", "CIRCLECI", "AZURE_PIPELINES"
        ]
        
        for indicator in ci_indicators:
            if os.environ.get(indicator):
                return ENV_CI
        
        # Check for production indicators
        if os.environ.get("PRODUCTION") or os.environ.get("ENV") == "production":
            return ENV_PROD
        
        return ENV_LOCAL
    
    def log_override(
        self,
        event_type: OverrideEventType,
        override_flag: bool,
        affected_domains: List[str],
        context: str,
        reason: str,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> AuditLogEntry:
        """
        Log a policy override event.
        
        This method:
        1. Creates structured log entry
        2. Appends to audit log file
        3. Emits console warning
        4. Returns the entry for caller use
        
        Args:
            event_type: Type of override event
            override_flag: Value of the override flag
            affected_domains: List of domains affected
            context: Where/why this is happening
            reason: Human-readable explanation
            additional_data: Any extra context
            
        Returns:
            AuditLogEntry that was logged
        """
        entry = AuditLogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            environment=self._environment,
            event_type=event_type.value,
            override_flag_value=override_flag,
            affected_domains=affected_domains,
            triggering_context=context,
            reason=reason,
            additional_data=additional_data or {}
        )
        
        # Append to log file
        self._append_to_log(entry)
        
        # Emit console warning (ALWAYS)
        self._emit_console_warning(entry)
        
        return entry
    
    def _append_to_log(self, entry: AuditLogEntry) -> None:
        """Append entry to audit log file."""
        try:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(entry.to_log_line() + "\n")
                f.write(f"  JSON: {entry.to_json()}\n")
        except IOError as e:
            # Log failure is itself a security event
            logger.error(f"[AUDIT] CRITICAL: Failed to write audit log: {e}")
            raise RuntimeError(f"Audit logging failure: {e}")
    
    def _emit_console_warning(self, entry: AuditLogEntry) -> None:
        """
        Emit visible console warning about the override.
        
        CRITICAL: This warning must NEVER be silenced.
        """
        warning_lines = [
            "",
            "=" * 70,
            "⚠️  POLICY OVERRIDE DETECTED",
            "=" * 70,
            f"Event Type:     {entry.event_type}",
            f"Override Value: {entry.override_flag_value}",
            f"Environment:    {entry.environment}",
            f"Context:        {entry.triggering_context}",
            f"Reason:         {entry.reason}",
            f"Affected:       {', '.join(entry.affected_domains[:3])}{'...' if len(entry.affected_domains) > 3 else ''}",
            "",
            "Documentation: See trusted_domains_manifest.json for policy governance",
            "=" * 70,
            ""
        ]
        
        for line in warning_lines:
            logger.warning(line)
        
        # Also print to stderr for CI visibility
        import sys
        for line in warning_lines:
            print(line, file=sys.stderr)
    
    def log_manifest_change(
        self,
        old_version: str,
        new_version: str,
        domains_added: List[str],
        domains_removed: List[str],
        change_reason: str,
        changed_by: str
    ) -> AuditLogEntry:
        """
        Log a manifest version change.
        
        This should be called whenever trusted_domains_manifest.json is updated.
        """
        return self.log_override(
            event_type=OverrideEventType.ALLOWLIST_MODIFICATION,
            override_flag=True,
            affected_domains=domains_added + domains_removed,
            context=f"manifest_change_{old_version}_to_{new_version}",
            reason=change_reason,
            additional_data={
                "old_version": old_version,
                "new_version": new_version,
                "domains_added": domains_added,
                "domains_removed": domains_removed,
                "changed_by": changed_by
            }
        )
    
    def log_canary_promotion(
        self,
        domain: str,
        consecutive_passes: int,
        approved_by: str
    ) -> AuditLogEntry:
        """
        Log promotion of a canary domain to regression set.
        """
        return self.log_override(
            event_type=OverrideEventType.CANARY_PROMOTION,
            override_flag=False,  # Promotion is not an override
            affected_domains=[domain],
            context="canary_to_regression_promotion",
            reason=f"Domain passed {consecutive_passes} consecutive canary tests",
            additional_data={
                "consecutive_passes": consecutive_passes,
                "approved_by": approved_by,
                "promotion_date": datetime.now(timezone.utc).isoformat()
            }
        )
    
    def get_recent_overrides(self, limit: int = 10) -> List[str]:
        """
        Get recent override log entries.
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List of recent log lines
        """
        if not os.path.exists(self.log_path):
            return []
        
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
            return lines[-limit:]
        except IOError:
            return []
    
    def check_override_flag_status(self) -> bool:
        """
        Check if the ALLOW_TRUSTED_DOMAIN_RECLASSIFICATION flag is enabled.
        
        This flag allows tests to override trusted domain verdicts for testing purposes.
        
        Returns:
            True if override is enabled
        """
        return os.environ.get("ALLOW_TRUSTED_DOMAIN_RECLASSIFICATION", "").lower() == "true"


# ============================================================================
# MANIFEST GOVERNANCE
# ============================================================================

class ManifestGovernance:
    """
    Enforce governance rules for trusted domain manifest changes.
    
    RULES:
        1. Version MUST be bumped for any domain change
        2. change_reason MUST be provided
        3. Snapshot MUST match manifest domains
    """
    
    MANIFEST_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "trusted_domains_manifest.json"
    )
    
    SNAPSHOT_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "tests", "fixtures", "trusted_domains_snapshot.json"
    )
    
    def __init__(self):
        """Initialize manifest governance checker."""
        self.audit_logger = PolicyAuditLogger()
    
    def load_manifest(self) -> Dict[str, Any]:
        """Load the trusted domains manifest."""
        if not os.path.exists(self.MANIFEST_PATH):
            raise FileNotFoundError(f"Manifest not found: {self.MANIFEST_PATH}")
        
        with open(self.MANIFEST_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def load_snapshot(self) -> Dict[str, Any]:
        """Load the regression snapshot."""
        if not os.path.exists(self.SNAPSHOT_PATH):
            raise FileNotFoundError(f"Snapshot not found: {self.SNAPSHOT_PATH}")
        
        with open(self.SNAPSHOT_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def validate_manifest(self) -> List[str]:
        """
        Validate manifest against governance rules.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        try:
            manifest = self.load_manifest()
        except FileNotFoundError as e:
            return [str(e)]
        
        # Rule 1: Version must be present
        if not manifest.get("version"):
            errors.append("Manifest missing 'version' field")
        
        # Rule 2: change_reason must be present and non-empty
        change_reason = manifest.get("change_reason", "")
        if not change_reason or change_reason.strip() == "":
            errors.append("Manifest missing or empty 'change_reason' field")
        
        # Rule 3: last_modified_by must be present
        if not manifest.get("last_modified_by"):
            errors.append("Manifest missing 'last_modified_by' field")
        
        # Rule 4: domains list must exist
        if "domains" not in manifest:
            errors.append("Manifest missing 'domains' list")
        
        return errors
    
    def compare_manifest_to_snapshot(self) -> Dict[str, Any]:
        """
        Compare manifest domains to snapshot domains.
        
        Returns:
            Dict with added, removed, and matched domains
        """
        try:
            manifest = self.load_manifest()
            snapshot = self.load_snapshot()
        except FileNotFoundError as e:
            return {"error": str(e)}
        
        manifest_domains = set(d["domain"] for d in manifest.get("domains", []))
        snapshot_domains = set(snapshot.get("regression_domains", []))
        
        added = manifest_domains - snapshot_domains
        removed = snapshot_domains - manifest_domains
        matched = manifest_domains & snapshot_domains
        
        return {
            "manifest_version": manifest.get("version"),
            "snapshot_version": snapshot.get("_manifest_version"),
            "domains_added": list(added),
            "domains_removed": list(removed),
            "domains_matched": list(matched),
            "versions_match": manifest.get("version") == snapshot.get("_manifest_version"),
            "requires_review": len(added) > 0 or len(removed) > 0
        }
    
    def enforce_snapshot_sync(self) -> None:
        """
        Enforce that snapshot matches manifest.
        
        Raises CI-blocking error if mismatch detected.
        """
        comparison = self.compare_manifest_to_snapshot()
        
        if "error" in comparison:
            raise RuntimeError(f"Governance check failed: {comparison['error']}")
        
        if comparison["requires_review"]:
            # Log the discrepancy
            self.audit_logger.log_override(
                event_type=OverrideEventType.MANIFEST_VERSION_MISMATCH,
                override_flag=False,
                affected_domains=comparison["domains_added"] + comparison["domains_removed"],
                context="ci_governance_check",
                reason="Manifest and snapshot are out of sync",
                additional_data=comparison
            )
            
            error_msg = (
                f"\n{'='*70}\n"
                f"GOVERNANCE FAILURE: Manifest/Snapshot Mismatch\n"
                f"{'='*70}\n"
                f"Manifest version: {comparison['manifest_version']}\n"
                f"Snapshot version: {comparison['snapshot_version']}\n"
                f"Domains added:    {comparison['domains_added']}\n"
                f"Domains removed:  {comparison['domains_removed']}\n"
                f"\n"
                f"ACTION REQUIRED:\n"
                f"1. Update snapshot to match manifest\n"
                f"2. Bump manifest version\n"
                f"3. Document change_reason in manifest\n"
                f"{'='*70}\n"
            )
            
            raise RuntimeError(error_msg)


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

_default_logger: Optional[PolicyAuditLogger] = None


def get_audit_logger() -> PolicyAuditLogger:
    """Get the default PolicyAuditLogger instance."""
    global _default_logger
    if _default_logger is None:
        _default_logger = PolicyAuditLogger()
    return _default_logger


def log_policy_override(
    event_type: OverrideEventType,
    override_flag: bool,
    affected_domains: List[str],
    context: str,
    reason: str
) -> None:
    """Convenience function to log a policy override."""
    get_audit_logger().log_override(
        event_type=event_type,
        override_flag=override_flag,
        affected_domains=affected_domains,
        context=context,
        reason=reason
    )


def check_override_enabled() -> bool:
    """Check if trusted domain reclassification override is enabled."""
    return get_audit_logger().check_override_flag_status()


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Policy Audit Logger CLI")
    parser.add_argument("--validate-manifest", action="store_true",
                        help="Validate manifest governance rules")
    parser.add_argument("--compare-snapshot", action="store_true",
                        help="Compare manifest to snapshot")
    parser.add_argument("--recent-overrides", type=int, default=10,
                        help="Show N recent override log entries")
    
    args = parser.parse_args()
    
    if args.validate_manifest:
        gov = ManifestGovernance()
        errors = gov.validate_manifest()
        if errors:
            print("❌ Manifest validation FAILED:")
            for error in errors:
                print(f"  - {error}")
            exit(1)
        else:
            print("✅ Manifest validation passed")
    
    elif args.compare_snapshot:
        gov = ManifestGovernance()
        comparison = gov.compare_manifest_to_snapshot()
        print(json.dumps(comparison, indent=2))
        if comparison.get("requires_review"):
            print("\n⚠️  Review required: manifest and snapshot are different")
            exit(1)
    
    elif args.recent_overrides:
        audit_logger = PolicyAuditLogger()
        entries = audit_logger.get_recent_overrides(args.recent_overrides)
        if entries:
            print("Recent policy overrides:")
            for entry in entries:
                print(f"  {entry}")
        else:
            print("No recent overrides found")
    
    else:
        parser.print_help()
