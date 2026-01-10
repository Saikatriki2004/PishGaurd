"""
Manifest-Runtime Synchronization Tests

PURPOSE:
    Ensure governance documents (manifest) match executable rules (runtime).
    Documentation drift is treated as a SAFETY FAILURE.

WHAT THIS FILE PROTECTS AGAINST:
    - Manifest domains not enforced at runtime
    - Runtime domains without governance record
    - Snapshot drift from manifest
    - Silent policy changes

CI BEHAVIOR:
    - Sync violations BLOCK deployment
    - Undocumented runtime domains emit CI warnings
"""

import pytest
import json
import os
import sys
from typing import Set

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trusted_domains import TRUSTED_DOMAINS, TrustedDomainChecker


# ============================================================================
# PATHS
# ============================================================================

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(PROJECT_ROOT, "trusted_domains_manifest.json")
SNAPSHOT_PATH = os.path.join(PROJECT_ROOT, "tests", "fixtures", "trusted_domains_snapshot.json")


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def manifest_data():
    """Load the trusted domains manifest."""
    with open(MANIFEST_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


@pytest.fixture
def snapshot_data():
    """Load the regression snapshot."""
    with open(SNAPSHOT_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


@pytest.fixture
def manifest_domains(manifest_data) -> Set[str]:
    """Extract domain set from manifest."""
    return {d["domain"] for d in manifest_data.get("domains", [])}


@pytest.fixture
def snapshot_domains(snapshot_data) -> Set[str]:
    """Extract domain set from snapshot."""
    return set(snapshot_data.get("regression_domains", []))


# ============================================================================
# TEST CLASS 1: MANIFEST COMPLETENESS
# ============================================================================

class TestManifestCompleteness:
    """Verify manifest is complete and valid."""
    
    def test_manifest_exists(self):
        """Manifest file must exist."""
        assert os.path.exists(MANIFEST_PATH), (
            f"GOVERNANCE FAILURE: Manifest missing at {MANIFEST_PATH}"
        )
    
    def test_manifest_has_required_fields(self, manifest_data):
        """Manifest must have all required governance fields."""
        required_fields = ["version", "change_reason", "last_modified_by", "domains"]
        
        for field in required_fields:
            assert field in manifest_data, (
                f"GOVERNANCE FAILURE: Manifest missing required field: {field}"
            )
    
    def test_manifest_domains_nonempty(self, manifest_domains):
        """Manifest must have at least one domain."""
        assert len(manifest_domains) > 0, (
            "GOVERNANCE FAILURE: Manifest has no domains"
        )


# ============================================================================
# TEST CLASS 2: MANIFEST-RUNTIME SYNC
# ============================================================================

class TestManifestRuntimeSync:
    """Verify manifest domains are enforced at runtime."""
    
    def test_all_manifest_domains_in_runtime(self, manifest_domains):
        """
        Every manifest domain MUST be in runtime TRUSTED_DOMAINS.
        
        PROTECTS AGAINST: Documented trust not actually enforced.
        """
        missing_from_runtime = manifest_domains - TRUSTED_DOMAINS
        
        assert len(missing_from_runtime) == 0, (
            f"GOVERNANCE FAILURE: Manifest domains NOT in runtime!\n"
            f"Domains in manifest but not enforced:\n"
            f"{sorted(missing_from_runtime)}\n\n"
            f"These domains are documented as trusted but will NOT bypass ML!"
        )
    
    def test_all_manifest_domains_trusted_by_checker(self, manifest_domains):
        """
        Every manifest domain must pass TrustedDomainChecker.
        
        PROTECTS AGAINST: Checker logic not matching allowlist.
        """
        checker = TrustedDomainChecker()
        failures = []
        
        for domain in manifest_domains:
            result = checker.check(f"https://{domain}")
            if not result.is_trusted:
                failures.append({
                    "domain": domain,
                    "reason": result.reason
                })
        
        assert len(failures) == 0, (
            f"GOVERNANCE FAILURE: Manifest domains fail trust check!\n"
            f"Failures:\n" + "\n".join(f"  {f['domain']}: {f['reason']}" for f in failures)
        )
    
    def test_undocumented_runtime_domains_flagged(self, manifest_domains):
        """
        Runtime domains without manifest entry emit warning.
        
        This is a WARNING, not a failure - for legacy compatibility.
        """
        undocumented = TRUSTED_DOMAINS - manifest_domains
        
        if undocumented:
            import sys
            print(
                f"\n⚠️  WARNING: {len(undocumented)} runtime domains lack manifest entries:\n"
                f"  {sorted(list(undocumented)[:10])}{'...' if len(undocumented) > 10 else ''}\n"
                f"Consider adding governance documentation for these domains.",
                file=sys.stderr
            )


# ============================================================================
# TEST CLASS 3: SNAPSHOT-MANIFEST SYNC
# ============================================================================

class TestSnapshotManifestSync:
    """Verify snapshot is subset of manifest."""
    
    def test_snapshot_is_manifest_subset(self, manifest_domains, snapshot_domains):
        """
        Regression snapshot MUST be subset of manifest.
        
        PROTECTS AGAINST: Testing domains not in governance.
        """
        not_in_manifest = snapshot_domains - manifest_domains
        
        assert len(not_in_manifest) == 0, (
            f"GOVERNANCE FAILURE: Snapshot domains not in manifest!\n"
            f"Domains tested but not governed:\n"
            f"{sorted(not_in_manifest)}\n\n"
            f"Add these to manifest or remove from snapshot."
        )
    
    def test_snapshot_version_matches_manifest(self, manifest_data, snapshot_data):
        """Snapshot version must match manifest version."""
        manifest_version = manifest_data.get("version")
        snapshot_version = snapshot_data.get("_manifest_version")
        
        assert manifest_version == snapshot_version, (
            f"GOVERNANCE FAILURE: Version mismatch!\n"
            f"Manifest: {manifest_version}\n"
            f"Snapshot: {snapshot_version}\n\n"
            f"Update snapshot _manifest_version to match."
        )


# ============================================================================
# TEST CLASS 4: ADVERSARIAL DOMAIN TESTS
# ============================================================================

class TestAdversarialDomainParsing:
    """Test that domain parsing attacks are blocked."""
    
    @pytest.mark.parametrize("spoofed_domain,should_be_trusted", [
        # Subdomain spoofing - should NOT be trusted
        ("google.com.evil.xyz", False),
        ("accounts.google.com.malicious.com", False),
        ("microsoft.com.phishing.net", False),
        
        # Hyphen injection - should NOT be trusted  
        ("google-login.com", False),
        ("accounts-google.com", False),
        ("microsoft-security.com", False),
        
        # Lookalike characters - should NOT be trusted
        ("go0gle.com", False),    # Zero instead of 'o'
        ("goog1e.com", False),    # One instead of 'l'
        ("micr0soft.com", False), # Zero instead of 'o'
        
        # Legitimate subdomains - SHOULD be trusted
        ("accounts.google.com", True),
        ("mail.google.com", True),
        ("login.microsoft.com", True),
        ("www.github.com", True),
    ])
    def test_spoofed_and_legitimate_domains(self, spoofed_domain, should_be_trusted):
        """
        Verify spoofed domains rejected, legitimate subdomains accepted.
        
        PROTECTS AGAINST: Domain parsing attacks bypassing trust.
        """
        checker = TrustedDomainChecker()
        result = checker.check(spoofed_domain)
        
        if should_be_trusted:
            assert result.is_trusted, (
                f"Legitimate domain incorrectly rejected: {spoofed_domain}\n"
                f"Reason: {result.reason}"
            )
        else:
            assert not result.is_trusted, (
                f"SECURITY FAILURE: Spoofed domain accepted as trusted!\n"
                f"Domain: {spoofed_domain}\n"
                f"This is a potential bypass attack."
            )


# ============================================================================
# TEST CLASS 5: MANIFEST GOVERNANCE FIELDS
# ============================================================================

class TestManifestGovernanceFields:
    """Test governance metadata is complete."""
    
    def test_all_domains_have_added_by(self, manifest_data):
        """All domains must have attribution."""
        for entry in manifest_data.get("domains", []):
            assert "added_by" in entry, (
                f"Domain {entry.get('domain')} missing 'added_by'"
            )
    
    def test_all_domains_have_reason(self, manifest_data):
        """All domains must have documented reason."""
        for entry in manifest_data.get("domains", []):
            reason = entry.get("reason", "")
            assert reason and len(reason) > 10, (
                f"Domain {entry.get('domain')} missing or insufficient 'reason'"
            )
    
    def test_all_domains_have_added_date(self, manifest_data):
        """All domains must have added date."""
        for entry in manifest_data.get("domains", []):
            assert "added_date" in entry, (
                f"Domain {entry.get('domain')} missing 'added_date'"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
