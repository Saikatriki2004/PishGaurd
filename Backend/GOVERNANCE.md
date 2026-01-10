# Trusted Domain Governance Policy

> [!CAUTION]
> This document describes **executable security policy**. All rules are enforced by `governance_engine.py`.

---

## Safety Invariants (NON-NEGOTIABLE)

| Invariant | Enforcement |
|-----------|-------------|
| Trusted domains → NEVER PHISHING | `governance_engine.py` freeze trigger |
| ML → NEVER overrides policy gates | `decision_pipeline.py` bypass |
| Missing data → NEVER increases severity | Neutral feature values |
| Drift → ONLY reduces confidence | `apply_calibration_restriction()` |
| Regressions → FAIL FAST | CI blocks on safety violations |

---

## Override Authority Boundaries

### Authority Levels

| Authority | Can Issue | Requirements |
|-----------|-----------|--------------|
| `SECURITY_TEAM` | PERMANENT, EMERGENCY | Review ticket for PERMANENT |
| `ON_CALL` | EMERGENCY only | Auto-expires in 24h |
| `CI_SYSTEM` | TESTING only | Auto-expires in 1h |

### Override Types

| Type | Duration | Approval |
|------|----------|----------|
| PERMANENT | Never expires | SECURITY_TEAM + review_ticket |
| EMERGENCY | Max 24 hours | ON_CALL or SECURITY_TEAM |
| TESTING | Max 1 hour | CI_SYSTEM automated |

### Usage

```python
from governance_engine import get_governance_engine, OverrideType, OverrideAuthority

engine = get_governance_engine()
override = engine.request_override(
    override_type=OverrideType.EMERGENCY,
    authority=OverrideAuthority.ON_CALL,
    affected_domains=["example.com"],
    reason="Production incident SEC-123",
    approved_by="on-call-engineer"
)
```

---

## Canary Promotion Workflow

### Promotion Criteria

| Criterion | Requirement |
|-----------|-------------|
| Consecutive passes | ≥ 5 |
| Sample size | ≥ 100 predictions |
| Pass rate | 100% |
| Approval | Explicit metadata required |

### Workflow

```
1. Add domain to trusted_domains_canary.json
2. Run canary tests (non-blocking)
3. Wait for 5 consecutive passes + 100 samples
4. Request promotion with:
   - approved_by
   - review_ticket
5. Update manifest + snapshot
```

### CLI

```bash
python governance_engine.py --check-canary stripe.com
```

---

## Calibration as Policy Input

| Status | Confidence Penalty | Verdict Restriction |
|--------|-------------------|---------------------|
| healthy | 0% | None |
| degraded | 20% | PHISHING → SUSPICIOUS |
| unknown | 10% | PHISHING → SUSPICIOUS |

> [!IMPORTANT]
> Degraded calibration can ONLY reduce confidence, NEVER increase severity.

---

## Safety Budgets

### Limits (per 24h window)

| Budget | Limit | Exceeded Action |
|--------|-------|-----------------|
| SUSPICIOUS on trusted | 0 | Immediate freeze |
| Emergency overrides | 3 | Freeze on 4th attempt |
| Canary failures | 5 | Freeze on 6th failure |

### Freeze Behavior

When frozen:
- ❌ No new overrides allowed
- ❌ CI must fail
- ✅ Requires manual intervention with:
  - `lifted_by`
  - `resolution`
  - `review_ticket`

---

## Policy-as-Code Verification

```bash
# Verify all policies
python governance_engine.py --verify

# Check safety status
python governance_engine.py --status
```

### CI Integration

```yaml
- name: Verify governance
  run: |
    python governance_engine.py --verify
    python governance_engine.py --status
```

---

## File Reference

| File | Purpose |
|------|---------|
| `governance_engine.py` | Executable governance rules |
| `policy_audit.py` | Audit logging |
| `trusted_domains_manifest.json` | Versioned allowlist |
| `tests/test_governance_enforcement.py` | Governance tests |
| `audit/policy_override.log` | Append-only audit trail |

---

## Quick Commands

```bash
# Verify policy consistency
python governance_engine.py --verify

# Check safety status  
python governance_engine.py --status

# List active overrides
python governance_engine.py --list-overrides

# Check canary eligibility
python governance_engine.py --check-canary domain.com

# Run governance tests
python -m pytest tests/test_governance_enforcement.py -v
```
