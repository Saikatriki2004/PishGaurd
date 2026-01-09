/**
 * PhishGuard API Type Definitions
 * 
 * These types strictly match the Flask API responses
 * to ensure type safety across the frontend.
 */

// ============================================================================
// SCAN API TYPES
// ============================================================================

/**
 * Matches the /scan endpoint response from app.py
 */
export interface ScanResponse {
  success: boolean;
  verdict: VerdictType;
  risk_score: number;
  is_trusted_domain: boolean;
  ml_bypassed: boolean;
  explanation: ExplanationData;
  warnings: string[];
  url: string;
  risk_level: string;
  latency_ms: number;
  trust_info?: TrustInfo;
  network_issues?: NetworkIssues;
}

export type VerdictType = 'SAFE' | 'SUSPICIOUS' | 'PHISHING';

export interface ExplanationData {
  summary: string;
  positive: string[];
  risk: string[];
  inconclusive: string[];
  analysis_complete: boolean;
  allowlist_override: boolean;
  blocklist_match?: boolean;
}

export interface TrustInfo {
  is_trusted: boolean;
  reason: string;
  source: string;
  registered_domain: string;
}

export interface NetworkIssues {
  http_failed: boolean;
  whois_failed: boolean;
  dns_failed: boolean;
  ssl_failed: boolean;
}

/**
 * Error response when system is frozen (503)
 */
export interface FrozenErrorResponse {
  error: 'SYSTEM FROZEN';
  reason: string;
  actions: string;
}

/**
 * Generic API error response
 */
export interface ApiErrorResponse {
  success: false;
  error: string;
}

// ============================================================================
// GOVERNANCE API TYPES
// ============================================================================

/**
 * Matches /api/governance/status endpoint response
 */
export interface GovernanceStatus {
  is_frozen: boolean;
  freeze_reason: string | null;
  frozen_at: string | null;
  frozen_by: string | null;
  incident_id: string | null;
  budget: BudgetStatus;
  health: HealthStatus;
}

export interface BudgetStatus {
  override_count_hourly: number;
  max_overrides_per_hour: number;
  budget_exhausted: boolean;
  window_start: string | null;
}

export interface HealthStatus {
  pipeline_ready: boolean;
  model_type: string;
  governance_available: boolean;
}

/**
 * Unfreeze request payload
 */
export interface UnfreezeRequest {
  force: true;
}

/**
 * Unfreeze response
 */
export interface UnfreezeResponse {
  success: boolean;
  message?: string;
  error?: string;
}

// ============================================================================
// THREAT MAP API TYPES
// ============================================================================

/**
 * Matches /api/threats/map-data response items
 */
export interface ThreatData {
  threat_id: string;
  type: ThreatType;
  severity: SeverityLevel;
  source: GeoLocation;
  target: GeoLocation;
  attack_vector: AttackVector;
  timestamp: string; // ISO-8601
}

export type ThreatType = 'malware' | 'credential_harvesting' | 'social_engineering';
export type SeverityLevel = 'critical' | 'suspicious' | 'safe';
export type AttackVector = 'email' | 'sms' | 'web' | 'network';

export interface GeoLocation {
  lat: number;
  lng: number;
}

// ============================================================================
// LIVE THREAT FEED TYPES
// ============================================================================

/**
 * Matches /api/threats/live response items
 */
export interface LiveThreat {
  id: string;
  label: string;
  entity: string;
  location: string;
  severity: SeverityLevel;
  timestamp: string; // ISO-8601
}

// ============================================================================
// BATCH SCAN TYPES
// ============================================================================

export interface BatchScanRequest {
  urls: string[];
}

export interface BatchScanResponse {
  success: boolean;
  results: BatchScanResult[];
  total: number;
  phishing_count: number;
  safe_count: number;
  suspicious_count: number;
}

export interface BatchScanResult {
  url: string;
  verdict: VerdictType | 'ERROR';
  risk_score?: number;
  is_trusted_domain?: boolean;
  ml_bypassed?: boolean;
  error?: string;
}

// ============================================================================
// SETTINGS TYPES
// ============================================================================

export interface AppSettings {
  theme: 'light' | 'dark' | 'system';
  apiEndpoint: string;
  safetyThresholds: SafetyThresholds;
}

export interface SafetyThresholds {
  phishing_threshold: number;  // Default: 0.85
  suspicious_threshold: number; // Default: 0.55
  max_overrides_per_hour: number; // Default: 5
}

// ============================================================================
// TRUSTED DOMAINS TYPES
// ============================================================================

export interface TrustedDomainsResponse {
  sample_trusted_domains: string[];
  total_trusted: number;
  note: string;
}

// ============================================================================
// TELEMETRY TYPES
// ============================================================================

export interface TelemetrySummary {
  total_scans: number;
  verdict_counts: {
    SAFE: number;
    SUSPICIOUS: number;
    PHISHING: number;
  };
  average_latency_ms: number;
  drift_warnings: number;
}
