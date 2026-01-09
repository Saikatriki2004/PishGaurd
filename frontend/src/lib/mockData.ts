/**
 * Mock Data for PhishGuard Frontend Development
 * 
 * Use this data when the Flask backend is not running.
 * Set NEXT_PUBLIC_USE_MOCKS=true to enable.
 */

import type {
    ScanResponse,
    GovernanceStatus,
    LiveThreat,
    ThreatData,
} from '@/types';

// ============================================================================
// MOCK CONFIGURATION
// ============================================================================

export const USE_MOCKS = process.env.NEXT_PUBLIC_USE_MOCKS === 'true';

// ============================================================================
// SCAN RESPONSE MOCKS
// ============================================================================

export const mockSafeScanResponse: ScanResponse = {
    success: true,
    verdict: 'SAFE',
    risk_score: 12.5,
    is_trusted_domain: true,
    ml_bypassed: true,
    explanation: {
        summary: 'This URL belongs to a trusted domain.',
        positive: [
            'Domain is on trusted list',
            'Valid SSL certificate',
            'Established domain (10+ years)',
        ],
        risk: [],
        inconclusive: [],
        analysis_complete: true,
        allowlist_override: true,
    },
    warnings: [],
    url: 'https://google.com',
    risk_level: 'Low Risk',
    latency_ms: 45.2,
    trust_info: {
        is_trusted: true,
        reason: 'Domain in trusted manifest',
        source: 'trusted_domains_manifest.json',
        registered_domain: 'google.com',
    },
};

export const mockPhishingScanResponse: ScanResponse = {
    success: true,
    verdict: 'PHISHING',
    risk_score: 92.8,
    is_trusted_domain: false,
    ml_bypassed: false,
    explanation: {
        summary: 'High-risk URL with multiple red flags detected.',
        positive: [],
        risk: [
            'Suspicious URL pattern detected (login-microsoft-secure)',
            'Domain registered within last 30 days',
            'No valid SSL certificate',
            'Known phishing kit signature',
        ],
        inconclusive: ['WHOIS lookup timed out'],
        analysis_complete: true,
        allowlist_override: false,
        blocklist_match: true,
    },
    warnings: ['Network timeout during analysis'],
    url: 'http://login-microsoft-secure.xyz/auth',
    risk_level: 'Critical',
    latency_ms: 234.8,
    network_issues: {
        http_failed: false,
        whois_failed: true,
        dns_failed: false,
        ssl_failed: true,
    },
};

export const mockSuspiciousScanResponse: ScanResponse = {
    success: true,
    verdict: 'SUSPICIOUS',
    risk_score: 67.3,
    is_trusted_domain: false,
    ml_bypassed: false,
    explanation: {
        summary: 'URL shows some concerning patterns but not definitively malicious.',
        positive: ['Valid SSL certificate'],
        risk: [
            'Unusual subdomain pattern',
            'Domain age less than 6 months',
        ],
        inconclusive: [
            'Unable to verify organization',
            'Limited DNS history',
        ],
        analysis_complete: true,
        allowlist_override: false,
    },
    warnings: [],
    url: 'https://secure-banking-update.com/verify',
    risk_level: 'Moderate Risk',
    latency_ms: 156.4,
};

// ============================================================================
// GOVERNANCE STATUS MOCKS
// ============================================================================

export const mockGovernanceNormal: GovernanceStatus = {
    is_frozen: false,
    freeze_reason: null,
    frozen_at: null,
    frozen_by: null,
    incident_id: null,
    budget: {
        override_count_hourly: 1,
        max_overrides_per_hour: 5,
        budget_exhausted: false,
        window_start: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    },
    health: {
        pipeline_ready: true,
        model_type: 'CalibratedClassifierCV',
        governance_available: true,
    },
};

export const mockGovernanceFrozen: GovernanceStatus = {
    is_frozen: true,
    freeze_reason: 'Canary failure budget exceeded - 6 consecutive failures detected',
    frozen_at: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    frozen_by: 'Governance Engine (Automated)',
    incident_id: 'INC-20260108-001',
    budget: {
        override_count_hourly: 5,
        max_overrides_per_hour: 5,
        budget_exhausted: true,
        window_start: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    },
    health: {
        pipeline_ready: true,
        model_type: 'CalibratedClassifierCV',
        governance_available: true,
    },
};

// ============================================================================
// LIVE THREAT FEED MOCKS
// ============================================================================

export const mockLiveThreats: LiveThreat[] = [
    {
        id: 'LIVE-203045-0',
        label: 'Malware C2',
        entity: '192.168.45.22 → FinCorp',
        location: 'Moscow, RU',
        severity: 'critical',
        timestamp: new Date(Date.now() - 1000 * 5).toISOString(),
    },
    {
        id: 'LIVE-203044-1',
        label: 'Cred Harvester',
        entity: 'login-microsoft-secure.com',
        location: 'Lagos, NG',
        severity: 'critical',
        timestamp: new Date(Date.now() - 1000 * 12).toISOString(),
    },
    {
        id: 'LIVE-203043-2',
        label: 'Port Scan',
        entity: '10.0.4.120 → Gateway',
        location: 'Shenzhen, CN',
        severity: 'suspicious',
        timestamp: new Date(Date.now() - 1000 * 28).toISOString(),
    },
    {
        id: 'LIVE-203042-3',
        label: 'Phishing Kit',
        entity: 'secure-paypal-verify.net',
        location: 'São Paulo, BR',
        severity: 'critical',
        timestamp: new Date(Date.now() - 1000 * 45).toISOString(),
    },
    {
        id: 'LIVE-203041-4',
        label: 'Ransomware',
        entity: '45.33.32.156 → AWS-EC2',
        location: 'Kyiv, UA',
        severity: 'suspicious',
        timestamp: new Date(Date.now() - 1000 * 58).toISOString(),
    },
];

// ============================================================================
// THREAT MAP DATA MOCKS
// ============================================================================

export const mockThreatMapData: ThreatData[] = [
    {
        threat_id: 'THR-0001-120000',
        type: 'credential_harvesting',
        severity: 'critical',
        source: { lat: 55.75, lng: 37.62 },
        target: { lat: 40.71, lng: -74.01 },
        attack_vector: 'email',
        timestamp: new Date(Date.now() - 1000 * 30).toISOString(),
    },
    {
        threat_id: 'THR-0002-120015',
        type: 'malware',
        severity: 'critical',
        source: { lat: 31.23, lng: 121.47 },
        target: { lat: 51.51, lng: -0.13 },
        attack_vector: 'web',
        timestamp: new Date(Date.now() - 1000 * 45).toISOString(),
    },
    {
        threat_id: 'THR-0003-120030',
        type: 'social_engineering',
        severity: 'suspicious',
        source: { lat: 6.52, lng: 3.38 },
        target: { lat: 37.77, lng: -122.42 },
        attack_vector: 'sms',
        timestamp: new Date(Date.now() - 1000 * 60).toISOString(),
    },
    {
        threat_id: 'THR-0004-120100',
        type: 'credential_harvesting',
        severity: 'critical',
        source: { lat: 22.57, lng: 114.06 },
        target: { lat: 48.86, lng: 2.35 },
        attack_vector: 'email',
        timestamp: new Date(Date.now() - 1000 * 120).toISOString(),
    },
    {
        threat_id: 'THR-0005-120200',
        type: 'malware',
        severity: 'suspicious',
        source: { lat: -23.55, lng: -46.64 },
        target: { lat: 35.68, lng: 139.69 },
        attack_vector: 'network',
        timestamp: new Date(Date.now() - 1000 * 180).toISOString(),
    },
];

// ============================================================================
// MOCK REGIONS DATA
// ============================================================================

export const mockThreatRegions = [
    { region: 'Eastern Europe', count: 4281 },
    { region: 'Southeast Asia', count: 2104 },
    { region: 'North America', count: 982 },
    { region: 'South America', count: 756 },
    { region: 'Africa', count: 543 },
];
