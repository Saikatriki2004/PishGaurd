/**
 * PhishGuard API Client
 * 
 * Robust API layer with proper error handling,
 * governance freeze detection, and type safety.
 */

import type {
    ScanResponse,
    FrozenErrorResponse,
    ApiErrorResponse,
    GovernanceStatus,
    UnfreezeResponse,
    ThreatData,
    LiveThreat,
    BatchScanRequest,
    BatchScanResponse,
    TrustedDomainsResponse,
    TelemetrySummary,
} from '@/types';

// ============================================================================
// CONFIGURATION
// ============================================================================

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:5000';

// Mock admin key for development - in production, use secure key management
const DEV_ADMIN_KEY = process.env.NEXT_PUBLIC_ADMIN_KEY || 'phishguard-dev-admin-key-2026';

// ============================================================================
// CUSTOM ERROR CLASSES
// ============================================================================

/**
 * Error thrown when the system is frozen (503 response)
 */
export class GovernanceFreezeError extends Error {
    public readonly reason: string;
    public readonly actions: string;
    public readonly statusCode = 503;

    constructor(data: FrozenErrorResponse) {
        super('System is frozen by Governance Engine');
        this.name = 'GovernanceFreezeError';
        this.reason = data.reason;
        this.actions = data.actions;
    }
}

/**
 * Generic API error
 */
export class ApiError extends Error {
    public readonly statusCode: number;

    constructor(message: string, statusCode: number) {
        super(message);
        this.name = 'ApiError';
        this.statusCode = statusCode;
    }
}

// ============================================================================
// BASE FETCH WRAPPER
// ============================================================================

interface FetchOptions extends RequestInit {
    requiresAuth?: boolean;
}

async function apiFetch<T>(
    endpoint: string,
    options: FetchOptions = {}
): Promise<T> {
    const { requiresAuth = false, ...fetchOptions } = options;

    const headers: HeadersInit = {
        'Content-Type': 'application/json',
        ...fetchOptions.headers,
    };

    // Add admin key for authenticated endpoints
    if (requiresAuth) {
        (headers as Record<string, string>)['X-Admin-Key'] = DEV_ADMIN_KEY;
    }

    const url = `${API_BASE_URL}${endpoint}`;

    try {
        const response = await fetch(url, {
            ...fetchOptions,
            headers,
        });

        // Handle 503 - System Frozen
        if (response.status === 503) {
            const errorData = await response.json() as FrozenErrorResponse;
            throw new GovernanceFreezeError(errorData);
        }

        // Handle other errors
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({})) as ApiErrorResponse;
            throw new ApiError(
                errorData.error || `HTTP error ${response.status}`,
                response.status
            );
        }

        return await response.json() as T;
    } catch (error) {
        // Re-throw our custom errors
        if (error instanceof GovernanceFreezeError || error instanceof ApiError) {
            throw error;
        }

        // Network errors
        throw new ApiError(
            error instanceof Error ? error.message : 'Network error',
            0
        );
    }
}

// ============================================================================
// SCAN API
// ============================================================================

/**
 * Scan a single URL for phishing threats
 */
export async function scanUrl(url: string): Promise<ScanResponse> {
    return apiFetch<ScanResponse>('/scan', {
        method: 'POST',
        body: JSON.stringify({ url }),
    });
}

/**
 * Batch scan multiple URLs
 */
export async function batchScanUrls(urls: string[]): Promise<BatchScanResponse> {
    const request: BatchScanRequest = { urls };
    return apiFetch<BatchScanResponse>('/api/batch-scan', {
        method: 'POST',
        body: JSON.stringify(request),
    });
}

// ============================================================================
// GOVERNANCE API
// ============================================================================

/**
 * Get current governance status including freeze state and budget
 */
export async function getGovernanceStatus(): Promise<GovernanceStatus> {
    return apiFetch<GovernanceStatus>('/api/governance/status');
}

/**
 * Emergency unfreeze the system
 * Requires admin authorization
 * 
 * @param ticket - Incident ticket reference (for audit trail)
 */
export async function unfreezeSystem(ticket: string): Promise<UnfreezeResponse> {
    return apiFetch<UnfreezeResponse>('/api/governance/unfreeze', {
        method: 'POST',
        body: JSON.stringify({ force: true, ticket }),
        requiresAuth: true,
    });
}

/**
 * Check if the system is currently frozen
 * Lightweight check without full status
 */
export async function isSystemFrozen(): Promise<boolean> {
    try {
        const status = await getGovernanceStatus();
        return status.is_frozen;
    } catch (error) {
        if (error instanceof GovernanceFreezeError) {
            return true;
        }
        throw error;
    }
}

// ============================================================================
// THREAT MAP API
// ============================================================================

/**
 * Get threat map data for visualization
 */
export async function getThreatMapData(): Promise<ThreatData[]> {
    return apiFetch<ThreatData[]>('/api/threats/map-data');
}

/**
 * Get live threat feed
 */
export async function getLiveThreats(): Promise<LiveThreat[]> {
    return apiFetch<LiveThreat[]>('/api/threats/live');
}

/**
 * Get top threat regions
 */
export async function getThreatRegions(): Promise<Array<{ region: string; count: number }>> {
    return apiFetch<Array<{ region: string; count: number }>>('/api/threats/regions');
}

// ============================================================================
// TRUSTED DOMAINS API
// ============================================================================

/**
 * Get sample trusted domains list
 */
export async function getTrustedDomains(): Promise<TrustedDomainsResponse> {
    return apiFetch<TrustedDomainsResponse>('/api/trusted-domains');
}

// ============================================================================
// TELEMETRY API
// ============================================================================

/**
 * Get telemetry summary (operators only)
 */
export async function getTelemetrySummary(): Promise<TelemetrySummary> {
    return apiFetch<TelemetrySummary>('/api/telemetry/summary');
}

// ============================================================================
// HEALTH CHECK API
// ============================================================================

interface HealthCheckResponse {
    status: string;
    pipeline_ready: boolean;
    model_type: string;
}

/**
 * Check API health status
 */
export async function checkHealth(): Promise<HealthCheckResponse> {
    return apiFetch<HealthCheckResponse>('/health');
}

/**
 * Check if API is reachable
 */
export async function isApiReachable(): Promise<boolean> {
    try {
        await checkHealth();
        return true;
    } catch {
        return false;
    }
}

// ============================================================================
// UTILITY HOOKS (for React)
// ============================================================================

/**
 * Type guard to check if an error is a GovernanceFreezeError
 */
export function isGovernanceFreezeError(error: unknown): error is GovernanceFreezeError {
    return error instanceof GovernanceFreezeError;
}

/**
 * Type guard to check if an error is an ApiError
 */
export function isApiError(error: unknown): error is ApiError {
    return error instanceof ApiError;
}

/**
 * Get a user-friendly error message
 */
export function getErrorMessage(error: unknown): string {
    if (isGovernanceFreezeError(error)) {
        return `System Frozen: ${error.reason}. ${error.actions}`;
    }
    if (isApiError(error)) {
        return error.message;
    }
    if (error instanceof Error) {
        return error.message;
    }
    return 'An unexpected error occurred';
}
