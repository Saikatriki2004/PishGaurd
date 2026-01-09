'use client';

/**
 * Scan Input Component
 * 
 * Main URL scanner with multiple states:
 * - idle: Ready for input
 * - loading: Analyzing URL with animated progress
 * - safe: Green success state
 * - phishing: Red danger state with explanation
 * - suspicious: Orange warning state
 * - error: Error with unfreeze button if governance frozen
 */

import { useState, useCallback } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
    Search,
    Shield,
    ShieldAlert,
    ShieldCheck,
    CheckCircle2,
    ShieldQuestion,
    Loader2,
    AlertTriangle,
    Unlock,
    ExternalLink,
    Info,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { scanUrl, unfreezeSystem, isGovernanceFreezeError, getErrorMessage } from '@/lib/api';
import {
    USE_MOCKS,
    mockSafeScanResponse,
    mockPhishingScanResponse,
    mockSuspiciousScanResponse
} from '@/lib/mockData';
import type { ScanResponse, VerdictType } from '@/types';

interface ScanInputProps {
    onScanComplete?: (result: ScanResponse) => void;
}

type ScanState = 'idle' | 'loading' | 'safe' | 'phishing' | 'suspicious' | 'error' | 'frozen';

const ML_PIPELINE_STAGES = [
    'Validating URL...',
    'Checking trusted domains...',
    'Extracting features...',
    'Running ML inference...',
    'Generating explanation...',
];

export function ScanInput({ onScanComplete }: ScanInputProps) {
    const [url, setUrl] = useState('');
    const [scanState, setScanState] = useState<ScanState>('idle');
    const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
    const [errorMessage, setErrorMessage] = useState<string>('');
    const [freezeReason, setFreezeReason] = useState<string>('');
    const [currentStage, setCurrentStage] = useState(0);
    const [progress, setProgress] = useState(0);

    // Mock scan function
    const mockScan = async (scanUrlVal: string): Promise<ScanResponse> => {
        await new Promise(resolve => setTimeout(resolve, 2000)); // Simulate delay

        if (scanUrlVal.includes('google')) return mockSafeScanResponse;
        if (scanUrlVal.includes('phishing')) return mockPhishingScanResponse;
        return mockSuspiciousScanResponse;
    };

    // Scan mutation
    const scanMutation = useMutation({
        mutationFn: USE_MOCKS ? mockScan : scanUrl,
        onMutate: () => {
            setScanState('loading');
            setScanResult(null);
            setErrorMessage('');
            setFreezeReason('');
            setCurrentStage(0);
            setProgress(0);

            // Simulate pipeline stages
            const stageInterval = setInterval(() => {
                setCurrentStage(prev => {
                    if (prev < ML_PIPELINE_STAGES.length - 1) {
                        return prev + 1;
                    }
                    clearInterval(stageInterval);
                    return prev;
                });
            }, 400);

            // Animate progress
            const progressInterval = setInterval(() => {
                setProgress(prev => {
                    if (prev >= 90) {
                        clearInterval(progressInterval);
                        return 90;
                    }
                    return prev + 10;
                });
            }, 150);

            return { stageInterval, progressInterval };
        },
        onSuccess: (data) => {
            setProgress(100);
            setScanResult(data);
            const verdictState = data.verdict.toLowerCase() as ScanState;
            setScanState(verdictState);
            onScanComplete?.(data);
        },
        onError: (error) => {
            setProgress(0);
            if (isGovernanceFreezeError(error)) {
                setScanState('frozen');
                setFreezeReason(error.reason);
            } else {
                setScanState('error');
                setErrorMessage(getErrorMessage(error));
            }
        },
    });

    // Unfreeze mutation
    const unfreezeMutation = useMutation({
        mutationFn: () => unfreezeSystem('DASHBOARD-' + Date.now()),
        onSuccess: () => {
            setScanState('idle');
            setFreezeReason('');
        },
        onError: (error) => {
            setErrorMessage(getErrorMessage(error));
        },
    });

    const handleSubmit = useCallback((e: React.FormEvent) => {
        e.preventDefault();
        if (url.trim() && !scanMutation.isPending) {
            scanMutation.mutate(url.trim());
        }
    }, [url, scanMutation]);

    const handleReset = useCallback(() => {
        setUrl('');
        setScanState('idle');
        setScanResult(null);
        setErrorMessage('');
        setFreezeReason('');
        setProgress(0);
    }, []);

    const getStateStyles = () => {
        switch (scanState) {
            case 'safe':
                return 'ring-2 ring-green-500/50 bg-green-500/5';
            case 'phishing':
                return 'ring-2 ring-red-500/50 bg-red-500/5 animate-pulse';
            case 'suspicious':
                return 'ring-2 ring-yellow-500/50 bg-yellow-500/5';
            case 'frozen':
            case 'error':
                return 'ring-2 ring-red-500/50 bg-red-500/5';
            default:
                return '';
        }
    };

    const getVerdictIcon = (verdict: VerdictType) => {
        switch (verdict) {
            case 'SAFE':
                return <ShieldCheck className="h-6 w-6 text-green-500" />;
            case 'PHISHING':
                return <ShieldAlert className="h-6 w-6 text-red-500" />;
            case 'SUSPICIOUS':
                return <ShieldQuestion className="h-6 w-6 text-yellow-500" />;
        }
    };

    const getVerdictBadge = (verdict: VerdictType) => {
        const variants: Record<VerdictType, { className: string; text: string }> = {
            SAFE: { className: 'bg-green-500/10 text-green-600 border-green-500/30', text: 'SAFE' },
            PHISHING: { className: 'bg-red-500/10 text-red-600 border-red-500/30', text: 'PHISHING' },
            SUSPICIOUS: { className: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/30', text: 'SUSPICIOUS' },
        };
        const v = variants[verdict];
        return <Badge variant="outline" className={cn('text-sm font-semibold', v.className)}>{v.text}</Badge>;
    };

    return (
        <Card className={cn('transition-all duration-300', getStateStyles())}>
            <CardHeader className="pb-4">
                <CardTitle className="flex items-center gap-2 text-lg">
                    <Shield className="h-5 w-5 text-indigo-500" />
                    URL Security Scanner
                </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
                {/* Input Form */}
                <form onSubmit={handleSubmit} className="flex gap-2">
                    <div className="relative flex-1">
                        <Input
                            type="url"
                            placeholder="Enter URL to scan (e.g., https://example.com)"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            disabled={scanMutation.isPending}
                            className="pr-10 h-12 text-base"
                        />
                        {scanResult && (
                            <div className="absolute right-3 top-1/2 -translate-y-1/2">
                                {getVerdictIcon(scanResult.verdict)}
                            </div>
                        )}
                    </div>
                    <Button
                        type="submit"
                        disabled={!url.trim() || scanMutation.isPending}
                        className="h-12 px-6"
                    >
                        {scanMutation.isPending ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                            <>
                                <Search className="h-4 w-4 mr-2" />
                                Scan
                            </>
                        )}
                    </Button>
                </form>

                {/* Loading State */}
                {scanState === 'loading' && (
                    <div className="space-y-3">
                        <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">
                                {ML_PIPELINE_STAGES[currentStage]}
                            </span>
                            <span className="text-muted-foreground">{progress}%</span>
                        </div>
                        <Progress value={progress} className="h-2" />
                    </div>
                )}

                {/* Frozen State */}
                {scanState === 'frozen' && (
                    <Alert variant="destructive">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertTitle className="flex items-center gap-2">
                            System Frozen
                        </AlertTitle>
                        <AlertDescription className="mt-2 space-y-3">
                            <p>{freezeReason}</p>
                            <Button
                                variant="destructive"
                                size="sm"
                                onClick={() => unfreezeMutation.mutate()}
                                disabled={unfreezeMutation.isPending}
                            >
                                {unfreezeMutation.isPending ? (
                                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                                ) : (
                                    <Unlock className="h-4 w-4 mr-2" />
                                )}
                                Emergency Unfreeze
                            </Button>
                        </AlertDescription>
                    </Alert>
                )}

                {/* Error State */}
                {scanState === 'error' && (
                    <Alert variant="destructive">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertTitle>Scan Failed</AlertTitle>
                        <AlertDescription>{errorMessage}</AlertDescription>
                    </Alert>
                )}

                {/* Result Display */}
                {scanResult && scanState !== 'loading' && (
                    <div className="space-y-4 pt-2">
                        {/* Verdict Header */}
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                                {getVerdictIcon(scanResult.verdict)}
                                <div>
                                    <div className="flex items-center gap-2">
                                        {getVerdictBadge(scanResult.verdict)}
                                        <span className="text-sm text-muted-foreground">
                                            Risk Score: {scanResult.risk_score}%
                                        </span>
                                    </div>
                                    <p className="text-sm text-muted-foreground mt-1">
                                        {scanResult.risk_level} • {scanResult.latency_ms}ms
                                    </p>
                                </div>
                            </div>
                            <Button variant="outline" size="sm" onClick={handleReset}>
                                New Scan
                            </Button>
                        </div>

                        {/* Trust Info */}
                        {scanResult.is_trusted_domain && scanResult.trust_info && (
                            <Alert variant="success">
                                <ShieldCheck className="h-4 w-4" />
                                <AlertTitle>Trusted Domain</AlertTitle>
                                <AlertDescription>
                                    {scanResult.trust_info.reason} ({scanResult.trust_info.registered_domain})
                                </AlertDescription>
                            </Alert>
                        )}

                        {/* Explanation */}
                        <div className="rounded-lg border p-4 space-y-3">
                            <div className="flex items-center gap-2">
                                <Info className="h-4 w-4 text-muted-foreground" />
                                <span className="font-medium">Analysis Summary</span>
                            </div>
                            <p className="text-sm text-muted-foreground">
                                {scanResult.explanation.summary}
                            </p>

                            {/* Risk Factors */}
                            {scanResult.explanation.risk.length > 0 && (
                                <div className="space-y-1">
                                    <span className="text-sm font-medium text-red-600 dark:text-red-400">
                                        Risk Factors:
                                    </span>
                                    <ul className="text-sm space-y-1 list-disc list-inside text-muted-foreground">
                                        {scanResult.explanation.risk.map((r, i) => (
                                            <li key={i}>{r}</li>
                                        ))}
                                    </ul>
                                </div>
                            )}

                            {/* Positive Signals */}
                            {scanResult.explanation.positive.length > 0 && (
                                <div className="space-y-1">
                                    <span className="text-sm font-medium text-green-600 dark:text-green-400">
                                        Positive Signals:
                                    </span>
                                    <ul className="text-sm space-y-1 list-disc list-inside text-muted-foreground">
                                        {scanResult.explanation.positive.map((p, i) => (
                                            <li key={i}>{p}</li>
                                        ))}
                                    </ul>
                                </div>
                            )}
                        </div>

                        {/* Scanned URL */}
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                            <ExternalLink className="h-4 w-4" />
                            <span className="truncate">{scanResult.url}</span>
                        </div>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
