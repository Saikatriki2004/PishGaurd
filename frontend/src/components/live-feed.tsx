'use client';

/**
 * Live Feed Component
 * 
 * Real-time threat feed that displays recent scan activity.
 * Polls the backend every 5 seconds for updates.
 */

import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
    Activity,
    AlertTriangle,
    AlertCircle,
    CheckCircle2,
    RefreshCw,
    Clock,
    MapPin,
    Loader2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { getLiveThreats } from '@/lib/api';
import { mockLiveThreats, USE_MOCKS } from '@/lib/mockData';
import type { LiveThreat, SeverityLevel } from '@/types';

interface LiveFeedProps {
    className?: string;
}

const POLL_INTERVAL = 5000; // 5 seconds

export function LiveFeed({ className }: LiveFeedProps) {
    const { data: threats, isLoading, isError, refetch, isFetching } = useQuery({
        queryKey: ['liveThreats'],
        queryFn: USE_MOCKS ? () => Promise.resolve(mockLiveThreats) : getLiveThreats,
        refetchInterval: POLL_INTERVAL,
        staleTime: POLL_INTERVAL - 1000,
    });

    const getSeverityIcon = (severity: SeverityLevel) => {
        switch (severity) {
            case 'critical':
                return <AlertCircle className="h-4 w-4 text-red-500" />;
            case 'suspicious':
                return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
            case 'safe':
                return <CheckCircle2 className="h-4 w-4 text-green-500" />;
        }
    };

    const getSeverityBadge = (severity: SeverityLevel) => {
        const variants: Record<SeverityLevel, string> = {
            critical: 'bg-red-500/10 text-red-600 border-red-500/30 dark:text-red-400',
            suspicious: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/30 dark:text-yellow-400',
            safe: 'bg-green-500/10 text-green-600 border-green-500/30 dark:text-green-400',
        };
        return (
            <Badge variant="outline" className={cn('text-xs', variants[severity])}>
                {severity.toUpperCase()}
            </Badge>
        );
    };

    const formatTimestamp = (timestamp: string) => {
        const date = new Date(timestamp);
        const now = new Date();
        const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000);

        if (diffSec < 60) return `${diffSec}s ago`;
        if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
        return date.toLocaleTimeString();
    };

    return (
        <Card className={cn('h-full', className)}>
            <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                    <CardTitle className="flex items-center gap-2 text-lg">
                        <Activity className="h-5 w-5 text-indigo-500" />
                        Live Threat Feed
                        {isFetching && !isLoading && (
                            <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                        )}
                    </CardTitle>
                    <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8"
                        onClick={() => refetch()}
                        disabled={isFetching}
                    >
                        <RefreshCw className={cn('h-4 w-4', isFetching && 'animate-spin')} />
                    </Button>
                </div>
            </CardHeader>
            <CardContent>
                {isLoading && (
                    <div className="flex items-center justify-center py-8">
                        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                    </div>
                )}

                {isError && (
                    <div className="flex flex-col items-center justify-center py-8 text-center">
                        <AlertTriangle className="h-8 w-8 text-yellow-500 mb-2" />
                        <p className="text-sm text-muted-foreground">Failed to load threats</p>
                        <Button variant="outline" size="sm" className="mt-2" onClick={() => refetch()}>
                            Retry
                        </Button>
                    </div>
                )}

                {threats && threats.length === 0 && (
                    <div className="flex flex-col items-center justify-center py-8 text-center">
                        <CheckCircle2 className="h-8 w-8 text-green-500 mb-2" />
                        <p className="text-sm text-muted-foreground">All clear! No recent threats detected.</p>
                    </div>
                )}

                {threats && threats.length > 0 && (
                    <div className="space-y-3">
                        {threats.map((threat) => (
                            <ThreatItem key={threat.id} threat={threat} />
                        ))}
                    </div>
                )}
            </CardContent>
        </Card>
    );
}

interface ThreatItemProps {
    threat: LiveThreat;
}

function ThreatItem({ threat }: ThreatItemProps) {
    const getSeverityIcon = (severity: SeverityLevel) => {
        switch (severity) {
            case 'critical':
                return <AlertCircle className="h-4 w-4 text-red-500" />;
            case 'suspicious':
                return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
            case 'safe':
                return <CheckCircle2 className="h-4 w-4 text-green-500" />;
        }
    };

    const getSeverityBadge = (severity: SeverityLevel) => {
        const variants: Record<SeverityLevel, string> = {
            critical: 'bg-red-500/10 text-red-600 border-red-500/30 dark:text-red-400',
            suspicious: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/30 dark:text-yellow-400',
            safe: 'bg-green-500/10 text-green-600 border-green-500/30 dark:text-green-400',
        };
        return (
            <Badge variant="outline" className={cn('text-xs', variants[severity])}>
                {severity.toUpperCase()}
            </Badge>
        );
    };

    const formatTimestamp = (timestamp: string) => {
        const date = new Date(timestamp);
        const now = new Date();
        const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000);

        if (diffSec < 60) return `${diffSec}s ago`;
        if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
        return date.toLocaleTimeString();
    };

    return (
        <div
            className={cn(
                'rounded-lg border p-3 transition-colors hover:bg-accent/50',
                threat.severity === 'critical' && 'border-red-500/30 bg-red-500/5',
                threat.severity === 'suspicious' && 'border-yellow-500/30 bg-yellow-500/5'
            )}
        >
            <div className="flex items-start justify-between gap-2">
                <div className="flex items-start gap-2 min-w-0">
                    {getSeverityIcon(threat.severity)}
                    <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-medium text-sm">{threat.label}</span>
                            {getSeverityBadge(threat.severity)}
                        </div>
                        <p className="text-xs text-muted-foreground truncate mt-0.5">
                            {threat.entity}
                        </p>
                    </div>
                </div>
            </div>
            <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                    <MapPin className="h-3 w-3" />
                    {threat.location}
                </span>
                <span className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {formatTimestamp(threat.timestamp)}
                </span>
            </div>
        </div>
    );
}
