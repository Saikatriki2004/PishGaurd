'use client';

/**
 * Threat Map Component
 * 
 * Visualizes geographic threat data using Recharts.
 * Shows attack sources and targets on a coordinate system.
 */

import { useQuery } from '@tanstack/react-query';
import {
    ScatterChart,
    Scatter,
    XAxis,
    YAxis,
    ZAxis,
    Tooltip,
    ResponsiveContainer,
    Cell,
} from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
    Globe,
    RefreshCw,
    Loader2,
    AlertTriangle,
    TrendingUp,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { getThreatMapData, getThreatRegions } from '@/lib/api';
import { mockThreatMapData, mockThreatRegions, USE_MOCKS } from '@/lib/mockData';
import type { ThreatData, SeverityLevel } from '@/types';

interface ThreatMapProps {
    className?: string;
    compact?: boolean;
}

const SEVERITY_COLORS: Record<SeverityLevel, string> = {
    critical: '#ef4444',
    suspicious: '#f59e0b',
    safe: '#22c55e',
};

export function ThreatMap({ className, compact = false }: ThreatMapProps) {
    const { data: threats, isLoading, isError, refetch, isFetching } = useQuery({
        queryKey: ['threatMapData'],
        queryFn: USE_MOCKS ? () => Promise.resolve(mockThreatMapData) : getThreatMapData,
        refetchInterval: 30000, // 30 seconds
        staleTime: 25000,
    });

    const { data: regions } = useQuery({
        queryKey: ['threatRegions'],
        queryFn: USE_MOCKS ? () => Promise.resolve(mockThreatRegions) : getThreatRegions,
        refetchInterval: 60000,
        staleTime: 55000,
    });

    // Transform threat data for scatter chart (sources)
    const scatterData = threats?.map((threat) => ({
        lng: threat.source.lng,
        lat: threat.source.lat,
        severity: threat.severity,
        type: threat.type,
        vector: threat.attack_vector,
        id: threat.threat_id,
    })) || [];

    // Count by severity
    const severityCounts = threats?.reduce((acc, t) => {
        acc[t.severity] = (acc[t.severity] || 0) + 1;
        return acc;
    }, {} as Record<string, number>) || {};

    const CustomTooltip = ({ active, payload }: any) => {
        if (active && payload && payload.length) {
            const data = payload[0].payload;
            return (
                <div className="rounded-lg border bg-popover p-3 shadow-md">
                    <p className="font-medium text-sm">
                        {data.type.replace('_', ' ').toUpperCase()}
                    </p>
                    <p className="text-xs text-muted-foreground">
                        Vector: {data.vector}
                    </p>
                    <p className="text-xs text-muted-foreground">
                        Severity: {data.severity}
                    </p>
                </div>
            );
        }
        return null;
    };

    return (
        <Card className={cn('h-full', className)}>
            <CardHeader className={cn('pb-3', compact && 'p-4')}>
                <div className="flex items-center justify-between">
                    <CardTitle className={cn('flex items-center gap-2', compact ? 'text-base' : 'text-lg')}>
                        <Globe className="h-5 w-5 text-indigo-500" />
                        {compact ? 'Threats' : 'Global Threat Map'}
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
            <CardContent className={cn(compact && 'p-4 pt-0')}>
                {isLoading && (
                    <div className="flex items-center justify-center py-8">
                        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                    </div>
                )}

                {isError && (
                    <div className="flex flex-col items-center justify-center py-8 text-center">
                        <AlertTriangle className="h-8 w-8 text-yellow-500 mb-2" />
                        <p className="text-sm text-muted-foreground">Failed to load threat data</p>
                        <Button variant="outline" size="sm" className="mt-2" onClick={() => refetch()}>
                            Retry
                        </Button>
                    </div>
                )}

                {threats && (
                    <div className="space-y-4">
                        {/* Severity Summary */}
                        <div className="flex items-center gap-2 flex-wrap">
                            {severityCounts.critical && (
                                <Badge variant="outline" className="bg-red-500/10 text-red-600 border-red-500/30">
                                    {severityCounts.critical} Critical
                                </Badge>
                            )}
                            {severityCounts.suspicious && (
                                <Badge variant="outline" className="bg-yellow-500/10 text-yellow-600 border-yellow-500/30">
                                    {severityCounts.suspicious} Suspicious
                                </Badge>
                            )}
                            {severityCounts.safe && (
                                <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/30">
                                    {severityCounts.safe} Safe
                                </Badge>
                            )}
                        </div>

                        {/* Scatter Chart */}
                        <div className={cn('w-full', compact ? 'h-32' : 'h-48')}>
                            <ResponsiveContainer width="100%" height="100%">
                                <ScatterChart
                                    margin={{ top: 10, right: 10, bottom: 10, left: 10 }}
                                >
                                    <XAxis
                                        type="number"
                                        dataKey="lng"
                                        domain={[-180, 180]}
                                        hide
                                    />
                                    <YAxis
                                        type="number"
                                        dataKey="lat"
                                        domain={[-90, 90]}
                                        hide
                                    />
                                    <ZAxis range={[40, 100]} />
                                    <Tooltip content={<CustomTooltip />} />
                                    <Scatter data={scatterData} fill="#8884d8">
                                        {scatterData.map((entry, index) => (
                                            <Cell
                                                key={`cell-${index}`}
                                                fill={SEVERITY_COLORS[entry.severity as SeverityLevel]}
                                            />
                                        ))}
                                    </Scatter>
                                </ScatterChart>
                            </ResponsiveContainer>
                        </div>

                        {/* Top Regions */}
                        {!compact && regions && (
                            <div className="space-y-2">
                                <div className="flex items-center gap-2 text-sm font-medium">
                                    <TrendingUp className="h-4 w-4 text-muted-foreground" />
                                    Top Source Regions
                                </div>
                                <div className="space-y-1">
                                    {regions.slice(0, 3).map((region, i) => (
                                        <div
                                            key={region.region}
                                            className="flex items-center justify-between text-sm"
                                        >
                                            <span className="text-muted-foreground">
                                                {i + 1}. {region.region}
                                            </span>
                                            <span className="font-medium">
                                                {region.count.toLocaleString()}
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
