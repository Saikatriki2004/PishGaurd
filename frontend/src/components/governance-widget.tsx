'use client';

/**
 * Governance Widget Component
 * 
 * Displays the system's governance health status:
 * - Safety Budget progress
 * - Freeze state indicator
 * - Emergency Override button when frozen
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
    Shield,
    ShieldAlert,
    ShieldCheck,
    Lock,
    Unlock,
    AlertTriangle,
    Loader2,
    RefreshCw,
    Clock,
    Activity,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { getGovernanceStatus, unfreezeSystem, getErrorMessage } from '@/lib/api';
import { mockGovernanceNormal, mockGovernanceFrozen, USE_MOCKS } from '@/lib/mockData';
import type { GovernanceStatus } from '@/types';

interface GovernanceWidgetProps {
    className?: string;
    compact?: boolean;
}

export function GovernanceWidget({ className, compact = false }: GovernanceWidgetProps) {
    const [showUnfreezeDialog, setShowUnfreezeDialog] = useState(false);
    const [ticketId, setTicketId] = useState('');
    const queryClient = useQueryClient();

    // For demo purposes, toggle between normal and frozen states
    const [mockFrozen, setMockFrozen] = useState(false);

    const { data: status, isLoading, isError, refetch, isFetching } = useQuery({
        queryKey: ['governanceStatus'],
        queryFn: USE_MOCKS
            ? () => Promise.resolve(mockFrozen ? mockGovernanceFrozen : mockGovernanceNormal)
            : getGovernanceStatus,
        refetchInterval: 10000, // 10 seconds
        staleTime: 8000,
    });

    const unfreezeMutation = useMutation({
        mutationFn: (ticket: string) => unfreezeSystem(ticket),
        onSuccess: () => {
            setShowUnfreezeDialog(false);
            setTicketId('');
            if (USE_MOCKS) {
                setMockFrozen(false);
            }
            queryClient.invalidateQueries({ queryKey: ['governanceStatus'] });
        },
    });

    const budgetPercentage = status
        ? (status.budget.override_count_hourly / status.budget.max_overrides_per_hour) * 100
        : 0;

    const getBudgetColor = () => {
        if (budgetPercentage >= 100) return 'text-red-500';
        if (budgetPercentage >= 60) return 'text-yellow-500';
        return 'text-green-500';
    };

    const formatTime = (isoString: string | null) => {
        if (!isoString) return 'N/A';
        const date = new Date(isoString);
        return date.toLocaleTimeString();
    };

    if (isLoading) {
        return (
            <Card className={cn('h-full', className)}>
                <CardContent className="flex items-center justify-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </CardContent>
            </Card>
        );
    }

    if (isError || !status) {
        return (
            <Card className={cn('h-full', className)}>
                <CardContent className="flex flex-col items-center justify-center py-8">
                    <AlertTriangle className="h-8 w-8 text-yellow-500 mb-2" />
                    <p className="text-sm text-muted-foreground">Failed to load status</p>
                    <Button variant="outline" size="sm" className="mt-2" onClick={() => refetch()}>
                        Retry
                    </Button>
                </CardContent>
            </Card>
        );
    }

    return (
        <>
            <Card
                className={cn(
                    'h-full transition-all duration-300',
                    status.is_frozen && 'ring-2 ring-red-500/50 bg-red-500/5',
                    className
                )}
            >
                <CardHeader className={cn('pb-3', compact && 'p-4')}>
                    <div className="flex items-center justify-between">
                        <CardTitle className={cn('flex items-center gap-2', compact ? 'text-base' : 'text-lg')}>
                            {status.is_frozen ? (
                                <ShieldAlert className="h-5 w-5 text-red-500" />
                            ) : (
                                <ShieldCheck className="h-5 w-5 text-green-500" />
                            )}
                            {compact ? 'Governance' : 'Governance Health'}
                        </CardTitle>
                        <div className="flex items-center gap-1">
                            {isFetching && !isLoading && (
                                <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                            )}
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
                    </div>
                </CardHeader>
                <CardContent className={cn('space-y-4', compact && 'p-4 pt-0')}>
                    {/* Status Badge */}
                    <div className="flex items-center gap-2">
                        {status.is_frozen ? (
                            <Badge variant="destructive" className="gap-1">
                                <Lock className="h-3 w-3" />
                                FROZEN
                            </Badge>
                        ) : (
                            <Badge variant="outline" className="gap-1 bg-green-500/10 text-green-600 border-green-500/30">
                                <Activity className="h-3 w-3" />
                                OPERATIONAL
                            </Badge>
                        )}
                        {status.health.governance_available && (
                            <Badge variant="secondary" className="text-xs">
                                {status.health.model_type}
                            </Badge>
                        )}
                    </div>

                    {/* Freeze Alert */}
                    {status.is_frozen && (
                        <Alert variant="destructive">
                            <AlertTriangle className="h-4 w-4" />
                            <AlertTitle>System Frozen</AlertTitle>
                            <AlertDescription className="space-y-2">
                                <p className="text-sm">{status.freeze_reason}</p>
                                {status.frozen_at && (
                                    <p className="text-xs flex items-center gap-1">
                                        <Clock className="h-3 w-3" />
                                        Frozen at: {formatTime(status.frozen_at)}
                                    </p>
                                )}
                                <Button
                                    variant="destructive"
                                    size="sm"
                                    className="mt-2"
                                    onClick={() => setShowUnfreezeDialog(true)}
                                >
                                    <Unlock className="h-4 w-4 mr-2" />
                                    Emergency Override
                                </Button>
                            </AlertDescription>
                        </Alert>
                    )}

                    {/* Safety Budget */}
                    <div className="space-y-2">
                        <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">Override Budget</span>
                            <span className={cn('font-medium', getBudgetColor())}>
                                {status.budget.override_count_hourly} / {status.budget.max_overrides_per_hour}
                            </span>
                        </div>
                        <Progress
                            value={budgetPercentage}
                            className={cn(
                                'h-2',
                                budgetPercentage >= 100 && '[&>div]:bg-red-500',
                                budgetPercentage >= 60 && budgetPercentage < 100 && '[&>div]:bg-yellow-500'
                            )}
                        />
                        <p className="text-xs text-muted-foreground">
                            {status.budget.budget_exhausted
                                ? 'Budget exhausted - new overrides blocked'
                                : `${status.budget.max_overrides_per_hour - status.budget.override_count_hourly} overrides remaining this hour`
                            }
                        </p>
                    </div>

                    {/* Pipeline Status */}
                    {!compact && (
                        <div className="flex items-center justify-between text-sm border-t pt-3">
                            <span className="text-muted-foreground">ML Pipeline</span>
                            <Badge
                                variant="outline"
                                className={cn(
                                    status.health.pipeline_ready
                                        ? 'bg-green-500/10 text-green-600 border-green-500/30'
                                        : 'bg-red-500/10 text-red-600 border-red-500/30'
                                )}
                            >
                                {status.health.pipeline_ready ? 'Ready' : 'Unavailable'}
                            </Badge>
                        </div>
                    )}

                    {/* Demo Toggle (only in mock mode) */}
                    {USE_MOCKS && (
                        <Button
                            variant="outline"
                            size="sm"
                            className="w-full mt-2"
                            onClick={() => setMockFrozen(!mockFrozen)}
                        >
                            Toggle Freeze State (Demo)
                        </Button>
                    )}
                </CardContent>
            </Card>

            {/* Unfreeze Dialog */}
            <Dialog open={showUnfreezeDialog} onOpenChange={setShowUnfreezeDialog}>
                <DialogContent className="sm:max-w-[425px]">
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2 text-red-600">
                            <ShieldAlert className="h-5 w-5" />
                            Emergency System Override
                        </DialogTitle>
                        <DialogDescription>
                            This will lift the governance freeze and allow scans to resume.
                            This action is logged for audit purposes.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4 py-4">
                        <Alert variant="warning">
                            <AlertTriangle className="h-4 w-4" />
                            <AlertDescription>
                                Only use emergency override if you have verified the root cause
                                and confirmed it is safe to resume operations.
                            </AlertDescription>
                        </Alert>
                        <div className="space-y-2">
                            <Label htmlFor="ticket">Incident Ticket (Optional)</Label>
                            <Input
                                id="ticket"
                                placeholder="e.g., INC-2026-001"
                                value={ticketId}
                                onChange={(e) => setTicketId(e.target.value)}
                            />
                            <p className="text-xs text-muted-foreground">
                                Link this action to an incident ticket for audit trail.
                            </p>
                        </div>
                    </div>
                    <DialogFooter>
                        <Button
                            variant="outline"
                            onClick={() => setShowUnfreezeDialog(false)}
                        >
                            Cancel
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={() => unfreezeMutation.mutate(ticketId || 'DASHBOARD')}
                            disabled={unfreezeMutation.isPending}
                        >
                            {unfreezeMutation.isPending ? (
                                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                            ) : (
                                <Unlock className="h-4 w-4 mr-2" />
                            )}
                            Confirm Override
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </>
    );
}
