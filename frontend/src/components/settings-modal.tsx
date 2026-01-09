'use client';

/**
 * Settings Modal Component
 * 
 * Allows users to configure app settings including:
 * - Theme (Dark Mode toggle)
 * - API Endpoint status
 * - Safety Thresholds (placeholder for future)
 */

import { useState, useEffect } from 'react';
import { useTheme } from 'next-themes';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Badge } from '@/components/ui/badge';
import { Slider } from '@/components/ui/slider';
import {
    Settings,
    Moon,
    Sun,
    Globe,
    Shield,
    CheckCircle2,
    XCircle,
    Loader2,
} from 'lucide-react';
import { checkHealth, isApiReachable } from '@/lib/api';

interface SettingsModalProps {
    trigger?: React.ReactNode;
}

export function SettingsModal({ trigger }: SettingsModalProps) {
    const { theme, setTheme, resolvedTheme } = useTheme();
    const [mounted, setMounted] = useState(false);
    const [isOpen, setIsOpen] = useState(false);
    const [apiStatus, setApiStatus] = useState<'checking' | 'online' | 'offline'>('checking');
    const [modelType, setModelType] = useState<string>('Unknown');

    // Safety thresholds (placeholder - would be persisted in real implementation)
    const [phishingThreshold, setPhishingThreshold] = useState(85);
    const [suspiciousThreshold, setSuspiciousThreshold] = useState(55);

    // Avoid hydration mismatch
    useEffect(() => {
        setMounted(true);
    }, []);

    // Check API status when modal opens
    useEffect(() => {
        if (isOpen) {
            checkApiStatus();
        }
    }, [isOpen]);

    const checkApiStatus = async () => {
        setApiStatus('checking');
        try {
            const health = await checkHealth();
            setApiStatus('online');
            setModelType(health.model_type || 'Unknown');
        } catch {
            setApiStatus('offline');
            setModelType('Unavailable');
        }
    };

    const isDarkMode = resolvedTheme === 'dark';

    const handleDarkModeToggle = (checked: boolean) => {
        setTheme(checked ? 'dark' : 'light');
    };

    const apiEndpoint = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:5000';

    if (!mounted) {
        return null;
    }

    return (
        <Dialog open={isOpen} onOpenChange={setIsOpen}>
            <DialogTrigger asChild>
                {trigger || (
                    <Button variant="ghost" size="icon" className="h-9 w-9">
                        <Settings className="h-5 w-5" />
                        <span className="sr-only">Settings</span>
                    </Button>
                )}
            </DialogTrigger>
            <DialogContent className="sm:max-w-[500px]">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <Settings className="h-5 w-5" />
                        Settings
                    </DialogTitle>
                    <DialogDescription>
                        Configure your PhishGuard preferences
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-6 py-4">
                    {/* Theme Section */}
                    <div className="space-y-4">
                        <h4 className="text-sm font-medium leading-none flex items-center gap-2">
                            {isDarkMode ? (
                                <Moon className="h-4 w-4" />
                            ) : (
                                <Sun className="h-4 w-4" />
                            )}
                            Appearance
                        </h4>
                        <div className="flex items-center justify-between rounded-lg border p-4">
                            <div className="space-y-0.5">
                                <Label htmlFor="dark-mode" className="text-base">
                                    Dark Mode
                                </Label>
                                <p className="text-sm text-muted-foreground">
                                    Switch between light and dark themes
                                </p>
                            </div>
                            <Switch
                                id="dark-mode"
                                checked={isDarkMode}
                                onCheckedChange={handleDarkModeToggle}
                            />
                        </div>
                    </div>

                    <Separator />

                    {/* API Endpoint Section */}
                    <div className="space-y-4">
                        <h4 className="text-sm font-medium leading-none flex items-center gap-2">
                            <Globe className="h-4 w-4" />
                            API Connection
                        </h4>
                        <div className="rounded-lg border p-4 space-y-3">
                            <div className="flex items-center justify-between">
                                <span className="text-sm font-medium">Endpoint</span>
                                <code className="text-xs bg-muted px-2 py-1 rounded">
                                    {apiEndpoint}
                                </code>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-sm font-medium">Status</span>
                                <div className="flex items-center gap-2">
                                    {apiStatus === 'checking' && (
                                        <>
                                            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                                            <Badge variant="outline">Checking...</Badge>
                                        </>
                                    )}
                                    {apiStatus === 'online' && (
                                        <>
                                            <CheckCircle2 className="h-4 w-4 text-green-500" />
                                            <Badge variant="outline" className="border-green-500 text-green-500">
                                                Online
                                            </Badge>
                                        </>
                                    )}
                                    {apiStatus === 'offline' && (
                                        <>
                                            <XCircle className="h-4 w-4 text-destructive" />
                                            <Badge variant="destructive">Offline</Badge>
                                        </>
                                    )}
                                </div>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-sm font-medium">Model</span>
                                <span className="text-sm text-muted-foreground">{modelType}</span>
                            </div>
                            <Button
                                variant="outline"
                                size="sm"
                                className="w-full mt-2"
                                onClick={checkApiStatus}
                                disabled={apiStatus === 'checking'}
                            >
                                {apiStatus === 'checking' ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Checking...
                                    </>
                                ) : (
                                    'Refresh Status'
                                )}
                            </Button>
                        </div>
                    </div>

                    <Separator />

                    {/* Safety Thresholds Section (Placeholder) */}
                    <div className="space-y-4">
                        <h4 className="text-sm font-medium leading-none flex items-center gap-2">
                            <Shield className="h-4 w-4" />
                            Safety Thresholds
                            <Badge variant="secondary" className="text-xs">
                                Coming Soon
                            </Badge>
                        </h4>
                        <div className="rounded-lg border p-4 space-y-4 opacity-60">
                            <div className="space-y-2">
                                <div className="flex items-center justify-between">
                                    <Label className="text-sm">Phishing Threshold</Label>
                                    <span className="text-sm text-muted-foreground">
                                        {phishingThreshold}%
                                    </span>
                                </div>
                                <Slider
                                    value={[phishingThreshold]}
                                    onValueChange={(v) => setPhishingThreshold(v[0])}
                                    max={100}
                                    min={50}
                                    step={1}
                                    disabled
                                    className="cursor-not-allowed"
                                />
                                <p className="text-xs text-muted-foreground">
                                    URLs with risk score above this are marked PHISHING
                                </p>
                            </div>

                            <div className="space-y-2">
                                <div className="flex items-center justify-between">
                                    <Label className="text-sm">Suspicious Threshold</Label>
                                    <span className="text-sm text-muted-foreground">
                                        {suspiciousThreshold}%
                                    </span>
                                </div>
                                <Slider
                                    value={[suspiciousThreshold]}
                                    onValueChange={(v) => setSuspiciousThreshold(v[0])}
                                    max={phishingThreshold - 1}
                                    min={20}
                                    step={1}
                                    disabled
                                    className="cursor-not-allowed"
                                />
                                <p className="text-xs text-muted-foreground">
                                    URLs with risk score above this are marked SUSPICIOUS
                                </p>
                            </div>

                            <p className="text-xs text-amber-600 dark:text-amber-400 mt-2">
                                ⚠️ Threshold configuration requires admin privileges and will be
                                available in a future release.
                            </p>
                        </div>
                    </div>
                </div>
            </DialogContent>
        </Dialog>
    );
}
