"use client"

import { useState } from "react"
import { Eye, EyeOff, Copy, RotateCw, Plus, Trash, Check, Shield, Circle, User, AlertTriangle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar" // Using custom fallback if not installed

export default function SettingsPage() {
    const [showKey, setShowKey] = useState(false)
    const [apiKey, setApiKey] = useState("pk_live_51M3Txxxxxxxxxxxxxxxx")

    return (
        <div className="min-h-screen bg-slate-50 dark:bg-slate-950 p-6">
            <div className="container mx-auto max-w-4xl space-y-8">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-white">Settings</h1>
                    <p className="text-slate-500 mt-1">Manage your security preferences, API access, and allowed domains.</p>
                </div>

                {/* User Profile */}
                <Card className="border-none shadow-sm ring-1 ring-slate-200 dark:ring-slate-800">
                    <CardHeader>
                        <CardTitle>User Profile</CardTitle>
                        <CardDescription>Update your personal information and account security.</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-6">
                        <div className="flex flex-col md:flex-row gap-6 items-start">
                            <div className="flex flex-col items-center gap-3">
                                <div className="h-24 w-24 rounded-full bg-indigo-100 flex items-center justify-center border-4 border-white shadow-sm overflow-hidden">
                                    {/* Avatar placeholder matching image */}
                                    <img src="/avatar-placeholder.png" alt="Profile" className="h-full w-full object-cover"
                                        onError={(e) => { e.currentTarget.style.display = 'none'; e.currentTarget.parentElement!.innerHTML = '<svg class="h-12 w-12 text-indigo-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>' }}
                                    />
                                </div>
                                <Button variant="outline" size="sm" className="w-full">Change Photo</Button>
                                <button className="text-xs text-red-500 hover:underline">Remove</button>
                            </div>
                            <div className="flex-1 space-y-4 w-full">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="fullName">Full Name</Label>
                                        <Input id="fullName" defaultValue="John Doe" className="bg-slate-50 dark:bg-slate-900" />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="email">Email Address</Label>
                                        <Input id="email" defaultValue="john.doe@phishguard.io" className="bg-slate-50 dark:bg-slate-900" />
                                    </div>
                                </div>
                                <div className="rounded-lg bg-slate-50 dark:bg-slate-900 p-4 flex items-center justify-between border border-slate-100 dark:border-slate-800">
                                    <div className="flex items-center gap-3">
                                        <div className="h-10 w-10 rounded-full bg-white dark:bg-slate-800 flex items-center justify-center border border-slate-200 dark:border-slate-700">
                                            <Shield className="h-5 w-5 text-slate-500" />
                                        </div>
                                        <div>
                                            <div className="font-medium text-slate-900 dark:text-white">Password</div>
                                            <div className="text-xs text-slate-500">Last changed 3 months ago</div>
                                        </div>
                                    </div>
                                    <Button variant="outline" size="sm" className="bg-white dark:bg-slate-800">Update Password</Button>
                                </div>
                            </div>
                        </div>
                    </CardContent>
                </Card>

                {/* API Access */}
                <Card className="border-none shadow-sm ring-1 ring-slate-200 dark:ring-slate-800">
                    <CardHeader>
                        <CardTitle>API Access</CardTitle>
                        <CardDescription>Manage your secret keys for external application integration.</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="space-y-2">
                            <Label>Secret Key</Label>
                            <div className="flex items-center gap-2">
                                <div className="relative flex-1">
                                    <Input
                                        type={showKey ? "text" : "password"}
                                        value={apiKey}
                                        readOnly
                                        className="pr-10 bg-slate-50 dark:bg-slate-900 font-mono text-sm"
                                    />
                                    <button
                                        onClick={() => setShowKey(!showKey)}
                                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                                    >
                                        {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                                    </button>
                                </div>
                                <Button className="bg-indigo-600 hover:bg-indigo-700 gap-2 min-w-[90px]">
                                    <Copy className="h-4 w-4" /> Copy
                                </Button>
                                <Button variant="outline" className="gap-2 min-w-[110px]">
                                    <RotateCw className="h-4 w-4" /> Regenerate
                                </Button>
                            </div>
                            <p className="text-xs text-slate-500 flex items-center gap-1 mt-2">
                                <InfoIcon className="h-3 w-3" /> Do not share this key with anyone. It grants full access to your account.
                            </p>
                        </div>
                    </CardContent>
                </Card>

                {/* Notification Preferences */}
                <Card className="border-none shadow-sm ring-1 ring-slate-200 dark:ring-slate-800">
                    <CardHeader>
                        <CardTitle>Notification Preferences</CardTitle>
                        <CardDescription>Choose how and when you want to be alerted about threats.</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-6">
                        {/* Critical Threats */}
                        <div className="flex items-center justify-between">
                            <div className="flex items-start gap-3">
                                <div className="h-10 w-10 rounded-lg bg-red-100 text-red-600 flex items-center justify-center shrink-0">
                                    <Shield className="h-5 w-5" />
                                </div>
                                <div>
                                    <div className="font-medium text-slate-900 dark:text-white">Critical Threats</div>
                                    <div className="text-sm text-slate-500">Immediate alerts for high-risk phishing URLs.</div>
                                </div>
                            </div>
                            <Switch defaultChecked />
                        </div>

                        {/* Suspicious Activity */}
                        <div className="flex items-center justify-between">
                            <div className="flex items-start gap-3">
                                <div className="h-10 w-10 rounded-lg bg-orange-100 text-orange-600 flex items-center justify-center shrink-0">
                                    <AlertTriangle className="h-5 w-5" />
                                </div>
                                <div>
                                    <div className="font-medium text-slate-900 dark:text-white">Suspicious Activity</div>
                                    <div className="text-sm text-slate-500">Alerts for unusual login attempts or API usage spikes.</div>
                                </div>
                            </div>
                            <Switch defaultChecked />
                        </div>

                        {/* Weekly Digest */}
                        <div className="flex items-center justify-between">
                            <div className="flex items-start gap-3">
                                <div className="h-10 w-10 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center shrink-0">
                                    <FileIcon className="h-5 w-5" />
                                </div>
                                <div>
                                    <div className="font-medium text-slate-900 dark:text-white">Weekly Digest</div>
                                    <div className="text-sm text-slate-500">A summary email of all prevented attacks sent every Monday.</div>
                                </div>
                            </div>
                            <Switch />
                        </div>
                    </CardContent>
                </Card>

                {/* Allowed Domains */}
                <Card className="border-none shadow-sm ring-1 ring-slate-200 dark:ring-slate-800 pb-20">
                    <CardHeader>
                        <CardTitle>Allowed Domains</CardTitle>
                        <CardDescription>Whitelisted domains that bypass phishing scans.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="flex gap-2 mb-6">
                            <div className="relative flex-1">
                                <div className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400">
                                    <LinkIcon className="h-4 w-4" />
                                </div>
                                <Input placeholder="e.g. internal-portal.com" className="pl-9 bg-slate-50 dark:bg-slate-900" />
                            </div>
                            <Button className="bg-indigo-600 hover:bg-indigo-700 gap-2">
                                <Plus className="h-4 w-4" /> Add Domain
                            </Button>
                        </div>

                        <div className="rounded-lg border border-slate-200 dark:border-slate-800 overflow-hidden">
                            {/* Header */}
                            <div className="grid grid-cols-12 bg-slate-50 dark:bg-slate-900 p-3 text-xs font-semibold text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                                <div className="col-span-8">Domain</div>
                                <div className="col-span-4 text-right">Date Added</div>
                            </div>
                            {/* Rows */}
                            <div className="bg-white dark:bg-slate-900 divide-y divide-slate-100 dark:divide-slate-800">
                                {[
                                    { domain: "google.com", date: "Oct 24, 2023" },
                                    { domain: "company-intranet.net", date: "Sep 12, 2023" },
                                    { domain: "secure-payments.io", date: "Aug 05, 2023" },
                                ].map((item, i) => (
                                    <div key={i} className="grid grid-cols-12 p-4 items-center hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                                        <div className="col-span-8 flex items-center gap-3">
                                            <div className="h-6 w-6 rounded-full bg-green-100 text-green-600 flex items-center justify-center">
                                                <Check className="h-3 w-3" />
                                            </div>
                                            <span className="font-medium text-slate-700 dark:text-slate-300">{item.domain}</span>
                                        </div>
                                        <div className="col-span-4 flex items-center justify-end gap-4">
                                            <span className="text-sm text-slate-500">{item.date}</span>
                                            <button className="text-slate-400 hover:text-red-500 transition-colors">
                                                <Trash className="h-4 w-4" />
                                            </button>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </CardContent>
                </Card>

            </div>

            {/* Footer Actions */}
            <div className="fixed bottom-0 left-0 right-0 bg-white dark:bg-slate-950 border-t border-slate-200 dark:border-slate-800 p-4 z-40">
                <div className="container mx-auto max-w-4xl flex justify-end gap-3">
                    <Button variant="ghost">Discard Changes</Button>
                    <Button className="bg-indigo-600 hover:bg-indigo-700">Save Settings</Button>
                </div>
            </div>

            <div className="text-center py-8 text-xs text-slate-400">
                © 2024 PhishGuard Security Systems. All rights reserved.
            </div>
        </div>
    )
}

function InfoIcon(props: any) { return <span {...props}><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-info"><circle cx="12" cy="12" r="10" /><path d="M12 16v-4" /><path d="M12 8h.01" /></svg></span> }
function FileIcon(props: any) { return <span {...props}><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-file-text"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" /><path d="M14 2v4a2 2 0 0 0 2 2h4" /><path d="M10 9H8" /><path d="M16 13H8" /><path d="M16 17H8" /></svg></span> }
function LinkIcon(props: any) { return <span {...props}><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-link"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" /><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" /></svg></span> }
