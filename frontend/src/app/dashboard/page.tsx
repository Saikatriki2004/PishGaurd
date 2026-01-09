"use client"

import { useState } from "react"
import { Scan, Shield, AlertTriangle, Lock, Globe, MapPin, Activity, ExternalLink, FileText, Share2, Info } from "lucide-react"
import { RiskGauge } from "@/components/risk-gauge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
// @ts-ignore
import { useQuery } from "@tanstack/react-query"
import { scanUrl } from "@/lib/api"

export default function Dashboard() {
    const [url, setUrl] = useState("")
    const [isScanning, setIsScanning] = useState(false)
    const [result, setResult] = useState<any>(null)

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault()
        if (!url) return
        setIsScanning(true)
        try {
            const data = await scanUrl(url)
            setResult(data)
        } catch (err) {
            console.error(err)
        } finally {
            setIsScanning(false)
        }
    }

    // Mock result for design verification if no real result
    const displayResult = result || (isScanning ? null : {
        id: "#8829-AF2",
        url: "http://secure-login-update-bank.com.ref/auth",
        verdict: "MALICIOUS",
        risk_score: 85,
        details: {
            primary_threat: "Phishing",
            server_location: "Moscow, RU",
            blacklist_status: "Listed (4/35)",
            ssl_issuer: "Let's Encrypt (R3)",
            domain_age: "2 days ago",
            redirects: [
                "bit.ly/3x89a...",
                "secure-login-update..."
            ]
        }
    })

    // Only show results if we have data or are scanning
    // But for the gap-fill purpose, let's show the hero state if empty, results if populated.
    // Actually, let's default to showing the mock result for verification since the user wants to see the design.
    // Comment out proper logic for now.
    const showResults = true // !!result || !!displayResult

    return (
        <div className="min-h-screen bg-slate-50 dark:bg-slate-950 pb-20">
            {/* Hero Section */}
            <div className="container mx-auto max-w-5xl pt-16 pb-12 text-center">
                <h1 className="text-4xl md:text-5xl font-bold tracking-tight text-slate-900 dark:text-white mb-4">
                    Scan any URL for <span className="text-indigo-600">hidden threats</span>
                </h1>
                <p className="text-slate-600 dark:text-slate-400 mb-8 max-w-2xl mx-auto">
                    Enter a link below to instantly analyze SSL certificates, domain age, redirects, and potential phishing vectors.
                </p>

                <form onSubmit={handleScan} className="relative max-w-2xl mx-auto">
                    <div className="relative flex items-center">
                        <div className="absolute left-4 text-slate-400">
                            <Scan className="h-5 w-5" />
                        </div>
                        <Input
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            placeholder="http://example.com/login"
                            className="h-14 pl-12 pr-32 rounded-lg text-lg bg-white dark:bg-slate-900 shadow-sm border-slate-200"
                        />
                        <Button
                            type="submit"
                            disabled={isScanning}
                            className="absolute right-2 h-10 bg-indigo-600 hover:bg-indigo-700 text-white px-6 rounded-md transition-all"
                        >
                            {isScanning ? "Scanning..." : "Scan URL"}
                        </Button>
                    </div>
                    <div className="mt-4 flex justify-center gap-6 text-xs text-slate-500 font-medium">
                        <span className="flex items-center gap-1"><span className="text-green-500">●</span> Real-time Analysis</span>
                        <span className="flex items-center gap-1"><span className="text-blue-500">●</span> AI-Powered Engine</span>
                    </div>
                </form>
            </div>

            {/* Results Section */}
            {showResults && displayResult && (
                <div className="container mx-auto max-w-6xl px-4 animate-in fade-in slide-in-from-bottom-4 duration-500">
                    {/* Result Header */}
                    <div className="mb-6">
                        <div className="flex items-center gap-3 mb-2">
                            <Badge variant="destructive" className="bg-red-100 text-red-600 hover:bg-red-200 border-none uppercase tracking-wide text-[10px] font-bold px-2 py-1">
                                Malicious Detected
                            </Badge>
                            <span className="text-sm text-slate-500">Scan ID: {displayResult.id}</span>
                        </div>
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                            <h2 className="text-2xl font-bold text-slate-900 dark:text-white truncate max-w-3xl">
                                {displayResult.url}
                            </h2>
                            <div className="flex items-center gap-3 shrink-0">
                                <Button variant="outline" size="sm" className="gap-2">
                                    <Share2 className="h-4 w-4" /> Export Report
                                </Button>
                                <Button variant="destructive" size="sm" className="gap-2 bg-red-white text-red-600 border border-red-200 hover:bg-red-50">
                                    <Shield className="h-4 w-4" /> Block Domain
                                </Button>
                            </div>
                        </div>
                    </div>

                    {/* Top Cards Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                        {/* Risk Score */}
                        <Card className="md:col-span-1 border-none shadow-sm ring-1 ring-slate-200 dark:ring-slate-800">
                            <CardContent className="p-6">
                                <h3 className="text-sm font-semibold text-indigo-600 mb-4">Risk Score</h3>
                                <RiskGauge score={displayResult.risk_score} level={displayResult.verdict} />
                                <div className="mt-2 h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
                                    <div className="h-full bg-red-500 w-[85%] rounded-full" />
                                </div>
                                <div className="mt-2 flex items-center gap-2 text-xs font-bold text-red-600">
                                    <AlertTriangle className="h-3 w-3" /> Critical Threat
                                </div>
                            </CardContent>
                        </Card>

                        {/* Primary Threat */}
                        <Card className="md:col-span-1 border-none shadow-sm ring-1 ring-slate-200 dark:ring-slate-800">
                            <CardContent className="p-6 h-full flex flex-col justify-between">
                                <div>
                                    <h3 className="text-sm font-medium text-slate-500 mb-1">Primary Threat</h3>
                                    <div className="text-2xl font-bold text-slate-900 dark:text-white mb-2">
                                        {displayResult.details.primary_threat}
                                    </div>
                                    <p className="text-xs text-slate-500 leading-relaxed">
                                        Impersonating financial institution login page.
                                    </p>
                                </div>
                            </CardContent>
                        </Card>

                        {/* Server Location */}
                        <Card className="md:col-span-1 border-none shadow-sm ring-1 ring-slate-200 dark:ring-slate-800">
                            <CardContent className="p-6 h-full flex flex-col justify-between">
                                <div>
                                    <div className="flex items-start justify-between">
                                        <h3 className="text-sm font-medium text-slate-500 mb-1">Server Location</h3>
                                        <Globe className="h-4 w-4 text-slate-400" />
                                    </div>
                                    <div className="text-2xl font-bold text-slate-900 dark:text-white mb-2">
                                        {displayResult.details.server_location}
                                    </div>
                                    <div className="flex items-center gap-2 text-xs text-orange-500">
                                        <MapPin className="h-3 w-3" /> High-risk jurisdiction
                                    </div>
                                </div>
                            </CardContent>
                        </Card>

                        {/* Blacklist Status */}
                        <Card className="md:col-span-1 border-none shadow-sm ring-1 ring-slate-200 dark:ring-slate-800">
                            <CardContent className="p-6 h-full flex flex-col justify-between">
                                <div>
                                    <h3 className="text-sm font-medium text-slate-500 mb-1">Blacklist Status</h3>
                                    <div className="text-2xl font-bold text-slate-900 dark:text-white mb-4">
                                        {displayResult.details.blacklist_status}
                                    </div>
                                    <div className="flex items-center gap-1">
                                        <div className="h-6 w-6 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-[10px] font-bold">G</div>
                                        <div className="h-6 w-6 rounded-full bg-red-100 text-red-600 flex items-center justify-center text-[10px] font-bold">M</div>
                                        <div className="h-6 w-6 rounded-full bg-slate-100 text-slate-600 flex items-center justify-center text-[10px] font-bold">+2</div>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    </div>

                    <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4">Detailed Intelligence</h3>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
                        {/* SSL Certificate */}
                        <Card className="border-none shadow-sm ring-1 ring-slate-200 dark:ring-slate-800">
                            <CardContent className="p-6">
                                <div className="flex items-center gap-3 mb-6">
                                    <div className="h-10 w-10 rounded-lg bg-red-50 flex items-center justify-center">
                                        <Lock className="h-5 w-5 text-red-500" />
                                    </div>
                                    <div className="font-semibold text-slate-900 dark:text-white">SSL Certificate</div>
                                </div>
                                <div className="space-y-3 text-sm">
                                    <div className="flex justify-between">
                                        <span className="text-slate-500">Issuer</span>
                                        <span className="font-medium">{displayResult.details.ssl_issuer}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-slate-500">Status</span>
                                        <span className="font-medium text-red-600">Mismatched Domain</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-slate-500">Expires</span>
                                        <span className="font-medium">in 14 days</span>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>

                        {/* Domain Profile */}
                        <Card className="border-none shadow-sm ring-1 ring-slate-200 dark:ring-slate-800">
                            <CardContent className="p-6">
                                <div className="flex items-center gap-3 mb-6">
                                    <div className="h-10 w-10 rounded-lg bg-orange-50 flex items-center justify-center">
                                        <FileText className="h-5 w-5 text-orange-500" />
                                    </div>
                                    <div className="font-semibold text-slate-900 dark:text-white">Domain Profile</div>
                                </div>
                                <div className="space-y-3 text-sm">
                                    <div className="flex justify-between">
                                        <span className="text-slate-500">Registrar</span>
                                        <span className="font-medium">NameCheap, Inc.</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-slate-500">Created</span>
                                        <span className="font-medium text-orange-600">{displayResult.details.domain_age}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-slate-500">Privacy</span>
                                        <span className="font-medium">Redacted for Privacy</span>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>

                        {/* Redirect Chain */}
                        <Card className="border-none shadow-sm ring-1 ring-slate-200 dark:ring-slate-800">
                            <CardContent className="p-6">
                                <div className="flex items-center gap-3 mb-6">
                                    <div className="h-10 w-10 rounded-lg bg-indigo-50 flex items-center justify-center">
                                        <Activity className="h-5 w-5 text-indigo-500" />
                                    </div>
                                    <div className="font-semibold text-slate-900 dark:text-white">Redirect Chain</div>
                                </div>
                                <div className="space-y-4 relative pl-4 border-l-2 border-slate-100 dark:border-slate-800 ml-2">
                                    <div className="relative">
                                        <div className="absolute -left-[21px] top-1.5 h-3 w-3 rounded-full bg-green-500 ring-4 ring-white dark:ring-slate-950" />
                                        <p className="text-xs font-mono text-indigo-600 truncate w-full">bit.ly/3x89a...</p>
                                        <p className="text-[10px] text-slate-400">301 Moved Permanently</p>
                                    </div>
                                    <div className="relative">
                                        <div className="absolute -left-[21px] top-1.5 h-3 w-3 rounded-full bg-red-500 ring-4 ring-white dark:ring-slate-950" />
                                        <p className="text-xs font-mono text-slate-900 dark:text-white font-bold truncate">secure-login-update...</p>
                                        <p className="text-[10px] text-red-500">200 OK (Malicious)</p>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    </div>

                    {/* Bottom Banner */}
                    <div className="rounded-2xl bg-indigo-50 dark:bg-indigo-900/20 p-6 flex flex-col md:flex-row items-center justify-between gap-6 border border-indigo-100 dark:border-indigo-800">
                        <div className="flex items-start gap-4">
                            <div className="h-12 w-12 shrink-0 rounded-full bg-white dark:bg-slate-800 flex items-center justify-center shadow-sm text-indigo-600">
                                <Info className="h-6 w-6" />
                            </div>
                            <div>
                                <h4 className="text-lg font-bold text-slate-900 dark:text-white">How to interpret these results</h4>
                                <p className="text-slate-600 dark:text-slate-400 text-sm max-w-xl mt-1">
                                    A Risk Score above 75 indicates a high probability of malicious intent. Check the domain age—phishing sites are often less than 1 week old. Mismatched SSL certificates on banking domains are a primary indicator of credential harvesting.
                                </p>
                            </div>
                        </div>
                        <Button className="bg-white text-indigo-600 hover:bg-slate-50 border border-indigo-200 shadow-sm shrink-0">
                            View Documentation
                        </Button>
                    </div>

                </div>
            )}
        </div>
    )
}
