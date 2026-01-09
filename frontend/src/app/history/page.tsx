"use client"

import { useState } from "react"
import { Search, Filter, Calendar, Download, ChevronDown, Flag, Globe, AlertTriangle, CheckCircle, XCircle, Eye } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

// Mock Data matching the image
const historyData = [
    { id: 1, url: "http://suspicious-login-update-account-v...", ip: "192.168.1.45", status: "Malicious", risk: 95, date: "Oct 24, 2023", time: "10:42 AM" },
    { id: 2, url: "https://google.com", ip: "142.250.190.46", status: "Safe", risk: 5, date: "Oct 24, 2023", time: "10:30 AM" },
    { id: 3, url: "http://verify-bank-account.net", ip: "45.33.22.11", status: "Suspicious", risk: 65, date: "Oct 23, 2023", time: "04:15 PM" },
    { id: 4, url: "https://github.com", ip: "140.82.112.4", status: "Safe", risk: 0, date: "Oct 23, 2023", time: "02:00 PM" },
    { id: 5, url: "http://free-gift-cards-claim-now.xy", ip: "103.14.25.1", status: "Malicious", risk: 88, date: "Oct 22, 2023", time: "09:20 AM" },
]

export default function HistoryPage() {
    const [activeFilter, setActiveFilter] = useState("All Statuses")

    return (
        <div className="min-h-screen bg-slate-50 dark:bg-slate-950 p-6">
            <div className="container mx-auto max-w-7xl">
                {/* Header */}
                <div className="flex flex-col md:flex-row items-start md:items-end justify-between gap-4 mb-8">
                    <div>
                        <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-white">Scan History</h1>
                        <p className="text-slate-500 mt-1">View and manage your recent URL analysis reports.</p>
                    </div>
                    <div className="flex items-center gap-3">
                        <Button variant="outline" className="bg-white dark:bg-slate-900 gap-2">
                            <Calendar className="h-4 w-4 text-slate-500" />
                            Last 30 Days
                        </Button>
                        <Button variant="outline" className="bg-white dark:bg-slate-900 gap-2">
                            <Download className="h-4 w-4 text-slate-500" />
                            Export CSV
                        </Button>
                    </div>
                </div>

                {/* Filters and Search */}
                <div className="flex flex-col md:flex-row items-center justify-between gap-4 mb-6">
                    <div className="flex items-center gap-2 overflow-x-auto pb-2 md:pb-0 w-full md:w-auto">
                        <Button
                            variant={activeFilter === "All Statuses" ? "default" : "outline"}
                            className={cn(activeFilter === "All Statuses" ? "bg-indigo-600 hover:bg-indigo-700" : "bg-white border-slate-200 text-slate-600")}
                            onClick={() => setActiveFilter("All Statuses")}
                        >
                            All Statuses <ChevronDown className="ml-2 h-3 w-3 opacity-50" />
                        </Button>
                        <Button
                            variant={activeFilter === "Malicious" ? "default" : "outline"}
                            className={cn(activeFilter === "Malicious" ? "bg-red-600 hover:bg-red-700 text-white" : "bg-white border-slate-200 text-slate-600")}
                            onClick={() => setActiveFilter("Malicious")}
                        >
                            Malicious
                        </Button>
                        <Button
                            variant={activeFilter === "Suspicious" ? "default" : "outline"}
                            className={cn(activeFilter === "Suspicious" ? "bg-orange-500 hover:bg-orange-600 text-white" : "bg-white border-slate-200 text-slate-600")}
                            onClick={() => setActiveFilter("Suspicious")}
                        >
                            Suspicious
                        </Button>
                        <Button
                            variant={activeFilter === "Safe" ? "default" : "outline"}
                            className={cn(activeFilter === "Safe" ? "bg-green-600 hover:bg-green-700 text-white" : "bg-white border-slate-200 text-slate-600")}
                            onClick={() => setActiveFilter("Safe")}
                        >
                            Safe
                        </Button>
                        <div className="h-6 w-px bg-slate-300 mx-2" />
                        <Button variant="ghost" className="text-indigo-600 font-medium hover:bg-indigo-50">
                            <Filter className="mr-2 h-4 w-4" /> More Filters
                        </Button>
                    </div>
                </div>

                {/* Table */}
                <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden">
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm text-left">
                            <thead className="bg-slate-50 dark:bg-slate-800/50 text-slate-500 font-medium uppercase text-xs tracking-wider border-b border-slate-100 dark:border-slate-800">
                                <tr>
                                    <th className="px-6 py-4">URL Analyzed</th>
                                    <th className="px-6 py-4">Status</th>
                                    <th className="px-6 py-4">Risk Score</th>
                                    <th className="px-6 py-4">Scan Time</th>
                                    <th className="px-6 py-4 w-10"></th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                                {historyData.map((item) => (
                                    <tr key={item.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                                        <td className="px-6 py-4">
                                            <div className="flex items-start gap-3">
                                                <div className={cn(
                                                    "mt-1 h-8 w-8 rounded-full flex items-center justify-center shrink-0",
                                                    item.status === 'Malicious' && "bg-red-100 text-red-600",
                                                    item.status === 'Safe' && "bg-green-100 text-green-600",
                                                    item.status === 'Suspicious' && "bg-orange-100 text-orange-600",
                                                )}>
                                                    {item.status === 'Malicious' && <XCircle className="h-4 w-4" />}
                                                    {item.status === 'Safe' && <CheckCircle className="h-4 w-4" />}
                                                    {item.status === 'Suspicious' && <AlertTriangle className="h-4 w-4" />}
                                                </div>
                                                <div>
                                                    <div className="font-medium text-slate-900 dark:text-white max-w-md truncate">{item.url}</div>
                                                    <div className="text-slate-500 text-xs mt-0.5">IP: {item.ip}</div>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <Badge variant="outline" className={cn(
                                                "border-none px-2.5 py-0.5 font-medium rounded-full",
                                                item.status === 'Malicious' && "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
                                                item.status === 'Safe' && "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
                                                item.status === 'Suspicious' && "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400",
                                            )}>
                                                {item.status}
                                            </Badge>
                                        </td>
                                        <td className="px-6 py-4 w-48">
                                            <div className="flex items-center gap-3">
                                                <span className="font-bold w-8 text-right">{item.risk}/100</span>
                                                <div className="h-1.5 flex-1 bg-slate-100 rounded-full overflow-hidden">
                                                    <div
                                                        className={cn("h-full rounded-full",
                                                            item.risk > 75 ? "bg-red-500" : item.risk > 30 ? "bg-orange-400" : "bg-green-500"
                                                        )}
                                                        style={{ width: `${item.risk}%` }}
                                                    />
                                                </div>
                                                <span className={cn(
                                                    "text-xs font-medium",
                                                    item.risk > 75 ? "text-red-600" : item.risk > 30 ? "text-orange-600" : "text-green-600"
                                                )}>
                                                    {item.risk > 75 ? "Critical" : item.risk > 30 ? "Medium" : "Low"}
                                                </span>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="text-sm text-slate-900 dark:text-white">{item.date}</div>
                                            <div className="text-xs text-slate-500">{item.time}</div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <Button variant="ghost" size="icon" className="text-slate-400 hover:text-indigo-600">
                                                <Eye className="h-4 w-4" />
                                            </Button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    {/* Pagination Footer */}
                    <div className="px-6 py-4 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-sm text-slate-500">
                        <div>Showing <span className="font-medium text-slate-900 dark:text-white">1</span> to <span className="font-medium text-slate-900 dark:text-white">10</span> of <span className="font-medium text-slate-900 dark:text-white">248</span> results</div>
                        <div className="flex gap-1">
                            <Button variant="outline" size="icon" className="h-8 w-8 disabled:opacity-50" disabled>{'<'}</Button>
                            <Button variant="default" size="icon" className="h-8 w-8 bg-indigo-600 hover:bg-indigo-700">1</Button>
                            <Button variant="outline" size="icon" className="h-8 w-8">2</Button>
                            <Button variant="outline" size="icon" className="h-8 w-8">3</Button>
                            <span className="flex items-center px-2">...</span>
                            <Button variant="outline" size="icon" className="h-8 w-8">25</Button>
                            <Button variant="outline" size="icon" className="h-8 w-8">{'>'}</Button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}
