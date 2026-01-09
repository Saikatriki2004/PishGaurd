"use client"

import { useState } from "react"
import { Search, RotateCcw, MessageSquare, Menu, Activity, Globe, Map as MapIcon, Maximize, Minus, Plus, Play, Pause, SkipBack, SkipForward, BarChart2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { cn } from "@/lib/utils"

export default function ThreatMap() {
    return (
        <div className="relative h-[calc(100vh-4rem)] w-full overflow-hidden bg-slate-950 text-white">
            {/* Map Background Placeholder */}
            <div className="absolute inset-0 z-0 bg-slate-950">
                {/* Grid Pattern */}
                <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:40px_40px] opacity-20" />

                {/* World Map SVG Placeholder (Abstract) */}
                <div className="absolute inset-0 flex items-center justify-center opacity-30 pointer-events-none">
                    <svg viewBox="0 0 1000 500" className="w-[80%] fill-slate-700">
                        <path d="M100,150 L200,120 L250,180 L180,250 Z" />
                        <path d="M300,100 L450,80 L500,200 L350,220 Z" />
                        <path d="M600,120 L750,110 L800,250 L650,280 Z" />
                        <path d="M500,350 L600,320 L650,400 L550,450 Z" />
                        {/* Add more shapes to simulate continents roughly */}
                    </svg>
                </div>

                {/* Connection Lines (Mock) */}
                <svg className="absolute inset-0 pointer-events-none">
                    <path d="M220,180 Q400,100 700,200" fill="none" stroke="#ef4444" strokeWidth="1" strokeDasharray="5,5" className="animate-pulse" />
                    <circle cx="700" cy="200" r="4" fill="#3b82f6" className="animate-ping" />
                </svg>
            </div>

            {/* Left Sidebar - Map Controls */}
            <div className="absolute left-6 top-6 bottom-6 w-80 z-10 flex flex-col gap-4 pointer-events-none">
                <div className="bg-slate-900/90 backdrop-blur-md border border-slate-800 rounded-xl p-4 pointer-events-auto">
                    <div className="flex items-center gap-2 mb-4 text-white">
                        <Menu className="h-5 w-5 text-blue-500" />
                        <h3 className="font-bold">Map Controls</h3>
                    </div>
                    <p className="text-xs text-slate-400 mb-4">Configure threat visualization layers</p>

                    <div className="space-y-6">
                        <div className="space-y-2">
                            <Label className="text-xs uppercase text-slate-500 font-bold">Focus Region</Label>
                            <div className="relative">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
                                <Input placeholder="e.g. Eastern Europe" className="bg-slate-800 border-slate-700 pl-9 h-9 text-sm" />
                            </div>
                        </div>

                        <div className="space-y-3">
                            <div className="flex items-center justify-between">
                                <Label className="text-xs uppercase text-slate-500 font-bold">Threat Types</Label>
                                <button className="text-blue-500 text-xs">Reset</button>
                            </div>
                            <div className="space-y-2">
                                {[
                                    { id: "malware", label: "Malware & Ransomware", checked: true },
                                    { id: "credential", label: "Credential Harvesting", checked: true },
                                    { id: "social", label: "Social Engineering", checked: false },
                                ].map((item) => (
                                    <div key={item.id} className="flex items-center space-x-2">
                                        <Checkbox id={item.id} defaultChecked={item.checked} className="border-slate-600 data-[state=checked]:bg-blue-600 data-[state=checked]:border-blue-600" />
                                        <Label htmlFor={item.id} className="text-sm text-slate-300 font-normal">{item.label}</Label>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label className="text-xs uppercase text-slate-500 font-bold">Attack Vector</Label>
                            <div className="flex gap-2">
                                <Button size="sm" className="bg-blue-600 text-white hover:bg-blue-700 h-8 text-xs gap-1.5"><MessageSquare className="h-3 w-3" /> Email</Button>
                                <Button size="sm" variant="outline" className="bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700 h-8 text-xs gap-1.5"><MessageSquare className="h-3 w-3" /> SMS</Button>
                                <Button size="sm" variant="outline" className="bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700 h-8 text-xs gap-1.5"><Globe className="h-3 w-3" /> Web</Button>
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label className="text-xs uppercase text-slate-500 font-bold">Display Mode</Label>
                            <div className="space-y-2">
                                <div className="border border-blue-900/50 bg-blue-900/20 rounded-lg p-3 flex items-center gap-3 cursor-pointer">
                                    <div className="h-4 w-4 rounded-full border-4 border-blue-500" />
                                    <div className="flex-1">
                                        <div className="text-sm font-medium text-white">Heatmap</div>
                                        <div className="text-xs text-slate-400">Density visualization</div>
                                    </div>
                                </div>
                                <div className="border border-slate-800 bg-slate-900/50 rounded-lg p-3 flex items-center gap-3 cursor-pointer opacity-70 hover:opacity-100">
                                    <div className="h-4 w-4 rounded-full border border-slate-500" />
                                    <div className="flex-1">
                                        <div className="text-sm font-medium text-white">Cluster Points</div>
                                        <div className="text-xs text-slate-400">Individual incidents</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Legend Box */}
                <div className="bg-slate-900/90 backdrop-blur-md border border-slate-800 rounded-xl p-4 pointer-events-auto mt-auto">
                    <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-2 text-xs font-bold text-slate-400 uppercase">
                            <BarChart2 className="h-3 w-3 text-blue-500" /> Legend
                        </div>
                        <span className="text-xs text-blue-500">Medium+</span>
                    </div>
                    <div className="space-y-2 text-xs">
                        <div className="flex items-center gap-2">
                            <div className="h-2 w-2 rounded-full bg-red-500" />
                            <span className="text-slate-300">Critical / Malicious</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <div className="h-2 w-2 rounded-full bg-orange-500" />
                            <span className="text-slate-300">Suspicious</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <div className="h-2 w-2 rounded-full bg-blue-500" />
                            <span className="text-slate-300">Monitoring / Safe</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Right Sidebar - Live Feed */}
            <div className="absolute right-6 top-6 bottom-6 w-80 z-10 flex flex-col gap-4 pointer-events-none">
                <div className="bg-slate-900/90 backdrop-blur-md border border-slate-800 rounded-xl overflow-hidden flex-1 flex flex-col pointer-events-auto">
                    <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900">
                        <div className="flex items-center gap-2">
                            <div className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
                            <h3 className="font-bold text-sm">Live Threat Feed</h3>
                        </div>
                        <span className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-slate-400">REAL-TIME</span>
                    </div>
                    <div className="flex-1 overflow-y-auto p-2 space-y-1 custom-scrollbar">
                        {/* Feed Item 1 */}
                        <div className="p-3 rounded-lg bg-slate-800/50 hover:bg-slate-800 transition-colors border-l-2 border-red-500">
                            <div className="flex justify-between items-start mb-1">
                                <span className="text-xs font-bold text-red-400">Malware C2</span>
                                <span className="text-[10px] text-slate-500">2s ago</span>
                            </div>
                            <div className="text-sm font-mono text-slate-300">192.168.45.22 → FinCorp</div>
                            <div className="flex items-center gap-1 mt-1 text-[10px] text-slate-500">
                                <Globe className="h-3 w-3" /> Moscow, RU
                            </div>
                        </div>

                        {/* Feed Item 2 */}
                        <div className="p-3 rounded-lg bg-slate-800/50 hover:bg-slate-800 transition-colors border-l-2 border-orange-500">
                            <div className="flex justify-between items-start mb-1">
                                <span className="text-xs font-bold text-orange-400">Cred Harvester</span>
                                <span className="text-[10px] text-slate-500">15s ago</span>
                            </div>
                            <div className="text-sm font-mono text-slate-300">login-microsoft-secure.com</div>
                            <div className="flex items-center gap-1 mt-1 text-[10px] text-slate-500">
                                <Globe className="h-3 w-3" /> Lagos, NG
                            </div>
                        </div>

                        {/* Feed Item 3 */}
                        <div className="p-3 rounded-lg bg-slate-800/50 hover:bg-slate-800 transition-colors border-l-2 border-blue-500">
                            <div className="flex justify-between items-start mb-1">
                                <span className="text-xs font-bold text-blue-400">Port Scan</span>
                                <span className="text-[10px] text-slate-500">42s ago</span>
                            </div>
                            <div className="text-sm font-mono text-slate-300">10.0.4.120 → Gateway</div>
                            <div className="flex items-center gap-1 mt-1 text-[10px] text-slate-500">
                                <Globe className="h-3 w-3" /> Shenzhen, CN
                            </div>
                        </div>
                    </div>

                    {/* Top Source Regions */}
                    <div className="p-4 border-t border-slate-800 bg-slate-900">
                        <h4 className="text-xs font-bold text-slate-400 uppercase mb-3">Top Source Regions</h4>
                        <div className="space-y-3">
                            <div>
                                <div className="flex justify-between text-xs mb-1">
                                    <span className="text-white">Eastern Europe</span>
                                    <span className="text-red-400 font-mono">4,281</span>
                                </div>
                                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                                    <div className="h-full bg-red-500 w-[85%] rounded-full" />
                                </div>
                            </div>
                            <div>
                                <div className="flex justify-between text-xs mb-1">
                                    <span className="text-white">Southeast Asia</span>
                                    <span className="text-orange-400 font-mono">2,104</span>
                                </div>
                                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                                    <div className="h-full bg-orange-500 w-[45%] rounded-full" />
                                </div>
                            </div>
                            <div>
                                <div className="flex justify-between text-xs mb-1">
                                    <span className="text-white">North America</span>
                                    <span className="text-blue-400 font-mono">982</span>
                                </div>
                                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                                    <div className="h-full bg-blue-500 w-[25%] rounded-full" />
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Map Controls (Bottom Right) */}
            <div className="absolute right-6 bottom-6 z-10 flex flex-col gap-2 pointer-events-auto">
                <div className="flex flex-col gap-1 bg-slate-900/90 backdrop-blur-md border border-slate-800 rounded-lg p-1">
                    <Button variant="ghost" size="icon" className="h-8 w-8 text-slate-300 hover:text-white hover:bg-slate-700 rounded"><Plus className="h-4 w-4" /></Button>
                    <Button variant="ghost" size="icon" className="h-8 w-8 text-slate-300 hover:text-white hover:bg-slate-700 rounded"><Minus className="h-4 w-4" /></Button>
                </div>
                <Button size="icon" className="h-10 w-10 bg-slate-800 border border-slate-700 hover:bg-slate-700 text-white rounded-lg">
                    <Activity className="h-5 w-5" />
                </Button>
            </div>

            {/* Bottom Player */}
            <div className="absolute bottom-6 left-1/2 -translate-x-1/2 z-10 pointer-events-auto">
                <div className="bg-slate-900/90 backdrop-blur-md border border-slate-800 rounded-full px-4 py-2 flex items-center gap-4">
                    <div className="flex items-center gap-2">
                        <Button variant="ghost" size="icon" className="h-8 w-8 text-slate-400 hover:text-white"><SkipBack className="h-4 w-4" /></Button>
                        <Button size="icon" className="h-10 w-10 rounded-full bg-blue-600 hover:bg-blue-700 text-white"><Play className="h-4 w-4 ml-0.5" /></Button>
                        {/* Spectrum Audio Visualizer mockup */}
                        <div className="flex items-end gap-1 h-6 w-20 mx-2">
                            {[40, 70, 45, 90, 60, 30, 80, 50, 70, 40].map((h, i) => (
                                <div key={i} className="w-1 bg-blue-500/50 rounded-t-sm" style={{ height: `${h}%` }} />
                            ))}
                        </div>
                    </div>
                    <div className="text-xs font-mono text-slate-400 pl-4 border-l border-slate-700">
                        LIVE
                    </div>
                </div>
            </div>

        </div>
    )
}
