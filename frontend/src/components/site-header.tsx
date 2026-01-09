"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { Shield, Bell, User } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { ThemeToggle } from "@/components/theme-toggle"

export function SiteHeader() {
    const pathname = usePathname()

    const navItems = [
        { href: "/dashboard", label: "Dashboard" },
        { href: "/history", label: "Scan History" },
        { href: "/threat-map", label: "Threat Map" },
        { href: "/settings", label: "Settings" },
    ]

    return (
        <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
            <div className="container flex h-16 items-center justify-between">
                {/* Logo */}
                <div className="flex items-center gap-2">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-600 text-white">
                        <Shield className="h-5 w-5" />
                    </div>
                    <span className="text-xl font-bold tracking-tight">PhishGuard</span>
                </div>

                {/* Navigation */}
                <nav className="hidden md:flex items-center gap-6">
                    {navItems.map((item) => (
                        <Link
                            key={item.href}
                            href={item.href}
                            className={cn(
                                "text-sm font-medium transition-colors hover:text-primary",
                                pathname === item.href
                                    ? "text-primary"
                                    : "text-muted-foreground"
                            )}
                        >
                            {item.label}
                        </Link>
                    ))}
                </nav>

                {/* Right Actions */}
                <div className="flex items-center gap-4">
                    <ThemeToggle />
                    <Button variant="ghost" size="icon" className="text-muted-foreground">
                        <Bell className="h-5 w-5" />
                    </Button>
                    <div className="h-8 w-8 rounded-full bg-slate-200 dark:bg-slate-800 flex items-center justify-center border border-slate-300 dark:border-slate-700">
                        <User className="h-5 w-5 text-slate-600 dark:text-slate-400" />
                    </div>
                </div>
            </div>
        </header>
    )
}
