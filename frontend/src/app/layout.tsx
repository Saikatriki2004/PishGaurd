import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { QueryProvider } from "@/components/query-provider";
import { SiteHeader } from "@/components/site-header";
import { Toaster } from "@/components/ui/toaster"

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
    title: "PhishGuard - AI-Powered Phishing Detection",
    description: "Real-time phishing detection and URL analysis",
};

export default function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="en" suppressHydrationWarning>
            <body className={inter.className}>
                <QueryProvider>
                    <ThemeProvider
                        attribute="class"
                        defaultTheme="system"
                        enableSystem
                        disableTransitionOnChange
                    >
                        <div className="relative flex min-h-screen flex-col">
                            <SiteHeader />
                            <main className="flex-1">
                                {children}
                            </main>
                        </div>
                        <Toaster />
                    </ThemeProvider>
                </QueryProvider>
            </body>
        </html>
    );
}
