export default function Home() {
    return (
        <main className="min-h-screen bg-gradient-to-b from-slate-50 to-slate-100 dark:from-slate-950 dark:to-slate-900">
            <div className="container mx-auto px-4 py-16">
                <div className="text-center">
                    <h1 className="text-4xl font-bold tracking-tight text-slate-900 dark:text-white sm:text-6xl">
                        Phish<span className="text-indigo-600">Guard</span>
                    </h1>
                    <p className="mt-6 text-lg leading-8 text-slate-600 dark:text-slate-300">
                        AI-Powered Phishing Detection. Scan any URL for hidden threats.
                    </p>
                    <div className="mt-10 flex items-center justify-center gap-x-6">
                        <a
                            href="/dashboard"
                            className="rounded-md bg-indigo-600 px-6 py-3 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
                        >
                            Open Dashboard
                        </a>
                    </div>
                </div>
            </div>
        </main>
    );
}
