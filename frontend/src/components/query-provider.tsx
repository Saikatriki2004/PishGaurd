'use client';

/**
 * React Query Provider
 * 
 * Wraps the application with TanStack Query client for API caching.
 */

// @ts-ignore
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState } from 'react';

interface QueryProviderProps {
    children: React.ReactNode;
}

export function QueryProvider({ children }: QueryProviderProps) {
    const [queryClient] = useState(
        () =>
            new QueryClient({
                defaultOptions: {
                    queries: {
                        staleTime: 5 * 1000, // 5 seconds
                        retry: 2,
                        refetchOnWindowFocus: true,
                    },
                    mutations: {
                        retry: 1,
                    },
                },
            })
    );

    return (
        <QueryClientProvider client={queryClient}>
            {children}
        </QueryClientProvider>
    );
}
