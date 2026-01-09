/** @type {import('next').NextConfig} */
const nextConfig = {
    // Enable strict mode for better development experience
    reactStrictMode: true,

    // Configure API rewrites to proxy Flask backend
    async rewrites() {
        return [
            {
                source: '/api/:path*',
                destination: 'http://127.0.0.1:5000/api/:path*',
            },
            {
                source: '/scan',
                destination: 'http://127.0.0.1:5000/scan',
            },
            {
                source: '/health',
                destination: 'http://127.0.0.1:5000/health',
            },
        ];
    },
};

export default nextConfig;
