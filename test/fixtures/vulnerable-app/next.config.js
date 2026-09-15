/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // FE-004: production source maps published
  productionBrowserSourceMaps: true,

  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          // NET-001: missing CSP / HSTS / nosniff / Referrer-Policy / Permissions-Policy
          { key: 'X-Frame-Options', value: 'DENY' },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
