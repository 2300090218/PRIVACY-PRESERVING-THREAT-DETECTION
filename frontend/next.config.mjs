/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    // When running under Vercel unified deployment, vercel.json handles routing /api to the Python serverless runtime
    if (process.env.VERCEL) {
      return [];
    }
    const apiHost = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");
    return [
      {
        source: "/api/:path*",
        destination: `${apiHost}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
