import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  output: "standalone",   // enables Docker-friendly single-file output
};

export default nextConfig;
