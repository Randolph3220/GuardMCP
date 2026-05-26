import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const authTarget = process.env.VITE_AUTH_TARGET || "http://127.0.0.1:8001";
const guardTarget = process.env.VITE_GUARD_TARGET || "http://127.0.0.1:8002";
const mcpTarget = process.env.VITE_MCP_SERVER_TARGET || "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    fs: {
      allow: [".."],
    },
    proxy: {
      "/auth": {
        target: authTarget,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/auth/, ""),
      },
      "/guard": {
        target: guardTarget,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/guard/, ""),
      },
      "/mcp-server": {
        target: mcpTarget,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/mcp-server/, ""),
      },
    },
  },
});
