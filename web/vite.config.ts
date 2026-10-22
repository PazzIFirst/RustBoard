import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// 开发时把 /api 反代到本地面板；生产由面板同源提供，前端不写死任何地址。
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "RUSTBOARD_");
  return {
    plugins: [react()],
    build: {
      outDir: "dist",
      sourcemap: false,
    },
    server: {
      port: 5173,
      proxy: {
        "/api": env.RUSTBOARD_PANEL_URL || "http://127.0.0.1:8080",
      },
    },
  };
});
