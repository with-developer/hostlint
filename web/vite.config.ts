import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// The server embeds the build (internal/server/webdist) with the `web` build tag.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  build: {
    outDir: "../internal/server/webdist",
    emptyOutDir: false, // scripts/prebuild.mjs empties it, keeping the .gitignore
    sourcemap: false,
    // No inline scripts or styles: the server's CSP forbids them.
    assetsInlineLimit: 0,
    cssCodeSplit: false,
  },
  server: {
    // `npm run dev` talks to a hostlint server on this address.
    proxy: { "/api": { target: loadEnv(mode, ".", "").HOSTLINT_SERVER || "http://127.0.0.1:8443", changeOrigin: false } },
  },
  test: { environment: "node" },
}));
