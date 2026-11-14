import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// The server embeds the build (internal/server/webdist) with the `web` build tag.
//
// `vite build --mode demo` makes the static live demo instead (site/demo, read by the project page): the same dashboard, with the answers
// of `vmsctl server demo` recorded in a file (src/lib/demoApi.ts) in place of a server.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  base: mode === "demo" ? "./" : "/",
  define: { DEMO: JSON.stringify(mode === "demo") },
  build: mode === "demo" ? { outDir: "../site/demo", emptyOutDir: true, sourcemap: false, assetsInlineLimit: 0, cssCodeSplit: false } : {
    outDir: "../internal/server/webdist",
    emptyOutDir: false, // scripts/prebuild.mjs empties it, keeping the .gitignore
    sourcemap: false,
    // No inline scripts or styles: the server's CSP forbids them.
    assetsInlineLimit: 0,
    cssCodeSplit: false,
  },
  server: {
    // `npm run dev` talks to a vmsctl server on this address.
    proxy: { "/api": { target: loadEnv(mode, ".", "").VMSCTL_SERVER || "http://127.0.0.1:8443", changeOrigin: false } },
  },
  test: { environment: "node" },
}));
