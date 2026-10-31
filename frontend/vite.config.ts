import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

// Dev:   `npm run dev:full` starts Flask (port 5000) + Vite (port 5173); /api is proxied to Flask.
// Build: `npm run build` writes dist/, which Flask serves on http://localhost:5000.
export default defineConfig({
  plugins: [tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: { "/api": "http://127.0.0.1:5000" },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    chunkSizeWarningLimit: 2500, // face-api bundles TensorFlow.js (~1.3 MB)
    // Two pages: the landing page (/) and the application (/app.html).
    rollupOptions: {
      input: {
        landing: "index.html",
        app: "app.html",
      },
    },
  },
});
