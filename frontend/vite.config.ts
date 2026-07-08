import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
//
// tailwindcss() restored here. It had been removed from this array entirely
// ("Temporarily removed... to unblock server boot"), which is the actual
// root cause of every missing grid-*/signal-* style in the app: with no
// plugin registered to intercept `@import "tailwindcss";`, main.tsx's CSS
// import couldn't be JIT-compiled at all -- which is why a prior pass had
// redirected main.tsx at a separate, static, manually-generated output.css
// as a workaround (also reverted this pass; see main.tsx).
//
// package.json confirms @tailwindcss/vite is an installed devDependency
// (^4.0.0, matching the `tailwindcss` package's own ^4.0.0), and
// node_modules/@tailwindcss/vite/oxide-win32-x64-msvc is present -- the
// correct native engine binary for this machine. Both prerequisites for the
// plugin to load are satisfied. What isn't verifiable from here: this repo
// is edited through a remote file bridge with no shell access on this
// machine, so `npm run dev` was not actually re-run to confirm the dev
// server boots clean end-to-end. If it still fails to boot after this
// change, that's the next concrete step -- run `npm run dev` locally and
// send the actual error, rather than continuing to guess at the cause from
// a file-only view.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: false,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false
      }
    }
  }
})