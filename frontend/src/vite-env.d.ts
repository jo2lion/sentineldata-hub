/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * SECURITY: anything under `VITE_*` is compiled directly into the static
   * browser bundle. Do not treat VITE_API_KEY as a server-side secret — see
   * the warning block at the top of App.tsx before wiring this into any
   * public-facing deployment.
   */
  readonly VITE_API_KEY?: string;
  readonly VITE_API_PROXY_TARGET?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
