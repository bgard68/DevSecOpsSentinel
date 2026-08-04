/// <reference types="vite/client" />

/**
 * Injected by Vite from package.json. See the `define` block in vite.config.ts.
 */
declare const __APP_VERSION__: string;

interface ImportMetaEnv {
  /**
   * Origin of the API, baked in at build time.
   *
   * Empty locally, which leaves the relative paths the dev proxy expects. Set
   * by the deploy workflow, because a deployed client and API are separate
   * origins and nothing rewrites between them.
   */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
