/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_GOOGLE_ADS_CLIENT: string;
  readonly VITE_GA_MEASUREMENT_ID: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
