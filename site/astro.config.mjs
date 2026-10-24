import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://emdashcyber.com',
  base: '/pwsh-package-scanner',
  output: 'static',
  trailingSlash: 'always',
  build: { format: 'directory' },
  vite: { build: { assetsInlineLimit: 0 } },
});
