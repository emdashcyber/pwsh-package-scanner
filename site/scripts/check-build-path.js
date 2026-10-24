import { readFile, access } from 'node:fs/promises';

const html = await readFile('dist/index.html', 'utf8');
if (!html.includes('/pwsh-package-scanner/')) throw new Error('Astro output is missing the configured project base path.');
if (!html.includes('/pwsh-package-scanner/methodology/')) throw new Error('Methodology link is missing the project base path.');
await access('dist/api/v1/manifest.json');
await access('dist/api/v1/openapi.json');
process.stdout.write('Built site paths and static API files are present.\n');
