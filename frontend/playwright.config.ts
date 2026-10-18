import { defineConfig, devices } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const artifacts = path.join(root, '.test-artifacts', 'browser-e2e', randomUUID());
mkdirSync(artifacts, { recursive: true });
const python = process.env.AUTOPATCH_PYTHON || (process.platform === 'win32'
  ? path.join(root, '.venv', 'Scripts', 'python.exe') : 'python');

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60000,
  expect: { timeout: 15000 },
  forbidOnly: !!process.env.CI,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: { baseURL: 'http://127.0.0.1:5174', trace: 'retain-on-failure', screenshot: 'only-on-failure' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], channel: process.env.AUTOPATCH_BROWSER_CHANNEL } }],
  webServer: [
    {
      command: `"${python}" -m uvicorn tests.browser_app:app --host 127.0.0.1 --port 8765`,
      cwd: root,
      url: 'http://127.0.0.1:8765/health',
      reuseExistingServer: false,
      timeout: 180000,
      env: {
        DATABASE_URL: `sqlite:///${path.join(artifacts, 'browser-e2e.db').replaceAll('\\', '/')}`,
        AUTOPATCH_E2E_ROOT: artifacts,
        LLM_PROVIDER: 'mock',
        DOCKER_ENABLED: 'false',
        ALLOW_LOCAL_FALLBACK: 'true',
        CORS_ORIGINS: '["http://127.0.0.1:5174"]',
        LOG_LEVEL: 'WARNING',
      },
    },
    {
      command: 'npm run dev -- --port 5174',
      url: 'http://127.0.0.1:5174',
      reuseExistingServer: false,
      timeout: 30000,
      env: { VITE_API_BASE_URL: 'http://127.0.0.1:8765' },
    },
  ],
});
