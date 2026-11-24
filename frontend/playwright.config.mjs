import { defineConfig } from '@playwright/test';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const databasePath = join(tmpdir(), `sam-playwright-${process.pid}.db`);
const uploadPath = join(tmpdir(), `sam-playwright-uploads-${process.pid}`);

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: 'http://127.0.0.1:5173',
    browserName: 'chromium',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: [
    {
      command: 'uv run alembic upgrade head && uv run uvicorn backend.app:app --host 127.0.0.1 --port 8000',
      cwd: '..',
      url: 'http://127.0.0.1:8000/health/ready',
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        APP_ENV: 'development',
        SAM_MODE: 'qa',
        DATABASE_URL: `sqlite:///${databasePath}`,
        SAM_ADMIN_EMAIL: 'admin@sam.local',
        SAM_ADMIN_PASSWORD: 'demo-access',
        SAM_TOKEN_SECRET: 'sam-playwright-test-secret-with-at-least-32-characters',
        LOAD_SAMPLE_DATA: 'true',
        COOKIE_SECURE: 'false',
        CORS_ORIGINS: 'http://127.0.0.1:5173',
        UPLOAD_DIR: uploadPath,
        CELERY_TASK_ALWAYS_EAGER: 'true',
      },
    },
    {
      command: 'npm run dev -- --host 127.0.0.1 --strictPort',
      url: 'http://127.0.0.1:5173',
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});
