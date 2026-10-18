import { test, expect, APIRequestContext, Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const backend = 'http://127.0.0.1:8765';
type Run = { id: string; repository_path: string; status: string };
const pageErrors = new WeakMap<Page, string[]>();

test.beforeEach(async ({ page }) => {
  pageErrors.set(page, []);
  page.on('pageerror', error => pageErrors.get(page)!.push(error.message));
});
test.afterEach(async ({ page }) => {
  expect(pageErrors.get(page)).toEqual([]);
});

async function fixture(request: APIRequestContext, name: string): Promise<Run> {
  const response = await request.get(`${backend}/api/workflows?limit=100`);
  expect(response.ok()).toBeTruthy();
  const runs = (await response.json()).items as Run[];
  const run = runs.find(item => path.basename(item.repository_path) === name);
  expect(run, `Missing browser fixture ${name}`).toBeTruthy();
  return run!;
}

async function finishReviews(page: Page, request: APIRequestContext, run: Run, decision: 'approve' | 'reject') {
  await page.goto(`/?workflow=${run.id}`);
  await expect(page.getByRole('heading', { name: 'Patch review', exact: true })).toBeVisible();
  const count = await page.locator('button.finding').count();
  expect(count).toBeGreaterThan(0);
  for (let index = 0; index < count; index++) {
    await page.locator('button.finding').nth(index).click();
    const reviewer = page.getByLabel('Reviewer label');
    await expect(reviewer).toBeEnabled();
    await reviewer.fill('Browser regression');
    if (decision === 'reject') {
      await page.getByLabel('Review comment').fill('');
      await expect(page.getByRole('button', { name: 'Reject proposal' })).toBeDisabled();
    }
    await page.getByLabel('Review comment').fill(`Browser ${decision}: reviewed actual scanner and test evidence`);
    const action = page.getByRole('button', { name: decision === 'approve' ? 'Approve proposal' : 'Reject proposal' });
    await action.click();
    await expect(action).toBeDisabled();
    await expect.poll(async () => {
      const report = await (await request.get(`${backend}/api/reports/${run.id}`)).json();
      return report.reviews.length;
    }).toBe(index + 1);
  }
}

test('submits a clean workflow and preserves the selection after refresh', async ({ page, request }) => {
  const seed = await fixture(request, 'approve-case');
  await page.goto('/');
  await page.getByLabel('Repository path').fill(path.join(path.dirname(seed.repository_path), 'clean-case'));
  await page.getByLabel('Additional retries').fill('0');
  await page.getByRole('button', { name: /Start workflow/ }).click();
  await expect(page).toHaveURL(/workflow=wf-/);
  await expect(page.getByText('Outcome: no findings', { exact: true })).toBeVisible();
  const selected = new URL(page.url()).searchParams.get('workflow');
  await page.reload();
  await expect(page.getByText('Outcome: no findings', { exact: true })).toBeVisible();
  expect(new URL(page.url()).searchParams.get('workflow')).toBe(selected);
});

test('superseded attempt stays disabled; approvals and report persist', async ({ page, request }) => {
  const run = await fixture(request, 'approve-case');
  const source = path.join(run.repository_path, 'app.py');
  const before = readFileSync(source, 'utf8');
  await page.goto(`/?workflow=${run.id}`);
  const attempts = page.getByRole('combobox', { name: 'Patch attempt' });
  await expect(attempts).toBeVisible();
  const options = attempts.locator('option');
  await expect(options).toHaveCount(2);
  await attempts.selectOption({ index: 1 });
  await expect(page.getByText('This attempt has been superseded.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Approve proposal' })).toBeDisabled();
  await attempts.selectOption({ index: 0 });
  await expect(page.locator('.check').filter({ hasText: 'Required scanner coverage' })).toContainText('Passed');
  await finishReviews(page, request, run, 'approve');
  await page.reload();
  await expect(page.getByText('Outcome: proposals approved', { exact: true })).toBeVisible();
  await page.getByRole('tab', { name: 'Report', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Review decisions', exact: true })).toBeVisible();
  const report = await (await request.get(`${backend}/api/reports/${run.id}`)).json();
  expect(report.workflow.status).toBe('APPROVED');
  expect(report.reviews).toHaveLength(2);
  expect(report.unresolved_findings).toHaveLength(0);
  expect(readFileSync(source, 'utf8')).toBe(before);
});

test('rejection requires a reason and persists unresolved findings', async ({ page, request }) => {
  const run = await fixture(request, 'reject-case');
  await finishReviews(page, request, run, 'reject');
  await page.reload();
  await expect(page.getByText('Outcome: review complete with unresolved', { exact: true })).toBeVisible();
  const report = await (await request.get(`${backend}/api/reports/${run.id}`)).json();
  expect(report.workflow.status).toBe('REJECTED');
  expect(report.reviews).toHaveLength(2);
  expect(report.unresolved_findings).toHaveLength(2);
});

test('incomplete scanner evidence disables review in UI and API', async ({ page, request }) => {
  const run = await fixture(request, 'incomplete-case');
  await page.goto(`/?workflow=${run.id}`);
  await expect(page.getByText('Scanner coverage is incomplete or unavailable. Remediation cannot be confirmed.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Approve proposal' })).toBeDisabled();
  const report = await (await request.get(`${backend}/api/reports/${run.id}`)).json();
  const current = report.patches.find((p: { status: string }) => p.status === 'READY_FOR_REVIEW');
  const response = await request.post(`${backend}/api/patches/${current.id}/approve`, { data: { reviewer_label: 'Browser regression' } });
  expect(response.status()).toBe(409);
});

test('mobile layout fits a narrow viewport', async ({ page, request }) => {
  const run = await fixture(request, 'incomplete-case');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`/?workflow=${run.id}`);
  await expect(page.getByRole('heading', { name: 'Workflow overview', exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
});
