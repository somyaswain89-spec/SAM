import { expect, test } from '@playwright/test';

test('login, create persisted inventory, and record a finding workflow', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel('Email address').fill('admin@sam.local');
  await page.getByLabel('Password').fill('demo-access');
  await page.getByRole('button', { name: 'Sign in' }).click();

  await expect(page).toHaveURL('/');
  await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible();
  await expect(page.getByText('Assets monitored')).toBeVisible();

  const assetId = `E2E-${Date.now()}`;
  const assetName = `qa-${assetId.toLowerCase()}.example`;
  await page.getByRole('link', { name: 'Asset inventory' }).click();
  await page.getByRole('button', { name: 'Add asset' }).click();
  const assetForm = page.locator('form');
  await assetForm.getByLabel('Asset ID').fill(assetId);
  await assetForm.getByLabel('Name or hostname').fill(assetName);
  await assetForm.getByLabel('Type').selectOption('Website');
  await assetForm.getByLabel('Classification').selectOption('External facing');
  await assetForm.getByLabel('Owner').fill('E2E Verification');
  await assetForm.getByLabel('Environment').fill('QA');
  await assetForm.getByLabel('Criticality').selectOption('High');
  await page.getByRole('button', { name: 'Save asset' }).click();

  const assetRow = page.getByRole('row').filter({ hasText: assetId });
  await expect(assetRow).toContainText(assetName);
  await expect(assetRow).toContainText('External facing');
  await page.reload();
  await expect(page.getByRole('row').filter({ hasText: assetId })).toContainText(assetName);

  await page.getByRole('link', { name: 'Workflows' }).click();
  await expect(page.getByRole('heading', { name: 'Operational workflows' })).toBeVisible();
  await page.getByRole('combobox', { name: 'Asset', exact: true }).selectOption(assetId);
  await page.getByLabel('Reason and context').fill('E2E verifies a persisted scanner rescan request.');
  await page.getByRole('button', { name: 'Submit request' }).click();
  const workflowRow = page.getByRole('row').filter({ hasText: assetId });
  await expect(workflowRow).toContainText('Rescan');
  await expect(workflowRow).toContainText('Pending');

  await page.getByRole('link', { name: 'Containment' }).click();
  await expect(page.getByRole('heading', { name: 'Containment approvals' })).toBeVisible();
  await page.getByRole('combobox', { name: 'Asset', exact: true }).selectOption('SRV-2201');
  const impactPreview = page.locator('.impact-preview');
  await expect(impactPreview).toContainText(/Quarantine may interrupt access/);
  await expect(impactPreview).toContainText('customer-portal.acme.test');
  const impactAcknowledgement = page.getByRole('checkbox');
  await impactAcknowledgement.check();
  await page.getByRole('combobox', { name: 'Action', exact: true }).selectOption('Release');
  await expect(impactAcknowledgement).not.toBeChecked();
  await expect(impactPreview).toContainText(/Release may restore access/);
  await page.getByRole('combobox', { name: 'Action', exact: true }).selectOption('Quarantine');
  await expect(impactAcknowledgement).not.toBeChecked();
  await expect(impactPreview).toContainText(/Quarantine may interrupt access/);
  await impactAcknowledgement.check();
  await page.getByRole('button', { name: 'Submit for independent approval' }).click();
  const containmentRequest = page.locator('.request-card').filter({ hasText: 'SRV-2201' });
  await expect(containmentRequest).toContainText('Quarantine');
  await expect(containmentRequest).toContainText('Approval required');

  await page.getByRole('link', { name: 'Vulnerabilities' }).click();
  const startWork = page.getByRole('button', { name: /FND-\d+: Start work/ }).first();
  const findingId = (await startWork.textContent())?.split(':')[0];
  expect(findingId).toBeTruthy();
  const stateChange = page.waitForResponse(
    (response) =>
      response.url().includes(`/findings/${findingId}/state`) &&
      response.request().method() === 'PATCH' &&
      response.ok(),
  );
  await startWork.click();
  await stateChange;
  await page.getByLabel('Finding state').selectOption('In Progress');
  await expect(page.getByRole('row').filter({ hasText: findingId! })).toContainText('In Progress');
  await page.reload();
  await page.getByLabel('Finding state').selectOption('In Progress');
  await expect(page.getByRole('row').filter({ hasText: findingId! })).toContainText('In Progress');

  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page).toHaveURL(/\/login$/);
});

test('requester and independent approver complete a persisted governance exception', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Email address').fill('admin@sam.local');
  await page.getByLabel('Password').fill('demo-access');
  const adminLoginResponse = page.waitForResponse((response) =>
    response.url().endsWith('/api/v1/auth/login') && response.request().method() === 'POST',
  );
  await page.getByRole('button', { name: 'Sign in' }).click();
  const adminSession = await (await adminLoginResponse).json() as { access_token: string };
  const createdUser = await page.request.post('http://127.0.0.1:5173/api/v1/auth/users', {
    headers: { Authorization: `Bearer ${adminSession.access_token}`, 'Idempotency-Key': 'e2e-governance-user-create-0001' },
    data: { email: 'governance-e2e@sam.local', password: 'governance-e2e-password', role: 'analyst' },
  });
  expect(createdUser.status()).toBe(201);

  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.getByLabel('Email address').fill('governance-e2e@sam.local');
  await page.getByLabel('Password').fill('governance-e2e-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible();
  await page.getByRole('link', { name: 'Governance' }).click();
  await expect(page.getByRole('heading', { name: 'Governance' })).toBeVisible();
  await page.getByRole('combobox', { name: 'Asset' }).selectOption('WEB-1042');
  await page.getByLabel('Business justification').fill('Short deferral while the production patch is validated in staging.');
  await page.getByRole('button', { name: 'Submit for approval' }).click();
  const requestCard = page.locator('.request-card').filter({ hasText: 'Short deferral while the production patch is validated in staging.' });
  await expect(requestCard).toContainText('Pending');
  const cardText = await requestCard.textContent();
  const exceptionId = cardText?.match(/EX-[A-F0-9]+/)?.[0];
  expect(exceptionId).toBeTruthy();
  await expect(requestCard.getByRole('button', { name: 'Approve' })).toHaveCount(0);

  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.getByLabel('Email address').fill('admin@sam.local');
  await page.getByLabel('Password').fill('demo-access');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('link', { name: 'Governance' }).click();
  const approvalCard = page.locator('.request-card').filter({ hasText: exceptionId! });
  await expect(approvalCard).toContainText('Pending');
  await approvalCard.getByLabel(`Review note for ${exceptionId}`).fill('Approved for a limited change window.');
  await approvalCard.getByRole('button', { name: 'Approve' }).click();
  await expect(approvalCard).toContainText('Approved');
  await expect(approvalCard).toContainText('Approved for a limited change window.');
});

test('local QA processes real asset import and export tasks and answers rescan guidance', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('Email address').fill('admin@sam.local');
  await page.getByLabel('Password').fill('demo-access');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('link', { name: 'Asset inventory' }).click();

  const importedId = `IMP-${Date.now()}`;
  const importedName = `imported-${importedId.toLowerCase()}.example`;
  const importCsv = [
    'id,name,kind,classification,owner,environment,criticality,compliance,waf',
    `${importedId},${importedName},Website,External facing,QA Import,QA,High,91,Protected`,
  ].join('\n');
  await page.getByLabel('Import CSV or XLSX').setInputFiles({
    name: 'qa-assets.csv',
    mimeType: 'text/csv',
    buffer: Buffer.from(importCsv),
  });
  await page.getByRole('button', { name: 'Upload and validate' }).click();
  await expect(page.getByText('Import completed', { exact: true })).toBeVisible();
  await expect(page.getByText('1 processed of 1', { exact: false })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('row').filter({ hasText: importedId })).toContainText(importedName);

  await page.getByRole('button', { name: 'Generate asset CSV export' }).click();
  await expect(page.getByText('Export completed', { exact: true })).toBeVisible();
  const exportDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download CSV' }).click();
  expect((await exportDownload).suggestedFilename()).toBe('sam-assets.csv');

  const duplicateCsv = [
    'id,name,kind,classification,owner,environment,criticality,compliance,waf',
    `${importedId},duplicate.example,Website,Internal facing,QA Import,QA,Low,,`,
  ].join('\n');
  await page.getByLabel('Import CSV or XLSX').setInputFiles({
    name: 'duplicate-assets.csv',
    mimeType: 'text/csv',
    buffer: Buffer.from(duplicateCsv),
  });
  await page.getByRole('button', { name: 'Upload and validate' }).click();
  await expect(page.getByText('Import completed_with_errors', { exact: true })).toBeVisible();
  await expect(page.getByText('1 rejected', { exact: false })).toBeVisible();
  const errorDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download row error report' }).click();
  expect((await errorDownload).suggestedFilename()).toBe('duplicate-assets.errors.csv');

  await page.getByRole('link', { name: 'AI security analyst' }).click();
  await page.getByPlaceholder(/Ask about a specific asset/).fill('How do I request an approved rescan?');
  await page.getByRole('button', { name: 'Ask analyst' }).click();
  await expect(page.getByText(/create a Rescan workflow with the asset, finding, reason/)).toBeVisible();
  await expect(page.getByText('rule-based-qa', { exact: false })).toBeVisible();
});

test('password reset UI validates the one-time flow and reports unavailable email delivery', async ({ page }) => {
  await page.goto('/login');
  await page.getByRole('link', { name: 'Forgot your password?' }).click();
  await expect(page.getByRole('heading', { name: 'Reset your password' })).toBeVisible();
  await page.getByLabel('Email address').fill('admin@sam.local');
  await page.getByRole('button', { name: 'Send reset link' }).click();
  await expect(page.getByRole('alert')).toContainText('Password reset email delivery is not configured');

  await page.goto('/reset-password?token=short-invalid-token');
  await expect(page.getByRole('heading', { name: 'Set a new password' })).toBeVisible();
  await page.getByLabel('New password', { exact: true }).fill('a-new-password-long-enough');
  await page.getByLabel('Confirm new password').fill('a-different-password-long-enough');
  await page.getByRole('button', { name: 'Update password' }).click();
  await expect(page.getByText('Passwords do not match')).toBeVisible();
  await page.getByLabel('Confirm new password').fill('a-new-password-long-enough');
  await page.getByRole('button', { name: 'Update password' }).click();
  await expect(page.getByRole('alert')).toContainText('Request validation failed');
});

test('administrator can create, deactivate, and restore a user account', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('Email address').fill('admin@sam.local');
  await page.getByLabel('Password').fill('demo-access');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('link', { name: 'User administration' }).click();
  await expect(page.getByRole('heading', { name: 'User administration' })).toBeVisible();

  const email = `account-${Date.now()}@sam.local`;
  await page.getByLabel('Work email').fill(email);
  await page.getByLabel('Temporary password').fill('temporary-account-password-2026');
  await page.getByRole('combobox', { name: 'Role', exact: true }).selectOption('viewer');
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByRole('row').filter({ hasText: email }).getByLabel(`Role for ${email}`)).toHaveValue('viewer');
  await expect(page.getByRole('status')).toContainText(`Created ${email}`);

  const row = page.getByRole('row').filter({ hasText: email });
  await row.getByRole('button', { name: 'Deactivate' }).click();
  await expect(row).toContainText('Inactive');
  await row.getByRole('button', { name: 'Reactivate' }).click();
  await expect(row).toContainText('Active');
  await row.getByLabel(`Role for ${email}`).selectOption('analyst');
  await row.getByRole('button', { name: 'Save role' }).click();
  await expect(row.getByLabel(`Role for ${email}`)).toHaveValue('analyst');
});

test('attack surface records an authorized domain and clearly blocks unconfigured discovery', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('Email address').fill('admin@sam.local');
  await page.getByLabel('Password').fill('demo-access');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('link', { name: 'Attack surface' }).click();
  await expect(page.getByRole('heading', { name: 'Attack surface' })).toBeVisible();
  await expect(page.locator('.notice.warning')).toContainText('Set CERTSPOTTER_API_TOKEN on the API and worker');

  const domain = `authorized-${Date.now()}.example.com`;
  await page.getByLabel('Registered root domain').fill(domain);
  await page.getByLabel('Authorization basis').fill('Approved under E2E authorization record SEC-7781.');
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Register authorized domain' }).click();

  const targetRow = page.getByRole('row').filter({ hasText: domain });
  await expect(targetRow).toContainText('Active');
  await expect(targetRow).toContainText('Approved under E2E authorization record SEC-7781.');
  await expect(targetRow.getByRole('button', { name: 'Discover' })).toBeDisabled();
  await expect(page.getByText(/SAM does not probe, crawl, or scan the returned hostnames/)).toBeVisible();
});
