// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

const { chromium, expect } = require('@playwright/test');
const { randomUUID } = require('node:crypto');
const assert = require('node:assert/strict');

async function run() {
  const base = new URL(process.env.O2_RBAC_BROWSER_URL);
  assert.equal(base.protocol, 'http:');
  assert.equal(base.hostname, '127.0.0.1');
  assert(process.argv.includes('--acknowledge-disposable-fixture'));
  const root = { email: process.env.O2_RBAC_ROOT_EMAIL, password: process.env.O2_RBAC_ROOT_PASSWORD };
  assert(root.email && root.password);
  const auth = 'Basic ' + Buffer.from(`${root.email}:${root.password}`).toString('base64');
  const id = randomUUID();
  const viewer = { email: `viewer-${id}@example.com`, password: randomUUID() + '1!Aa' };
  const title = `Browser fixture ${id}`;
  async function api(method, path, body) {
    const response = await fetch(new URL('/api/default/' + path, base), {
      method, redirect: 'error', headers: { Authorization: auth, 'Content-Type': 'application/json' },
      body: body && JSON.stringify(body),
    });
    assert(response.ok, `${method} ${path.split('?')[0]} returned ${response.status}`);
    return response.json();
  }
  const policy = await api('POST', 'rbac/bootstrap');
  await api('POST', 'users', { ...viewer, first_name: 'Browser', last_name: 'Viewer', role: 'admin', is_external: false });
  const dashboard = await api('POST', 'dashboards?folder=default', { version: 8, title, description: '', tabs: [{ tabId: 'main', name: 'Main', panels: [] }] });
  const dashboardId = dashboard.v8.dashboardId;
  const subjects = await api('GET', 'rbac/subjects');
  const subject = subjects.find(item => item.email === viewer.email).subject;
  await api('PUT', 'rbac/policy', { expected_version: policy.version, grants: [...policy.grants, { subject, role: 'viewer', resources: [{ kind: 'dashboard', name: dashboardId, stream_type: '' }] }] });
  console.log("Browser fixture grants configured");
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  try {
    for (const [user, role] of [[root, 'Admin'], [viewer, 'Viewer']]) {
      const context = await browser.newContext({ serviceWorkers: 'block' });
      await context.route(/^https?:/, route => new URL(route.request().url()).origin === base.origin ? route.continue() : route.abort());
      context.setDefaultTimeout(20000);
      const page = await context.newPage();
      const pageErrors = [];
      page.on('pageerror', error => pageErrors.push(error.message.slice(0, 180)));
      page.on('response', response => {
        if (response.status() >= 400) console.error('HTTP', response.status(), new URL(response.url()).pathname);
      });
      const field = name => page.locator(`[data-test="${name}"]`);
      await page.goto(new URL('/web/login?org_identifier=default', base).href);
      const internal = field('login-as-internal-user');
      if (await internal.isVisible()) await internal.click();
      await field('login-user-id-field').fill(user.email);
      await field('login-password-field').fill(user.password);
      const login = page.waitForResponse(response => new URL(response.url()).pathname === '/auth/login');
      await field('login-sign-in').click();
      assert.equal((await login).status(), 200);
      await page.waitForURL(url => !url.pathname.includes('login'));
      await page.goto(new URL('/web/iam/users?org_identifier=default', base).href);
      await expect(field('iam-rbac-roles')).toContainText(role, { timeout: 20000 });
      if (role === 'Admin') {
        await expect(field('iam-rbac-member')).toBeVisible();
        await expect(field('add-basic-user')).toBeVisible();
      } else {
        await expect(field('iam-rbac-member')).toHaveCount(0);
        await expect(field('add-basic-user')).toHaveCount(0);
      }
      // Controls follow upstream until the permission read answers, so wait for it before asserting.
      const permissions = page.waitForResponse(response => new URL(response.url()).pathname === '/api/default/rbac/me' && response.status() === 200, { timeout: 20000 });
      await page.goto(new URL(`/web/dashboards/view?org_identifier=default&folder=default&dashboard=${encodeURIComponent(dashboardId)}&period=30m`, base).href);
      await expect(field('dashboard-name-title')).toHaveText(title, { timeout: 20000 });
      await permissions;
      if (role === 'Admin') await expect(field('dashboard-edit-btn')).toBeVisible();
      else await expect(field('dashboard-edit-btn')).toHaveCount(0);
      assert.deepEqual(pageErrors, [], `${role} browser execution failed: ${pageErrors.join(", ")}`);
      console.log(`PASS ${role} login, IAM permissions and dashboard editing controls`);
      await context.close();
    }
  } finally { await browser.close(); }
}
run().catch(error => { console.error(error.message); process.exitCode = 1; });
