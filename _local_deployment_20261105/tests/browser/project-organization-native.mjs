import fs from 'node:fs';
import path from 'node:path';
import {chromium} from 'playwright';

const [origin, fixturePath, output] = process.argv.slice(2);
const endpoint = new URL(origin);
if (endpoint.protocol !== 'http:' || endpoint.hostname !== '127.0.0.1' || Number(endpoint.port) < 1024) {
  throw new Error('Only a disposable loopback application is allowed.');
}
const f = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const t = f.teams;
const report = {scope: 'Disposable organization fixture and synthetic sessions only.', checks: []};
const browser = await chromium.launch({headless: true});
const contexts = new Map();
const check = (name, ok) => { report.checks.push({name, passed: Boolean(ok)}); if (!ok) throw new Error(name); };
async function account(role) {
  const ctx = await browser.newContext({viewport: {width: 1440, height: 1000}});
  contexts.set(role, ctx);
  await ctx.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
  await ctx.addCookies([{name: 'phusr', value: f[role].username, url: origin},
    {name: 'phsid', value: f[role].session, url: origin, httpOnly: true}]);
  const page = await ctx.newPage(); page.setDefaultTimeout(20000); return page;
}
async function visit(page, route) {
  const response = await page.goto(origin + route, {waitUntil: 'networkidle'});
  check('HTTP renders ' + route, response?.status() === 200);
  check('no runtime failure on ' + route, !/Unhandled Exception|Call to undefined method|Fatal error|Stack Trace/.test(await page.locator('body').innerText()));
}
const teamURI = team => `/organization/view/${team.id}/`;
const formWith = (page, selector) => page.locator('form').filter({has: page.locator(selector)});
const field = (page, label) => page.locator('.aphront-form-control').filter({has: page.locator('label').filter({hasText: label})});
async function addToken(page, control, text, phid) {
  await control.locator('input.jx-tokenizer-input').pressSequentially(text, {delay: 12});
  await page.locator(`a.jx-result[rel="${phid}"]:visible`).click();
  check('native tokenizer selects ' + text, await control.locator(`input[value="${phid}"]`).count() === 1);
}
async function removeToken(page, phid) {
  await page.locator('.jx-tokenizer-token').filter({has: page.locator(`input[value="${phid}"]`)}).locator('.jx-tokenizer-x').click();
}
async function submit(page, form) {
  await Promise.all([page.waitForNavigation({waitUntil: 'networkidle'}), form.locator('button[type="submit"]').last().click()]);
}
async function choosePolicy(page, inputName, label) {
  const control = page.locator('.aphront-form-control-policy').filter({has: page.locator(`input[name="${inputName}"]`)});
  await control.locator('a.policy-control').click();
  await page.locator('a.phabricator-action-view-item').filter({hasText: new RegExp('^' + label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$')}).click();
}
async function csrf(page) {
  return page.evaluate(() => new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('CSRF refresh timed out.')), 15000);
    new JX.Request('/login/refresh/', data => { clearTimeout(timeout); resolve(data.token); }).send();
  }));
}
async function projectAccess(page, allowed, label) {
  const response = await page.goto(origin + `/project/profile/${f.project.id}/`, {waitUntil: 'networkidle'});
  const body = await page.locator('body').innerText();
  check(label, allowed ? response.status() === 200 && body.includes(f.project.name)
    : !body.includes(f.project.name) && ([403, 404].includes(response.status()) || /Access Denied|You Shall Not Pass/.test(body)));
}
async function saveTeamPolicyDialog(page, ruleClass) {
  const dialog = page.locator('.aphront-dialog-view');
  await dialog.locator('select[data-sigil~="rule-select"]').selectOption(ruleClass);
  check('native policy dialog offers both team scopes',
    (await dialog.locator('select[data-sigil~="rule-select"]').innerText()).includes('所选团队本级成员') &&
    (await dialog.locator('select[data-sigil~="rule-select"]').innerText()).includes('所选团队及下级成员'));
  if (!await dialog.locator(`input[value="${t.policyParent.phid}"]`).count()) {
    await addToken(page, dialog, t.policyParent.name, t.policyParent.phid);
  }
  check('policy editor retains the selected team when changing scope',
    await dialog.locator(`input[value="${t.policyParent.phid}"]`).count() === 1);
  await dialog.getByRole('button', {name: 'Save Policy', exact: true}).click();
  await dialog.waitFor({state: 'hidden'});
}
async function customProjectPolicy(page, ruleClass) {
  await visit(page, `/project/edit/${f.project.id}/`);
  const current = await page.locator('input[name="policy.view"]').inputValue();
  if (current.startsWith('PHID-PLCY-')) {
    const control = page.locator('.aphront-form-control-policy').filter({has: page.locator('input[name="policy.view"]')});
    await control.locator('a.policy-control').click();
    await page.locator('a.phabricator-action-view-item').filter({hasText: /^(?:团队成员（|Custom Policy$)/}).click();
  } else {
    await choosePolicy(page, 'policy.view', 'Custom Policy...');
  }
  await saveTeamPolicyDialog(page, ruleClass);
  check('native custom policy saves a policy object', (await page.locator('input[name="policy.view"]').inputValue()).startsWith('PHID-PLCY-'));
  await submit(page, formWith(page, 'input[name="name"]'));
}
async function boundary(page, scope, selected = true) {
  await visit(page, `/project/edit/${f.project.id}/`);
  const control = field(page, '团队额外限制（影响查看、编辑、加入）');
  const present = await control.locator(`input[value="${t.policyParent.phid}"]`).count();
  if (selected && !present) await addToken(page, control, t.policyParent.name, t.policyParent.phid);
  if (!selected && present) await removeToken(page, t.policyParent.phid);
  await page.locator('select[name="organizationScope"]').selectOption(scope);
  await submit(page, formWith(page, 'input[name="name"]'));
}

try {
  const admin = await account('admin');
  const outsider = await account('outsider');
  const child = await account('child');
  const parent = await account('parent');
  await visit(admin, '/organization/');
  check('administrator has a clear team creation entry', await admin.getByRole('button', {name: '新建团队', exact: true}).isVisible());
  await visit(outsider, '/organization/');
  let html = await outsider.content();
  check('independent privacy hides parent and child names and PHIDs in the tree',
    [t.hiddenParent.name, t.hiddenParent.phid, t.hiddenChild.name, t.hiddenChild.phid, t.privateLocal.name]
      .every(value => !html.includes(value)));
  check('a visible child of a hidden parent remains discoverable with its own visible children',
    await outsider.locator(`li[data-team-id="${t.visibleChild.id}"] a`).first().innerText() === t.visibleChild.name &&
    await outsider.locator(`li[data-team-id="${t.visibleChild.id}"] li[data-team-id="${t.grandchild.id}"]`).count() === 1);
  check('ordinary users have no team creation action', await outsider.getByRole('button', {name: '新建团队', exact: true}).count() === 0);
  await outsider.screenshot({path: path.join(output, 'visible-team-tree.png'), fullPage: true});
  await visit(outsider, teamURI(t.visibleChild));
  check('hidden parent produces a list back button without a hidden breadcrumb',
    await outsider.getByRole('button', {name: '返回团队列表', exact: true}).isVisible() &&
    !(await outsider.content()).includes(t.hiddenParent.name) && !(await outsider.content()).includes(t.hiddenParent.phid));
  await visit(outsider, teamURI(t.grandchild));
  check('visible child navigation can return one level',
    await outsider.getByRole('button', {name: '返回上级团队', exact: true}).getAttribute('href') === teamURI(t.visibleChild));
  await outsider.getByRole('button', {name: '返回上级团队', exact: true}).click();
  await outsider.waitForLoadState('networkidle');
  check('back navigation reaches the visible parent', new URL(outsider.url()).pathname === teamURI(t.visibleChild));
  await visit(admin, teamURI(t.rosterPrivate));
  check('administrator can inspect member identities and management history',
    (await admin.locator('body').innerText()).includes(f.child.username) &&
    (await admin.locator('body').innerText()).includes('最近管理记录'));
  await visit(outsider, teamURI(t.rosterPrivate));
  html = await outsider.content();
  check('team visibility does not expose the protected roster or audit after administrator rendering',
    html.includes('成员名单未对当前账户开放') && !html.includes(f.child.username) &&
    !html.includes(f.child.phid) && !html.includes('最近管理记录'));
  await outsider.screenshot({path: path.join(output, 'private-roster.png'), fullPage: true});
  const hidden = await outsider.goto(origin + teamURI(t.hiddenChild), {waitUntil: 'networkidle'});
  check('hidden team direct URL discloses no team title',
    [403, 404].includes(hidden.status()) && !(await outsider.content()).includes(t.hiddenChild.name));
  await visit(outsider, '/organization/?q=' + encodeURIComponent(t.grandchild.name));
  check('search finds visible descendants without needing their parent in the result set',
    (await outsider.locator('body').innerText()).includes(t.grandchild.name) &&
    !(await outsider.content()).includes(t.hiddenParent.name));
  const datasource = await outsider.request.get(origin + '/typeahead/class/TeamOrganizationDatasource/?q=' +
    encodeURIComponent(t.visibleChild.name.split(' ').at(-1)) + '&__ajax__=true');
  const data = await datasource.text();
  check('team typeahead also filters hidden names and PHIDs', data.includes(t.visibleChild.name) &&
    !data.includes(t.hiddenParent.name) && !data.includes(t.hiddenParent.phid) && !data.includes(t.hiddenChild.name));

  await visit(admin, `/p/${f.child.username}/`);
  check('administrator sees the user team attribute and allocation entry',
    (await admin.locator('.team-organization-user-teams').innerText()).includes(t.hiddenChild.name) &&
    await admin.getByRole('link', {name: '分配团队', exact: true}).isVisible());
  await visit(outsider, `/p/${f.child.username}/`);
  const shown = await outsider.locator('.team-organization-user-teams').innerText();
  check('other viewers see only teams whose team and roster policies both permit it',
    shown.includes(t.policyChild.name) && !shown.includes(t.rosterPrivate.name) &&
    !shown.includes(t.visibleChild.name) && !shown.includes(t.hiddenChild.name) && !shown.includes(t.privateLocal.name));
  await visit(outsider, `/p/${f.secret.username}/`);
  check('hidden-only membership is represented as unavailable information, not no membership',
    await outsider.locator('.team-organization-user-teams').innerText() === '暂无可显示团队' &&
    !(await outsider.content()).includes(t.hiddenChild.name));
  await visit(child, `/p/${f.child.username}/`);
  const selfTeams = await child.locator('.team-organization-user-teams').innerText();
  check('users see their own visible memberships without gaining visibility of hidden teams',
    selfTeams.includes(t.rosterPrivate.name) && selfTeams.includes(t.privateLocal.name) && !selfTeams.includes(t.hiddenChild.name));
  check('a user cannot assign their own authorization teams', await child.getByRole('link', {name: '分配团队', exact: true}).count() === 0);
  await child.screenshot({path: path.join(output, 'user-team-attribute.png'), fullPage: true});
  const manageDenied = await child.request.get(origin + `/organization/user/${f.child.phid}/`);
  check('team allocation endpoint is independently administrator-only', manageDenied.status() === 403);

  // An empty native tokenizer submits no parentPHIDs field. Exercise this
  // through real forms: service fixtures using an explicit null missed it.
  await visit(admin, '/organization/edit/');
  await admin.locator('input[name="name"]').fill(f.rootTeam);
  await admin.locator('textarea[name="description"]').fill('Browser-created root team.');
  check('new root team starts with independent member-only default policies',
    await admin.locator('input[name="viewPolicy"]').inputValue() === 'obj.team.organization.members' &&
    await admin.locator('input[name="membersPolicy"]').inputValue() === 'obj.team.organization.members' &&
    await field(admin, '上级团队').locator('input[type="hidden"]').count() === 0);
  await submit(admin, formWith(admin, 'input[name="name"]'));
  const rootMatch = new URL(admin.url()).pathname.match(/^\/organization\/view\/(\d+)\/$/);
  check('creating a team without selecting a parent opens its detail page', Boolean(rootMatch) &&
    (await admin.locator('body').innerText()).includes(f.rootTeam));
  const rootID = Number(rootMatch[1]);
  check('new root team can return directly to the team list',
    await admin.getByRole('button', {name: '返回团队列表', exact: true}).isVisible());
  await visit(admin, `/organization/edit/${rootID}/`);
  check('root edit retains empty parent and default privacy policies',
    await field(admin, '上级团队').locator('input[type="hidden"]').count() === 0 &&
    await admin.locator('input[name="viewPolicy"]').inputValue() === 'obj.team.organization.members' &&
    await admin.locator('input[name="membersPolicy"]').inputValue() === 'obj.team.organization.members');
  await admin.locator('textarea[name="description"]').fill('Root edit without choosing a parent.');
  await submit(admin, formWith(admin, 'input[name="name"]'));
  check('saving an existing root team preserves its root navigation',
    new URL(admin.url()).pathname === `/organization/view/${rootID}/` &&
    await admin.getByRole('button', {name: '返回团队列表', exact: true}).isVisible() &&
    (await admin.locator('body').innerText()).includes('Root edit without choosing a parent.'));
  await visit(admin, `/organization/members/${rootID}/`);
  await addToken(admin, field(admin, '本级成员'), f.child.username, f.child.phid);
  await submit(admin, formWith(admin, 'input[name="expectedVersion"]'));
  await visit(admin, `/organization/edit/${rootID}/`);
  await addToken(admin, field(admin, '上级团队'), t.policyParent.name, t.policyParent.phid);
  await choosePolicy(admin, 'viewPolicy', 'All Users');
  await choosePolicy(admin, 'membersPolicy', 'Administrators');
  await submit(admin, formWith(admin, 'input[name="name"]'));
  check('root team can be assigned an existing parent',
    await admin.getByRole('button', {name: '返回上级团队', exact: true}).getAttribute('href') === teamURI(t.policyParent));
  await visit(admin, `/organization/edit/${rootID}/`);
  await removeToken(admin, t.policyParent.phid);
  await submit(admin, formWith(admin, 'input[name="name"]'));
  check('removing the last parent saves the child as a root team',
    new URL(admin.url()).pathname === `/organization/view/${rootID}/` &&
    await admin.getByRole('button', {name: '返回团队列表', exact: true}).isVisible());
  check('clearing a parent preserves the existing team member',
    (await admin.locator('body').innerText()).includes(f.child.username));
  await visit(admin, `/organization/edit/${rootID}/`);
  check('clearing a parent preserves both independent privacy settings',
    await field(admin, '上级团队').locator('input[type="hidden"]').count() === 0 &&
    await admin.locator('input[name="viewPolicy"]').inputValue() === 'users' &&
    await admin.locator('input[name="membersPolicy"]').inputValue() === 'admin');
  await visit(outsider, `/organization/view/${rootID}/`);
  check('detached root remains visible while its roster stays private',
    (await outsider.locator('body').innerText()).includes(f.rootTeam) &&
    !(await outsider.locator('body').innerText()).includes(f.child.username));
  const invalidParent = await admin.request.post(origin + '/organization/edit/', {form: {
    __csrf__: await csrf(admin), name: f.invalidParentTeam, description: '',
    'parentPHIDs[0]': 'not-a-team-phid', viewPolicy: 'users', membersPolicy: 'admin', expectedVersion: '0'}});
  check('nonempty malformed parent PHID remains rejected by the create form',
    invalidParent.status() === 200 && (await invalidParent.text()).includes('包含无效的对象标识。'));
  await visit(admin, '/organization/');
  check('rejected invalid-parent creation does not add a team to the directory',
    !(await admin.locator('body').innerText()).includes(f.invalidParentTeam));

  await visit(admin, '/organization/edit/');
  check('team creation exposes separate visibility and roster policies',
    await admin.locator('input[name="viewPolicy"]').count() === 1 && await admin.locator('input[name="membersPolicy"]').count() === 1);
  await admin.locator('input[name="name"]').fill(f.createdTeam);
  await admin.locator('textarea[name="description"]').fill('Browser-created organization team.');
  await addToken(admin, field(admin, '上级团队'), t.policyParent.name, t.policyParent.phid);
  await choosePolicy(admin, 'viewPolicy', 'All Users');
  await choosePolicy(admin, 'membersPolicy', 'Custom Policy...');
  await saveTeamPolicyDialog(admin, 'TeamOrganizationDirectPolicyRule');
  check('independent roster capability supports the native custom policy workflow',
    (await admin.locator('input[name="membersPolicy"]').inputValue()).startsWith('PHID-PLCY-'));
  await choosePolicy(admin, 'membersPolicy', 'Administrators');
  await submit(admin, formWith(admin, 'input[name="name"]'));
  const createdID = Number(new URL(admin.url()).pathname.split('/')[3]);
  check('actual create form opens a new team detail', Number.isInteger(createdID) && createdID > 0 &&
    (await admin.locator('body').innerText()).includes(f.createdTeam));
  const createdURI = `/organization/view/${createdID}/`;
  await visit(admin, `/organization/edit/${createdID}/`);
  const staleVersion = await admin.locator('input[name="expectedVersion"]').inputValue();
  await admin.locator('input[name="name"]').fill(f.renamedTeam);
  await removeToken(admin, t.policyParent.phid);
  await addToken(admin, field(admin, '上级团队'), t.visibleChild.name, t.visibleChild.phid);
  await submit(admin, formWith(admin, 'input[name="name"]'));
  check('renaming and moving a team keeps navigation consistent',
    (await admin.locator('body').innerText()).includes(f.renamedTeam) &&
    await admin.getByRole('button', {name: '返回上级团队', exact: true}).getAttribute('href') === teamURI(t.visibleChild));
  const stale = await admin.request.post(origin + `/organization/edit/${createdID}/`, {form: {
    __csrf__: await csrf(admin), name: 'Stale overwrite must fail', description: '',
    viewPolicy: 'users', membersPolicy: 'admin', expectedVersion: staleVersion}});
  check('stale edit form is rejected without overwriting the newer team',
    (await stale.text()).includes('团队已被其他操作更新，请刷新后重试。') && stale.status() === 200);
  await visit(admin, `/organization/user/${f.child.phid}/`);
  // The newly created team is resolved through the actual native typeahead.
  const createdResult = await admin.request.get(origin + '/typeahead/class/TeamOrganizationDatasource/?q=' + encodeURIComponent(f.renamedTeam) + '&__ajax__=true');
  const createdPHID = (await createdResult.text()).match(/PHID-ORGT-[a-z0-9]+/)?.[0];
  check('created team is selectable for user allocation', Boolean(createdPHID));
  await addToken(admin, field(admin, '所属团队'), f.renamedTeam, createdPHID);
  await submit(admin, formWith(admin, 'input[name^="expectedTeams["]'));
  check('user allocation updates the native user profile',
    (await admin.locator('.team-organization-user-teams').innerText()).includes(f.renamedTeam));
  await visit(admin, createdURI);
  check('user allocation is reflected in the team member roster', (await admin.locator('body').innerText()).includes(f.child.username));
  await admin.screenshot({path: path.join(output, 'admin-team-detail.png'), fullPage: true});
  await visit(outsider, createdURI);
  const token = await csrf(outsider);
  for (const route of [`/organization/edit/${createdID}/`, `/organization/members/${createdID}/`, `/organization/user/${f.outsider.phid}/`]) {
    const rejected = await outsider.request.post(origin + route, {form: {__csrf__: token, name: 'Unauthorized', members: f.outsider.phid}});
    check('ordinary user cannot directly POST administrator route ' + route, rejected.status() === 403);
  }
  const noCSRF = await admin.request.post(origin + `/organization/members/${createdID}/`, {form: {expectedVersion: '1'}});
  check('administrator mutation without CSRF is rejected', noCSRF.status() === 400);

  await customProjectPolicy(admin, 'TeamOrganizationDirectPolicyRule');
  await projectAccess(parent, true, 'direct team policy admits direct members');
  await projectAccess(child, false, 'direct team policy does not silently include children');
  await projectAccess(outsider, true, 'custom policy alone preserves native project-member access');
  await customProjectPolicy(admin, 'TeamOrganizationDescendantsPolicyRule');
  await projectAccess(child, true, 'descendant team policy admits nested team members');
  await boundary(admin, 'direct');
  await projectAccess(parent, true, 'strict direct boundary retains matching members');
  await projectAccess(child, false, 'strict direct boundary excludes nested-only members');
  await projectAccess(outsider, false, 'strict boundary also excludes existing outside project members');
  await boundary(admin, 'descendants');
  await projectAccess(child, true, 'descendant boundary admits nested members');
  await boundary(admin, 'descendants', false);
  await projectAccess(outsider, true, 'clearing the optional boundary restores native member access');
  await boundary(admin, 'descendants');
  await admin.screenshot({path: path.join(output, 'project-team-boundary.png'), fullPage: true});
  await visit(parent, `/policy/explain/${f.explainChild.phid}/view/`);
  const explanation = await parent.locator('body').innerText();
  check('native policy explanation names the boundary without exposing an internal guard ID',
    explanation.includes('团队访问边界') && !explanation.includes('Unknown Object') &&
    !/PHID-ORGB-/.test(await parent.content()));
  const parentLink = parent.getByRole('link', {name: f.explainParent.name, exact: true});
  check('native policy explanation retains the original parent project link',
    await parentLink.count() === 1 && /^\/(tag|project)\//.test(await parentLink.getAttribute('href')));
  await parent.screenshot({path: path.join(output, 'project-policy-explanation.png'), fullPage: true});
  await parentLink.click();
  await parent.waitForLoadState('networkidle');
  check('the parent project link still opens the real parent',
    (await parent.locator('body').innerText()).includes(f.explainParent.name));

  await visit(admin, `/organization/edit/${createdID}/`);
  await admin.locator('input[name="isArchived"]').check();
  await submit(admin, formWith(admin, 'input[name="name"]'));
  await visit(admin, `/organization/members/${createdID}/`);
  check('archived team permits member removal with a clear explanation', (await admin.locator('body').innerText()).includes('归档团队只能保留或移除'));
  await removeToken(admin, f.child.phid);
  await submit(admin, formWith(admin, 'input[name="expectedVersion"]'));
  check('team member editing updates the roster', (await admin.locator('body').innerText()).includes('暂无成员'));
  await visit(admin, `/p/${f.child.username}/`);
  check('membership removal is also reflected in the user attribute', !(await admin.locator('.team-organization-user-teams').innerText()).includes(f.renamedTeam));
  await visit(outsider, '/organization/');
  check('archived teams are excluded from the active directory', !(await outsider.locator('body').innerText()).includes(f.renamedTeam));
  await visit(outsider, '/organization/?archived=1');
  check('archived visible teams remain explicitly discoverable', (await outsider.locator('body').innerText()).includes(f.renamedTeam));
  await outsider.setViewportSize({width: 390, height: 844});
  await visit(outsider, '/organization/');
  check('mobile tree remains within the viewport', await outsider.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  await outsider.screenshot({path: path.join(output, 'mobile-team-tree.png'), fullPage: true});
  await admin.setViewportSize({width: 390, height: 844});
  await visit(admin, `/organization/edit/${createdID}/`);
  check('mobile editing preserves policy labels and submit button',
    await admin.getByRole('button', {name: '保存团队', exact: true}).isVisible() &&
    await admin.locator('a.policy-control').count() === 2 &&
    await admin.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  await admin.screenshot({path: path.join(output, 'mobile-team-edit.png'), fullPage: true});
  report.passed = true;
} catch (error) {
  report.passed = false; report.error = error.message;
  for (const [role, ctx] of contexts) {
    await ctx.pages().at(-1)?.screenshot({path: path.join(output, `failure-${role}.png`), fullPage: true}).catch(() => {});
  }
} finally {
  for (const ctx of contexts.values()) await ctx.close();
  await browser.close();
  fs.writeFileSync(path.join(output, 'browser-report.json'), JSON.stringify(report, null, 2) + '\n', {mode: 0o600});
}
console.log(JSON.stringify({passed: report.passed, checks: report.checks.length, error: report.error}));
if (!report.passed) process.exitCode = 1;
