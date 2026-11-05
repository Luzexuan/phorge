import fs from 'node:fs';
import path from 'node:path';
import {chromium} from 'playwright';

const [origin, fixturePath, output] = process.argv.slice(2);
const endpoint = new URL(origin);
if (endpoint.protocol !== 'http:' || endpoint.hostname !== '127.0.0.1' || Number(endpoint.port) < 1024) {
  throw new Error('Only a disposable loopback application is allowed.');
}
const f = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const report = {scope: 'Disposable project permission fixtures and synthetic sessions only.', checks: []};
const browser = await chromium.launch({headless: true});
const contexts = [];
const check = (name, ok) => { report.checks.push({name, passed: Boolean(ok)}); if (!ok) throw new Error(name); };
const uri = (key = 'main', capability = 'view') => `/organization/project/${f.projects[key].id}/permissions/?capability=${capability}`;
async function account(role) {
  const ctx = await browser.newContext({viewport: {width: 1440, height: 1000}}); contexts.push(ctx);
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
const editForm = page => page.locator('#team-project-access-form');
const capabilityForm = page => page.locator('#team-project-access-selector');
const field = (page, label) => page.locator('.aphront-form-control').filter({has: page.locator('label').filter({hasText: label})});
const boundaryField = page => page.locator('#team-project-access-boundary-teams');
async function addToken(page, control, text, phid) {
  await control.locator('input.jx-tokenizer-input').pressSequentially(text, {delay: 10});
  await page.locator(`a.jx-result[rel="${phid}"]:visible`).click();
  check('tokenizer selects ' + text, await control.locator(`input[value="${phid}"]`).count() === 1);
}
async function submit(page, form = editForm(page)) {
  await Promise.all([page.waitForNavigation({waitUntil: 'networkidle'}), form.locator('button[type="submit"]').last().click()]);
}
async function change(page, {project = 'main', capability = 'view', mode = 'add', users = [], teams = [], descendants = [], boundaryMode = 'keep', boundaryTeams = []} = {}) {
  await visit(page, uri(project, capability));
  await editForm(page).locator('select[name="mode"]').selectOption(mode);
  if (['add', 'replace', 'revoke'].includes(mode)) {
    await editForm(page).locator('select[name="teamScope"]').selectOption(
      teams.length && descendants.length ? 'mixed' : teams.length ? 'direct' : descendants.length ? 'descendants' : 'none');
  }
  for (const role of users) await addToken(page, field(page, /^指定人员$/), f[role].username, f[role].phid);
  for (const key of teams) await addToken(page, field(page, /^团队（仅本级）$/), f.teams[key].name, f.teams[key].phid);
  for (const key of descendants) await addToken(page, field(page, /^团队（包含下级）$/), f.teams[key].name, f.teams[key].phid);
  await editForm(page).locator('select[name="boundaryMode"]').selectOption(boundaryMode);
  for (const key of boundaryTeams) await addToken(page, boundaryField(page), f.teams[key].name, f.teams[key].phid);
  await submit(page);
  check('permission mutation succeeds ' + project + '/' + capability + '/' + mode,
    new URL(page.url()).searchParams.get('saved') === '1' && (await page.locator('body').innerText()).includes('授权调整已保存'));
}
async function rejectChange(page, project, values, label) {
  await visit(page, uri(project));
  const state = await editForm(page).locator('input[name="expectedState"]').inputValue();
  const response = await page.request.post(origin + uri(project), {form: {
    __csrf__: await csrf(page), capability: 'view', mode: 'add', teamScope: 'none',
    boundaryMode: 'keep', expectedState: state, ...values,
  }});
  check(label + ' is rejected', [200, 400].includes(response.status()) &&
    new URL(response.url()).searchParams.get('saved') !== '1');
  await visit(page, uri(project));
  check(label + ' preserves all permission state',
    await editForm(page).locator('input[name="expectedState"]').inputValue() === state);
}
async function submittedSubjectNames(page) {
  return editForm(page).evaluate(form => [...new FormData(form).keys()].filter(
    name => /^(?:users|teams|descendantTeams|boundaryTeams)(?:\[|$)/.test(name)));
}
async function access(page, project, allowed, label) {
  const response = await page.goto(origin + `/project/profile/${f.projects[project].id}/`, {waitUntil: 'networkidle'});
  const body = await page.locator('body').innerText();
  check(label, allowed ? response.status() === 200 && body.includes(f.projects[project].name)
    : !body.includes(f.projects[project].name) && ([403, 404].includes(response.status()) || /Access Denied|You Shall Not Pass/.test(body)));
}
async function csrf(page) {
  return page.evaluate(() => new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('CSRF refresh timed out.')), 15000);
    new JX.Request('/login/refresh/', data => { clearTimeout(timeout); resolve(data.token); }).send();
  }));
}
async function removeUserRule(page, project, role) {
  await visit(page, uri(project));
  const row = page.locator('.team-project-access-rule[data-access-rule-action="allow"]').filter({hasText: f[role].username});
  check('selected explicit user rule is unambiguous', await row.count() === 1);
  await submit(page, row.locator('form'));
  check('individual allow rule removed through its own POST form', new URL(page.url()).searchParams.get('saved') === '1');
}

try {
  const manager = await account('manager'); const parent = await account('parent');
  const child = await account('child'); const outsider = await account('outsider');
  const member = await account('member'); const blocked = await account('blocked');
  const admin = await account('admin');
  await visit(manager, `/project/profile/${f.projects.main.id}/`);
  check('project overview exposes the permission management entry', await manager.getByRole('link', {name: '增添、替换或回收授权', exact: true}).isVisible());
  await manager.screenshot({path: path.join(output, 'project-access-entry.png'), fullPage: true});
  await manager.getByRole('link', {name: '增添、替换或回收授权', exact: true}).click();
  await manager.waitForURL(url => url.pathname === new URL(origin + uri()).pathname);
  await manager.locator('#team-project-access-form[data-access-ready="1"]').waitFor({state: 'visible'});
  check('clicking the project entry initializes permission dropdowns after navigation',
    new URL(manager.url()).pathname === new URL(origin + uri()).pathname &&
    await manager.locator('#team-project-access-form[data-access-ready="1"]').isVisible());
  await visit(manager, `/project/manage/${f.projects.main.id}/`);
  check('project history also exposes the same management entry', await manager.getByRole('link', {name: '增添、替换或回收授权', exact: true}).isVisible());
  await visit(manager, `/project/edit/${f.projects.main.id}/`);
  check('native editor exposes the additive authorization entry', await manager.getByRole('link', {name: '打开项目权限管理', exact: true}).isVisible());
  check('native editor distinguishes the strict boundary from grants', (await manager.locator('body').innerText()).includes('额外限制'));
  await manager.screenshot({path: path.join(output, 'native-edit-access-entry.png'), fullPage: true});
  await visit(member, `/project/profile/${f.projects.main.id}/`);
  check('read-only member has no management action', await member.getByRole('link', {name: '增添、替换或回收授权', exact: true}).count() === 0);
  const readonly = await member.request.get(origin + uri());
  check('direct management GET rejects a read-only project member', readonly.status() === 403);
  const readonlyPost = await member.request.post(origin + uri(), {form: {__csrf__: await csrf(member), capability: 'view', mode: 'add', 'users[0]': f.blocked.phid, expectedState: 'untrusted'}});
  check('direct management POST independently rejects read-only member', readonlyPost.status() === 403);

  await visit(manager, uri());
  check('additive grant is the default operation', await editForm(manager).locator('select[name="mode"]').inputValue() === 'add');
  check('permission selection uses one explicit dropdown and a usable submit action',
    await capabilityForm(manager).locator('select[name="capability"]').count() === 1 &&
    await capabilityForm(manager).getByRole('button', {name: '打开权限项', exact: true}).isVisible());
  check('operation dropdown covers retention, scoped changes and explicit global replacement',
    JSON.stringify(await editForm(manager).locator('select[name="mode"] option').evaluateAll(nodes => nodes.map(node => node.value).sort())) ===
    JSON.stringify(['add', 'administrators', 'all-users', 'automatic', 'keep', 'replace', 'revoke'].sort()));
  check('team scopes preserve both simple and mixed team combinations',
    JSON.stringify(await editForm(manager).locator('select[name="teamScope"] option').evaluateAll(nodes => nodes.map(node => node.value).sort())) ===
    JSON.stringify(['none', 'direct', 'descendants', 'mixed'].sort()));
  check('project-wide extra restriction has explicit keep, clear and both team scopes',
    JSON.stringify(await editForm(manager).locator('select[name="boundaryMode"] option').evaluateAll(nodes => nodes.map(node => node.value).sort())) ===
    JSON.stringify(['keep', 'none', 'direct', 'descendants'].sort()));
  const selectionState = await editForm(manager).locator('input[name="expectedState"]').inputValue();
  await Promise.all([manager.waitForNavigation({waitUntil: 'networkidle'}),
    capabilityForm(manager).locator('select[name="capability"]').selectOption('join')]);
  check('capability dropdown navigates to the selected permission without mutating grants',
    new URL(manager.url()).searchParams.get('capability') === 'join' &&
    await editForm(manager).locator('input[name="capability"]').inputValue() === 'join' &&
    await editForm(manager).locator('input[name="expectedState"]').inputValue() === selectionState);
  await Promise.all([manager.waitForNavigation({waitUntil: 'networkidle'}),
    capabilityForm(manager).locator('select[name="capability"]').selectOption('view')]);
  await editForm(manager).locator('select[name="mode"]').selectOption('keep');
  const [dismissedDialog] = await Promise.all([
    manager.waitForEvent('dialog').then(async dialog => {
      const type = dialog.type(); await dialog.dismiss(); return type;
    }),
    capabilityForm(manager).locator('select[name="capability"]').selectOption('join'),
  ]);
  check('cancelling permission navigation preserves the current selection and unsaved changes',
    dismissedDialog === 'confirm' && new URL(manager.url()).searchParams.get('capability') === 'view' &&
    await capabilityForm(manager).locator('select[name="capability"]').inputValue() === 'view' &&
    await editForm(manager).locator('input[name="capability"]').inputValue() === 'view' &&
    await editForm(manager).locator('select[name="mode"]').inputValue() === 'keep');
  const [acceptedDialog] = await Promise.all([
    manager.waitForEvent('dialog').then(async dialog => {
      const type = dialog.type(); await dialog.accept(); return type;
    }),
    manager.waitForNavigation({waitUntil: 'networkidle'}),
    capabilityForm(manager).locator('select[name="capability"]').selectOption('join'),
  ]);
  check('accepting permission navigation discards only the unsaved form and opens the requested capability',
    acceptedDialog === 'confirm' && new URL(manager.url()).searchParams.get('capability') === 'join' &&
    await editForm(manager).locator('input[name="capability"]').inputValue() === 'join' &&
    await editForm(manager).locator('input[name="expectedState"]').inputValue() === selectionState);
  await Promise.all([manager.waitForNavigation({waitUntil: 'networkidle'}),
    capabilityForm(manager).locator('select[name="capability"]').selectOption('view')]);
  check('default union and remaining automatic sources are explained', (await manager.locator('body').innerText()).includes('项目成员仍自动可见') &&
    (await manager.locator('body').innerText()).includes('回收一个来源后，其他来源可能继续授权'));
  check('boundary is explicitly preserved by default and the old ambiguous checkbox is absent',
    await editForm(manager).locator('select[name="boundaryMode"]').inputValue() === 'keep' &&
    await manager.locator('input[name="clearBoundary"]').count() === 0);
  check('default team scope shows no unused team pickers',
    await editForm(manager).locator('select[name="teamScope"]').inputValue() === 'none' &&
    !await field(manager, /^团队（仅本级）$/).isVisible() &&
    !await field(manager, /^团队（包含下级）$/).isVisible() && !await boundaryField(manager).isVisible());
  await editForm(manager).locator('select[name="teamScope"]').selectOption('direct');
  check('direct scope reveals only its own team picker', await field(manager, /^团队（仅本级）$/).isVisible() &&
    !await field(manager, /^团队（包含下级）$/).isVisible());
  await editForm(manager).locator('select[name="teamScope"]').selectOption('descendants');
  check('descendant scope reveals only its own team picker', !await field(manager, /^团队（仅本级）$/).isVisible() &&
    await field(manager, /^团队（包含下级）$/).isVisible());
  await editForm(manager).locator('select[name="teamScope"]').selectOption('mixed');
  check('mixed scope exposes both independently labelled team pickers', await field(manager, /^团队（仅本级）$/).isVisible() &&
    await field(manager, /^团队（包含下级）$/).isVisible());
  await editForm(manager).locator('select[name="teamScope"]').selectOption('none');
  const missingCSRF = await manager.request.post(origin + uri(), {form: {capability: 'view', mode: 'add', 'users[0]': f.outsider.phid}});
  check('management mutation requires CSRF', missingCSRF.status() === 400);
  const wrongMethod = await manager.request.delete(origin + uri());
  check('unsupported mutation method is rejected', wrongMethod.status() === 405);
  const initialState = await editForm(manager).locator('input[name="expectedState"]').inputValue();
  const badIndex = await manager.request.post(origin + uri(), {form: {__csrf__: await csrf(manager),
    capability: 'view', mode: 'remove-rule', ruleIndex: 'not-an-index', expectedState: initialState}});
  check('malformed rule index is rejected instead of coercing to the first allow rule',
    badIndex.status() === 200 && (await badIndex.text()).includes('请选择要回收的授权规则'));
  await visit(manager, uri());
  check('invalid rule index leaves all permission state unchanged',
    await editForm(manager).locator('input[name="expectedState"]').inputValue() === initialState);

  await change(manager, {users: ['parent', 'outsider'], teams: ['parent']});
  await access(parent, 'main', true, 'user and team grants admit a team participant');
  await access(outsider, 'main', true, 'individually invited participant from another team is included in the union');
  await access(child, 'main', false, 'direct team grant does not silently include descendants');
  await access(member, 'main', true, 'existing project member remains visible under additive grants');
  await change(manager, {mode: 'revoke', users: ['parent']});
  await access(parent, 'main', true, 'revoking personal grant retains access through the team grant');
  await change(manager, {mode: 'revoke', teams: ['parent']});
  await access(parent, 'main', false, 'revoking the remaining team source removes access without changing global membership');
  await access(outsider, 'main', true, 'revoking a team source does not remove a separate cross-team user grant');

  await change(manager, {teams: ['parent']});
  const oldState = await editForm(manager).locator('input[name="expectedState"]').inputValue();
  await change(manager, {descendants: ['parent']});
  await access(child, 'main', true, 'descendant scope is explicit and grants a child-team participant');
  const stale = await manager.request.post(origin + uri(), {form: {__csrf__: await csrf(manager), capability: 'view', mode: 'replace', teamScope: 'none', boundaryMode: 'keep', 'users[0]': f.blocked.phid, expectedState: oldState}});
  check('stale replacement is rejected instead of overwriting newer grants', stale.status() === 200 && (await stale.text()).includes('权限已被其他操作修改，请刷新后重试'));
  await access(blocked, 'main', false, 'stale submission did not grant its requested user');
  await change(manager, {mode: 'revoke', teams: ['parent']});
  await access(parent, 'main', true, 'direct and descendant team scopes are independently revocable sources');
  await change(manager, {mode: 'revoke', users: ['outsider']});
  await access(outsider, 'main', false, 'selected user authorization can be revoked');
  await change(manager, {users: ['outsider']});
  await removeUserRule(manager, 'main', 'outsider');
  await access(outsider, 'main', false, 'whole allow row removal takes effect');

  await change(manager, {mode: 'replace', users: ['manager'], teams: ['parent']});
  await access(parent, 'main', true, 'replacement retains only its chosen explicit team source');
  await access(child, 'main', false, 'replacement removes the old descendant grant');
  await access(member, 'main', true, 'replacement does not silently remove an existing project member');
  check('view replacement does not confer edit rights', (await parent.request.get(origin + uri())).status() === 403);
  await change(manager, {users: ['outsider']});
  await change(manager, {capability: 'edit', users: ['outsider']});
  check('an explicitly authorized editor still needs a project administrator role to manage permissions',
    (await outsider.request.get(origin + uri())).status() === 403);
  await change(manager, {capability: 'edit', mode: 'revoke', users: ['outsider']});
  check('revoking edit closes permission management immediately', (await outsider.request.get(origin + uri())).status() === 403);
  await access(outsider, 'main', true, 'independent view authorization remains after edit is revoked');
  await change(manager, {capability: 'join', teams: ['parent']});
  await visit(manager, uri());
  await manager.screenshot({path: path.join(output, 'project-access-rules.png'), fullPage: true});

  await visit(manager, uri('hidden'));
  let html = await manager.content();
  check('existing hidden team rule reveals neither team name nor PHID', !html.includes(f.teams.hidden.name) && !html.includes(f.teams.hidden.phid));
  const hiddenRule = manager.locator('.team-project-access-rule[data-access-rule-index="1"]');
  check('hidden allow reference can be removed without selecting its hidden team', await hiddenRule.getByRole('button', {name: '回收此授权', exact: true}).isVisible());
  await submit(manager, hiddenRule.locator('form'));
  check('hidden reference removal succeeds', new URL(manager.url()).searchParams.get('saved') === '1');

  await visit(manager, uri('deny'));
  const deny = manager.locator('.team-project-access-rule[data-access-rule-action="deny"]');
  check('deny rules have no misleading revoke-allow action', await deny.count() === 1 && await deny.locator('form').count() === 0);
  await manager.screenshot({path: path.join(output, 'existing-deny-rule.png'), fullPage: true});
  await change(manager, {project: 'deny', users: ['blocked']});
  await access(blocked, 'deny', true, 'adding a user grants the explicit exception ahead of an existing deny rule');
  await removeUserRule(manager, 'deny', 'blocked');
  await access(blocked, 'deny', false, 'removing the added exception restores the old deny behavior');

  await change(manager, {project: 'global', teams: ['parent']});
  check('mixed policy still names its old global allow rule clearly', (await manager.locator('.team-project-access-rule').allTextContents()).some(text => text.includes('所有登录用户')));
  await access(blocked, 'global', true, 'adding a team to an all-users policy does not turn it into a restriction');

  await visit(manager, uri('strict'));
  check('existing strict boundary is prominently distinct from additive grants', (await manager.locator('body').innerText()).includes('高级限制正在生效'));
  check('existing boundary is not silently opted out', await editForm(manager).locator('select[name="boundaryMode"]').inputValue() === 'keep');
  await change(manager, {project: 'strict', users: ['outsider']});
  await access(outsider, 'strict', false, 'adding an individual does not silently erase a previously configured strict boundary');
  await visit(manager, uri('strict'));
  await manager.screenshot({path: path.join(output, 'explicit-boundary-choice.png'), fullPage: true});
  await change(manager, {project: 'strict', mode: 'keep', boundaryMode: 'none'});
  check('after explicit removal the boundary selector returns to preserving the saved state',
    await editForm(manager).locator('select[name="boundaryMode"]').inputValue() === 'keep' && !await boundaryField(manager).isVisible());
  await access(outsider, 'strict', true, 'explicitly clearing strict boundary enables the cross-team personal grant');

  await change(manager, {project: 'mixed', mode: 'replace', users: ['manager'],
    teams: ['parent'], descendants: ['other']});
  await access(parent, 'mixed', true, 'mixed scope includes the selected direct team');
  await access(child, 'mixed', false, 'mixed scope does not include children of a direct-only team');
  await access(outsider, 'mixed', true, 'mixed scope simultaneously includes a different descendant-scope team');
  await change(manager, {project: 'mixed', mode: 'revoke', teams: ['parent']});
  await access(parent, 'mixed', false, 'mixed scope direct source can be revoked independently');
  await access(outsider, 'mixed', true, 'revoking the direct source preserves the other descendant source');
  await change(manager, {project: 'mixed', mode: 'revoke', descendants: ['other']});
  await access(outsider, 'mixed', false, 'mixed scope descendant source can be revoked independently');

  await visit(manager, uri('presets'));
  const untouchedState = await editForm(manager).locator('input[name="expectedState"]').inputValue();
  await editForm(manager).locator('select[name="teamScope"]').selectOption('mixed');
  await addToken(manager, field(manager, /^指定人员$/), f.blocked.username, f.blocked.phid);
  await addToken(manager, field(manager, /^团队（仅本级）$/), f.teams.parent.name, f.teams.parent.phid);
  await addToken(manager, field(manager, /^团队（包含下级）$/), f.teams.other.name, f.teams.other.phid);
  await editForm(manager).locator('select[name="boundaryMode"]').selectOption('direct');
  await addToken(manager, boundaryField(manager), f.teams.parent.name, f.teams.parent.phid);
  await editForm(manager).locator('select[name="boundaryMode"]').selectOption('keep');
  for (const mode of ['keep', 'all-users', 'administrators', 'automatic']) {
    await editForm(manager).locator('select[name="mode"]').selectOption(mode);
    check(mode + ' mode hides unused personal and team controls', !await field(manager, /^指定人员$/).isVisible() &&
      !await editForm(manager).locator('select[name="teamScope"]').isVisible() && !await boundaryField(manager).isVisible());
    check(mode + ' mode omits hidden token values from actual form data', (await submittedSubjectNames(manager)).length === 0);
  }
  await editForm(manager).locator('select[name="mode"]').selectOption('keep');
  await submit(manager);
  check('keeping all settings is a true no-op even after filling now-hidden pickers',
    new URL(manager.url()).searchParams.get('saved') === '1' &&
    await editForm(manager).locator('input[name="expectedState"]').inputValue() === untouchedState);
  await access(blocked, 'presets', false, 'the hidden pending personal grant was never saved');

  await change(manager, {project: 'presets', mode: 'all-users'});
  await access(blocked, 'presets', true, 'all-users preset grants a previously unrelated logged-in user');
  check('global view preset does not silently confer project edit access',
    (await blocked.request.get(origin + uri('presets'))).status() === 403);
  await change(manager, {project: 'presets', mode: 'administrators'});
  await access(admin, 'presets', true, 'administrator preset grants a site administrator');
  await access(blocked, 'presets', false, 'administrator replacement removes the former all-users grant');
  await access(member, 'presets', true, 'administrator preset still preserves native project-member visibility');
  await change(manager, {project: 'presets', mode: 'automatic'});
  await access(parent, 'presets', false, 'clearing explicit grants excludes unrelated nonmembers');
  await access(member, 'presets', true, 'clearing explicit grants preserves existing project membership');
  await visit(manager, uri('presets'));
  check('clearing view grants preserves the existing editor and permission management access', await editForm(manager).count() === 1);
  check('automatic-only permission has a neutral explanation and no meaningless revoke action',
    (await manager.locator('body').innerText()).includes('当前没有显式授权') &&
    await manager.locator('.team-project-access-rule').count() === 0 &&
    await manager.getByRole('button', {name: '回收此授权', exact: true}).count() === 0);
  await manager.screenshot({path: path.join(output, 'explicit-policy-presets.png'), fullPage: true});

  for (const [values, label] of [
    [{teamScope: 'none', 'teams[0]': f.teams.parent.phid}, 'hidden direct team under no-team scope'],
    [{teamScope: 'direct', 'descendantTeams[0]': f.teams.parent.phid}, 'hidden descendant team under direct scope'],
    [{teamScope: 'descendants', 'teams[0]': f.teams.parent.phid}, 'hidden direct team under descendant scope'],
    [{mode: 'keep', 'users[0]': f.blocked.phid}, 'hidden personal grant under keep mode'],
    [{mode: 'all-users', 'users[0]': f.blocked.phid}, 'hidden personal grant under global preset'],
    [{mode: 'keep', boundaryMode: 'keep', 'boundaryTeams[0]': f.teams.other.phid}, 'hidden boundary team under keep mode'],
    [{mode: 'keep', boundaryMode: 'none', 'boundaryTeams[0]': f.teams.parent.phid}, 'hidden boundary team under no-restriction mode'],
    [{mode: 'keep', boundaryMode: 'direct'}, 'new direct boundary without a selected team'],
    [{mode: 'keep', boundaryMode: 'keep', clearBoundary: '1'}, 'legacy clear checkbox conflicting with explicit keep mode'],
  ]) {
    await rejectChange(manager, 'presets', values, label);
  }

  await change(manager, {project: 'boundary', mode: 'keep', boundaryMode: 'direct', boundaryTeams: ['parent']});
  await access(parent, 'boundary', true, 'new direct boundary retains an already authorized direct team member');
  await access(child, 'boundary', false, 'new direct boundary excludes child-team membership');
  await access(member, 'boundary', false, 'project-wide boundary also restricts automatic project-member visibility');
  await access(outsider, 'boundary', false, 'project-wide boundary restricts an otherwise global view grant');
  await visit(manager, uri('boundary'));
  check('saved project-wide boundary is retained unless explicitly changed',
    await editForm(manager).locator('select[name="boundaryMode"]').inputValue() === 'keep' &&
    (await manager.locator('body').innerText()).includes('高级限制正在生效'));
  await manager.screenshot({path: path.join(output, 'project-wide-restriction.png'), fullPage: true});
  await change(manager, {project: 'boundary', capability: 'join', mode: 'keep',
    boundaryMode: 'descendants', boundaryTeams: ['parent']});
  await access(child, 'boundary', true, 'changing the project-wide scope from the join tab also changes visibility');
  await access(outsider, 'boundary', false, 'including child teams does not include unrelated teams');
  await change(manager, {project: 'boundary', capability: 'edit', mode: 'keep', boundaryMode: 'none'});
  await access(member, 'boundary', true, 'explicitly clearing the project-wide boundary restores automatic visibility');
  await access(outsider, 'boundary', true, 'clearing the boundary retains the original all-users policy');

  await visit(manager, uri('named'));
  check('named policy retains its name and independent management explanation',
    (await manager.locator('body').innerText()).includes(f.namedPolicy.name) &&
    (await manager.locator('body').innerText()).includes('命名策略'));
  const namedState = await editForm(manager).locator('input[name="expectedState"]').inputValue();
  await change(manager, {project: 'named', mode: 'keep'});
  check('keeping a named policy preserves its exact binding',
    await editForm(manager).locator('input[name="expectedState"]').inputValue() === namedState);
  await rejectChange(manager, 'named', {mode: 'add', 'users[0]': f.blocked.phid}, 'adding through a named policy');
  await rejectChange(manager, 'named', {mode: 'revoke', 'users[0]': f.blocked.phid}, 'revoking through a named policy');
  await change(manager, {project: 'named', mode: 'replace', users: ['manager']});
  await access(blocked, 'named', false, 'explicit named-policy replacement removes the former global grant');

  await visit(manager, uri('child'));
  check('ordinary subprojects disclose the parent visibility requirement', (await manager.locator('body').innerText()).includes('上级项目可见性要求'));
  await visit(manager, uri('milestone'));
  check('milestone explains inherited permissions and links to the parent management page',
    await manager.getByRole('button', {name: '管理所属项目权限', exact: true}).getAttribute('href') === uri('parent') && await editForm(manager).count() === 0);
  const milestonePost = await manager.request.post(origin + uri('milestone'), {form: {__csrf__: await csrf(manager), capability: 'view', mode: 'add'}});
  check('milestone direct permission mutation remains rejected', milestonePost.status() === 403);

  await manager.setViewportSize({width: 390, height: 844});
  await visit(manager, uri());
  check('mobile management form has no horizontal overflow', await manager.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  check('mobile keeps the primary action text and add default visible', await editForm(manager).getByRole('button', {name: '保存授权调整', exact: true}).isVisible() &&
    await editForm(manager).locator('select[name="mode"]').inputValue() === 'add');
  await manager.screenshot({path: path.join(output, 'project-access-mobile.png'), fullPage: true});
  await editForm(manager).locator('select[name="teamScope"]').selectOption('mixed');
  await editForm(manager).locator('select[name="boundaryMode"]').selectOption('direct');
  check('mobile expanded mixed scopes and overall restriction remain accessible without horizontal overflow',
    await field(manager, /^团队（仅本级）$/).isVisible() && await field(manager, /^团队（包含下级）$/).isVisible() &&
    await boundaryField(manager).isVisible() && await manager.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await manager.screenshot({path: path.join(output, 'project-access-mobile-expanded.png'), fullPage: true});
  report.passed = true;
} catch (error) {
  report.passed = false; report.error = error.stack || String(error);
} finally {
  for (const ctx of contexts) await ctx.close();
  await browser.close();
  fs.writeFileSync(path.join(output, 'browser-report.json'), JSON.stringify(report, null, 2) + '\n');
}
console.log(JSON.stringify({passed: report.passed, checks: report.checks.length, error: report.error}, null, 2));
process.exitCode = report.passed ? 0 : 1;
