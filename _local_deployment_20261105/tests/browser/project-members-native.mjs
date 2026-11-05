import fs from 'node:fs';
import path from 'node:path';
import {chromium} from 'playwright';

const [origin, fixturePath, output] = process.argv.slice(2);
const endpoint = new URL(origin);
if (endpoint.protocol !== 'http:' || endpoint.hostname !== '127.0.0.1' || Number(endpoint.port) < 1024) {
  throw new Error('Only a disposable loopback application is allowed.');
}
const f = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const report = {scope: 'Disposable member-role and project-creation fixtures only.', checks: []};
const browser = await chromium.launch({headless: true});
const contexts = [];
let activePage;
const check = (name, ok) => { report.checks.push({name, passed: Boolean(ok)}); if (!ok) throw new Error(name); };
const target = f.projects.target;
const membersURI = `/project/members/${target.id}/`;
const addURI = `${membersURI}add/`;
const roleURI = role => `/organization/project/${target.id}/member-role/?phid=${f[role].phid}`;
const field = (page, label) => page.locator('.aphront-form-control').filter({has: page.locator('label').filter({hasText: label})});
const formWith = (page, selector) => page.locator('form').filter({has: page.locator(selector)});
async function account(role) {
  const ctx = await browser.newContext({viewport: {width: 1440, height: 1000}}); contexts.push(ctx);
  await ctx.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
  await ctx.addCookies([{name: 'phusr', value: f[role].username, url: origin},
    {name: 'phsid', value: f[role].session, url: origin, httpOnly: true}]);
  const page = await ctx.newPage(); page.setDefaultTimeout(20000); return page;
}
async function visit(page, route) {
  activePage = page;
  const response = await page.goto(origin + route, {waitUntil: 'networkidle'});
  check('HTTP renders ' + route, response?.status() === 200);
  check('no runtime failure on ' + route, !/Unhandled Exception|Call to undefined method|Fatal error|Stack Trace/.test(await page.locator('body').innerText()));
}
async function submit(page, form) {
  await Promise.all([page.waitForNavigation({waitUntil: 'networkidle'}), form.locator('button[type="submit"]').last().click()]);
}
async function csrf(page) {
  return page.evaluate(() => new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('CSRF refresh timed out.')), 15000);
    new JX.Request('/login/refresh/', data => { clearTimeout(timeout); resolve(data.token); }).send();
  }));
}
async function addToken(page, control, text, token) {
  await control.locator('input.jx-tokenizer-input').pressSequentially(text, {delay: 5});
  await page.locator(`a.jx-result[rel="${token}"]:visible`).click();
  check('tokenizer selects ' + token, await control.locator(`input[value="${token}"]`).count() === 1);
}
async function teamPolicy(page, capability) {
  const name = `policy.${capability}`;
  const control = page.locator('.aphront-form-control-policy').filter({has: page.locator(`input[name="${name}"]`)});
  await control.locator('a.policy-control').click();
  const option = page.locator('a.phabricator-action-view-item').filter({hasText: /^团队成员…$/});
  check('team-member policy is directly available for ' + capability, await option.isVisible());
  await option.click();
  const dialog = page.locator('.aphront-dialog-view');
  await dialog.getByText('团队成员策略', {exact: true}).waitFor();
  check('team shortcut keeps scope explicit for ' + capability,
    await dialog.locator('select[name="scope"]').inputValue() === 'direct' &&
    JSON.stringify(await dialog.locator('select[name="scope"] option').evaluateAll(nodes => nodes.map(x => x.value).sort())) === JSON.stringify(['descendants', 'direct']));
  await addToken(page, dialog, f.teams.allowed.name, f.teams.allowed.phid);
  await dialog.getByRole('button', {name: '使用此团队策略', exact: true}).click();
  await dialog.waitFor({state: 'hidden'});
  check('team shortcut stores a native custom policy for ' + capability,
    (await page.locator(`input[name="${name}"]`).inputValue()).startsWith('PHID-PLCY-'));
}
async function delegatedPolicy(page, capability, option, selected) {
  const name = `policy.${capability}`;
  const control = page.locator('.aphront-form-control-policy').filter({has: page.locator(`input[name="${name}"]`)});
  await control.locator('a.policy-control').click();
  await page.locator('a.phabricator-action-view-item').filter({hasText: option}).click();
  const dialog = page.locator('.aphront-dialog-view');
  await dialog.waitFor({state: 'visible'});
  check('delegated ' + option + ' retains its capability when submitting',
    await dialog.locator('input[name="capability"]').inputValue() === capability);
  await addToken(page, dialog, selected.name, selected.phid);
  await dialog.getByRole('button', {name: 'Done', exact: true}).click();
  await dialog.waitFor({state: 'hidden'});
  check('delegated ' + option + ' updates the native policy field after Done',
    await page.locator(`input[name="${name}"]`).inputValue() === selected.phid);
}
async function changeRole(page, role, value) {
  await visit(page, roleURI(role));
  await page.locator('select[name="role"]').selectOption(value);
  await submit(page, formWith(page, 'select[name="role"]'));
  check('role saved through the visible form: ' + role + '/' + value,
    new URL(page.url()).searchParams.get('roleSaved') === '1');
}

try {
  const owner = await account('owner'); const editor = await account('editor');
  const reader = await account('reader'); const teamuser = await account('teamuser');
  const outsider = await account('outsider');

  await visit(owner, '/project/edit/');
  check('creation omits both project-wide team restriction fields',
    await owner.locator('[name^="organizationTeams"], [name="organizationScope"]').count() === 0 &&
    !(await owner.locator('body').innerText()).includes('团队额外限制（影响查看、编辑、加入）'));
  check('creation retains three independent native policy controls',
    await owner.locator('input[name="policy.view"]').count() === 1 &&
    await owner.locator('input[name="policy.edit"]').count() === 1 &&
    await owner.locator('input[name="policy.join"]').count() === 1);
  await owner.locator('input[name="name"]').fill(f.newName);
  await delegatedPolicy(owner, 'view', 'Other Project...', f.projects.source);
  await delegatedPolicy(owner, 'edit', 'Other Named Policy...', f.namedPolicy);
  for (const capability of ['view', 'edit', 'join']) await teamPolicy(owner, capability);
  check('initial-members instructions explain one-time direct membership and role separation',
    (await owner.locator('body').innerText()).includes('仅一次性添加成员') &&
    (await owner.locator('body').innerText()).includes('不授予编辑或管理权限'));
  const initial = field(owner, /^初始成员$/);
  await addToken(owner, initial, f.teams.allowed.name, `teamMembers(${f.teams.allowed.phid})`);
  await addToken(owner, initial, f.projects.source.name, `members(${f.projects.source.phid})`);
  await addToken(owner, initial, f.reader.username, f.reader.phid);
  await owner.screenshot({path: path.join(output, 'create-team-policies-and-member-sources.png'), fullPage: true});
  await submit(owner, formWith(owner, 'input[name="name"]'));
  check('mixed-source project creation succeeds', (await owner.locator('body').innerText()).includes(f.newName) &&
    !new URL(owner.url()).pathname.startsWith('/project/edit/'));
  const createdMatch = new URL(owner.url()).pathname.match(/\/project\/(?:profile|manage|view|board)\/(\d+)\//);
  check('created project has a concrete object route', Boolean(createdMatch));
  const createdID = Number(createdMatch[1]);
  await visit(owner, `/project/members/${createdID}/`);
  const createdBody = await owner.locator('body').innerText();
  check('mixed sources persist all three unique people',
    [f.editor.username, f.reader.username, f.teamuser.username].every(name => createdBody.includes(name)));
  check('project creator retains member-administration controls outside the selected team',
    await owner.locator(`a[href="/project/members/${createdID}/add/"]`).count() >= 1);
  await visit(teamuser, `/project/profile/${createdID}/`);
  check('selected team members can read the created project', (await teamuser.locator('body').innerText()).includes(f.newName));
  const outsideCreated = await outsider.request.get(origin + `/project/profile/${createdID}/`);
  check('unselected nonmembers cannot read the created project',
    [403, 404].includes(outsideCreated.status()) || !(await outsideCreated.text()).includes(f.newName));

  await visit(owner, membersURI);
  check('creator can add members and manage roles without site-administrator status',
    await owner.getByRole('link', {name: '添加成员', exact: true}).count() >= 1 &&
    await owner.getByRole('link', {name: '管理角色', exact: true}).count() >= 1);
  await owner.screenshot({path: path.join(output, 'project-members-and-roles.png'), fullPage: true});
  for (const [page, name] of [[editor, 'editor'], [reader, 'reader']]) {
    await visit(page, membersURI);
    check(name + ' has no active member administration controls',
      await page.getByRole('link', {name: '管理角色', exact: true}).count() === 0 &&
      await page.getByRole('link', {name: '添加成员', exact: true}).count() === 0);
    for (const route of [addURI, roleURI('reader'), `${membersURI}remove/?phid=${f.reader.phid}`]) {
      const r = await page.request.get(origin + route);
      check(name + ' direct administration GET is rejected ' + route, [403, 404].includes(r.status()));
    }
    const forged = await page.request.post(origin + addURI, {form: {
      __csrf__: await csrf(page), expectedState: 'forged', 'memberPHIDs[0]': f.outsider.phid}});
    check(name + ' direct add POST is rejected', [403, 404].includes(forged.status()));
  }
  await visit(editor, `/project/edit/${target.id}/`);
  check('ordinary editor can still open content editing', await editor.locator('input[name="name"]').isEnabled());
  check('ordinary editor policy controls are locked', await editor.locator('.aphront-form-control-policy a.policy-control.disabled-control').count() === 3);
  await visit(editor, `/project/progress/${target.id}/`);
  check('ordinary editable member may publish before downgrade', await editor.locator('.team-project-progress-publish').count() === 1);

  await visit(owner, addURI);
  check('add-members dialog explains the same batch import semantics',
    (await owner.locator('body').innerText()).includes('一次性'));
  const stateBeforeAdd = await owner.locator('input[name="expectedState"]').inputValue();
  const sourceQuery = await owner.request.get(origin + '/typeahead/class/TeamProjectMemberImportDatasource/?q=' +
    encodeURIComponent(f.teams.hiddenRoster.name) + '&__ajax__=true');
  check('team with a hidden roster is absent from the member-source search', sourceQuery.status() === 200 &&
    !(await sourceQuery.text()).includes(f.teams.hiddenRoster.phid));
  const hiddenProjectQuery = await owner.request.get(origin + '/typeahead/class/TeamProjectMemberImportDatasource/?q=' +
    encodeURIComponent(f.projects.hidden.name) + '&__ajax__=true');
  check('hidden project is absent from the member-source search', hiddenProjectQuery.status() === 200 &&
    !(await hiddenProjectQuery.text()).includes(f.projects.hidden.phid));
  const forgedSource = await owner.request.post(origin + addURI, {form: {
    __form__: true, __csrf__: await csrf(owner), expectedState: stateBeforeAdd,
    'memberPHIDs[0]': f.outsider.phid, 'memberPHIDs[1]': `teamMembers(${f.teams.hiddenRoster.phid})`}});
  check('forged unreadable roster rejects the complete import',
    [200, 400].includes(forgedSource.status()) && (await forgedSource.text()).includes('成员名单不可读'));
  await visit(owner, addURI);
  check('rejected source import preserves the membership version',
    await owner.locator('input[name="expectedState"]').inputValue() === stateBeforeAdd);
  const noCSRF = await owner.request.post(origin + addURI, {form: {
    __form__: true, expectedState: stateBeforeAdd, 'memberPHIDs[0]': f.outsider.phid}});
  check('administrator member additions require CSRF', noCSRF.status() === 400);
  await addToken(owner, field(owner, /^添加成员$/), f.outsider.username, f.outsider.phid);
  await submit(owner, formWith(owner, 'input[name="expectedState"]'));
  check('administrator can add a new member after project creation',
    (await owner.locator('body').innerText()).includes(f.outsider.username));
  await visit(owner, `${membersURI}remove/?phid=${f.outsider.phid}`);
  await submit(owner, formWith(owner, 'input[name="expectedState"]'));
  check('administrator can remove the added member', new URL(owner.url()).pathname === membersURI &&
    !(await owner.locator('body').innerText()).includes(f.outsider.username));

  await visit(owner, roleURI('editor'));
  const oldState = await owner.locator('input[name="expectedState"]').inputValue();
  await owner.locator('select[name="role"]').selectOption('editor');
  await submit(owner, formWith(owner, 'select[name="role"]'));
  check('member can be explicitly assigned the editor role', new URL(owner.url()).searchParams.get('roleSaved') === '1');
  const stale = await owner.request.post(origin + roleURI('editor'), {form: {
    __csrf__: await csrf(owner), phid: f.editor.phid, role: 'viewer', expectedState: oldState}});
  check('stale member-role form rejects overwriting the new role', stale.status() === 200 &&
    (await stale.text()).includes('成员或权限已被其他操作修改'));
  await visit(owner, roleURI('editor'));
  check('rejected stale role retains the explicit editor assignment', await owner.locator('select[name="role"]').inputValue() === 'editor');
  await owner.locator('select[name="role"]').selectOption('viewer');
  await submit(owner, formWith(owner, 'select[name="role"]'));
  check('administrator can lower a member from editor to read-only', new URL(owner.url()).searchParams.get('roleSaved') === '1');
  await visit(editor, `/project/profile/${target.id}/`);
  await visit(editor, `/project/progress/${target.id}/`);
  check('read-only downgrade immediately removes node publication despite broad edit policy',
    await editor.locator('.team-project-progress-publish').count() === 0);
  const editAfter = await editor.request.get(origin + `/project/edit/${target.id}/`);
  const editDetails = await editor.evaluate(html => {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    doc.querySelectorAll('script, style, noscript').forEach(node => node.remove());
    const name = doc.querySelector('input[name="name"]');
    const text = (doc.body?.textContent || '').replace(/\s+/g, ' ').trim();
    const denial = text.search(/Access Denied|You Shall Not Pass/);
    return {
      denialText: text.slice(Math.max(0, denial - 120), Math.max(0, denial - 120) + 1600),
      nativeDenial: denial >= 0,
      nameInputExists: Boolean(name),
      editableNameInput: Boolean(name && name.type !== 'hidden' && !name.disabled && !name.readOnly),
    };
  }, await editAfter.text());
  fs.writeFileSync(path.join(output, 'edit-access-response.json'), JSON.stringify({
    route: `/project/edit/${target.id}/`, status: editAfter.status(), ...editDetails,
  }, null, 2) + '\n', {mode: 0o600});
  check('read-only downgrade removes native edit access',
    [403, 404].includes(editAfter.status()) ||
    (editAfter.status() === 200 && editDetails.nativeDenial && !editDetails.editableNameInput));
  const forgeRole = await editor.request.post(origin + roleURI('reader'), {form: {
    __csrf__: await csrf(editor), phid: f.reader.phid, role: 'admin', expectedState: 'forged'}});
  check('downgraded member cannot escalate another member to administrator', [403, 404].includes(forgeRole.status()));

  await visit(owner, roleURI('owner'));
  await owner.locator('select[name="role"]').selectOption('viewer');
  await submit(owner, formWith(owner, 'select[name="role"]'));
  check('last effective project administrator cannot be downgraded',
    new URL(owner.url()).pathname.includes('/member-role/') &&
    /最后一名有效项目管理员|失去.*权限|policy/i.test(await owner.locator('body').innerText()));
  await visit(owner, roleURI('owner'));
  check('last-administrator protection leaves owner in control', await owner.locator('select[name="role"]').inputValue() === 'admin');

  await owner.setViewportSize({width: 390, height: 844});
  await visit(owner, membersURI);
  check('mobile member administration has no horizontal overflow', await owner.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await owner.screenshot({path: path.join(output, 'project-members-mobile.png'), fullPage: true});
  await visit(owner, roleURI('editor'));
  check('mobile role control and save action are usable', await owner.locator('select[name="role"]').isVisible() &&
    await owner.getByRole('button', {name: '保存成员角色', exact: true}).isVisible() &&
    await owner.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await owner.screenshot({path: path.join(output, 'project-member-role-mobile.png'), fullPage: true});
  await visit(owner, '/project/edit/');
  check('mobile create form retains batch member search without overflow',
    await field(owner, /^初始成员$/).locator('input.jx-tokenizer-input').isVisible() &&
    await owner.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await owner.screenshot({path: path.join(output, 'project-create-mobile.png'), fullPage: true});
  report.passed = true;
} catch (error) {
  report.passed = false; report.error = error.stack || String(error);
  try {
    if (activePage && !activePage.isClosed()) {
      await activePage.screenshot({path: path.join(output, 'failure.png'), fullPage: true});
      fs.writeFileSync(path.join(output, 'failure-body.txt'), await activePage.locator('body').innerText(), {mode: 0o600});
    }
  } catch (_) { /* Preserve the original failure if the page already closed. */ }
} finally {
  for (const ctx of contexts) await ctx.close();
  await browser.close();
  fs.writeFileSync(path.join(output, 'browser-report.json'), JSON.stringify(report, null, 2) + '\n');
}
console.log(JSON.stringify({passed: report.passed, checks: report.checks.length, error: report.error}, null, 2));
process.exitCode = report.passed ? 0 : 1;
