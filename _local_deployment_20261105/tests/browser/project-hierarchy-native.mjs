import fs from 'node:fs';
import path from 'node:path';
import {chromium} from 'playwright';

const [origin, fixturePath, output] = process.argv.slice(2);
const url = new URL(origin);
if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || Number(url.port) < 1024) {
  throw new Error('Only an isolated loopback HTTP test server is allowed.');
}
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const projects = fixture.projects;
const report = {scope: 'Isolated HTTP, synthetic native sessions and objects.', checks: []};
const browser = await chromium.launch({headless: true});
let owner, member;
const check = (name, passed) => {
  report.checks.push({name, passed: Boolean(passed)});
  if (!passed) throw new Error(name);
};
async function context(user) {
  const ctx = await browser.newContext({viewport: {width: 1440, height: 1000}});
  await ctx.route('**/*', async route => {
    const dest = new URL(route.request().url());
    if (dest.origin === origin) await route.continue();
    else await route.abort();
  });
  await ctx.addCookies([
    {name: 'phusr', value: user.username, url: origin},
    {name: 'phsid', value: user.session, url: origin, httpOnly: true},
  ]);
  return ctx;
}
async function visit(page, route) {
  const response = await page.goto(origin + route, {waitUntil: 'networkidle'});
  check('HTTP renders ' + route, response?.status() === 200);
  check('no runtime exception on ' + route,
    !/Unhandled Exception|Call to undefined method|Fatal error|Stack Trace/i.test(await page.locator('body').innerText()));
}
async function backHref(page) {
  const action = page.locator('a.team-project-parent-navigation, .team-project-parent-navigation a').first();
  check('visible parent navigation is present', await action.count() === 1 && await action.isVisible());
  return action.getAttribute('href');
}
try {
  owner = await context(fixture.owner);
  const page = await owner.newPage();
  page.setDefaultTimeout(20000);
  await visit(page, '/project/');
  let names = await page.locator('a.phui-oi-link').allTextContents();
  check('default directory displays sorted roots only',
    JSON.stringify(names) === JSON.stringify(['root', 'second', 'empty'].map(k => projects[k].name)));
  check('root title opens direct child directory',
    await page.locator('a.phui-oi-link').filter({hasText: projects.root.name}).getAttribute('href') ===
      `/project/subprojects/${projects.root.id}/`);
  await page.screenshot({path: path.join(output, 'root-directory.png'), fullPage: true});
  await page.locator('a.phui-oi-link').filter({hasText: projects.root.name}).click();
  await page.waitForLoadState('networkidle');
  names = await page.locator('a.phui-oi-link').allTextContents();
  check('parent directory shows immediate children without grandchildren',
    JSON.stringify(names) === JSON.stringify(['child', 'private'].map(k => projects[k].name)));
  check('root directory returns to explicit hierarchy', await backHref(page) === '/project/query/hierarchy/');
  await page.locator('a.phui-oi-link').filter({hasText: projects.child.name}).click();
  await page.waitForLoadState('networkidle');
  check('nested directory exposes only immediate grandchild',
    JSON.stringify(await page.locator('a.phui-oi-link').allTextContents()) === JSON.stringify([projects.grandchild.name]));
  check('nested directory back link targets actual parent',
    await backHref(page) === `/project/subprojects/${projects.root.id}/`);
  await page.screenshot({path: path.join(output, 'nested-directory.png'), fullPage: true});
  for (const section of ['profile', 'members', 'manage', 'edit']) {
    await visit(page, `/project/${section}/${projects.grandchild.id}/`);
    check(section + ' supports returning one level',
      await backHref(page) === `/project/subprojects/${projects.child.id}/`);
  }
  await page.setViewportSize({width: 390, height: 844});
  await visit(page, `/project/profile/${projects.grandchild.id}/`);
  check('mobile parent link retains the correct destination',
    await backHref(page) === `/project/subprojects/${projects.child.id}/`);
  await page.screenshot({path: path.join(output, 'mobile-project.png'), fullPage: true});
  await page.setViewportSize({width: 1440, height: 1000});
  await visit(page, '/project/query/all/');
  check('explicit all search retains descendant results',
    (await page.locator('a.phui-oi-link').allTextContents()).includes(projects.grandchild.name));

  member = await context(fixture.member);
  const other = await member.newPage();
  await visit(other, `/project/subprojects/${projects.root.id}/`);
  check('parent member cannot see private child in directory',
    !(await other.locator('body').innerText()).includes(projects.private.name));
  const denied = await other.goto(origin + `/project/profile/${projects.private.id}/`, {waitUntil: 'networkidle'});
  const deniedBody = await other.locator('body').innerText();
  check('direct private child URL is denied to parent member',
    ([403, 404].includes(denied.status()) || /Access Denied|You Shall Not Pass|权限|拒绝/.test(deniedBody)) &&
    !deniedBody.includes(projects.private.name));

  await visit(page, `/project/edit/?parent=${projects.empty.id}`);
  check('first-child form immediately offers all three independent policies',
    await page.locator('input[name="policy.view"]').count() === 1 &&
    await page.locator('input[name="policy.edit"]').count() === 1 &&
    await page.locator('input[name="policy.join"]').count() === 1);
  check('create-child form back link targets creation parent',
    await backHref(page) === `/project/subprojects/${projects.empty.id}/`);
  await page.locator('input[name="name"]').fill(fixture.createdName);
  await page.evaluate(phid => {
    for (const [name, value] of Object.entries({'policy.view': phid, 'policy.edit': phid, 'policy.join': 'no-one'})) {
      const input = document.querySelector(`input[name="${name}"]`);
      input.value = value;
      input.dispatchEvent(new Event('change', {bubbles: true}));
    }
  }, fixture.owner.phid);
  const form = page.locator('form').filter({has: page.locator('input[name="name"]')});
  await Promise.all([
    page.waitForURL(value => value.pathname !== '/project/edit/', {timeout: 30000}),
    form.locator('button[type="submit"], input[type="submit"]').first().click(),
  ]);
  await page.waitForLoadState('networkidle');
  check('actual first-child form submission succeeds',
    (await page.locator('body').innerText()).includes(fixture.createdName));
  await page.screenshot({path: path.join(output, 'created-first-child.png'), fullPage: true});
  await visit(other, `/project/subprojects/${projects.empty.id}/`);
  check('first child stays hidden from pre-existing parent member',
    !(await other.locator('body').innerText()).includes(fixture.createdName));
  report.passed = true;
} catch (error) {
  report.passed = false;
  report.error = error.message;
  for (const [label, ctx] of [['owner', owner], ['member', member]]) {
    const pages = ctx?.pages() || [];
    if (pages.length) await pages[pages.length - 1].screenshot({
      path: path.join(output, `failure-${label}.png`), fullPage: true,
    }).catch(() => {});
  }
} finally {
  for (const ctx of [owner, member]) {
    if (ctx) await ctx.close();
  }
  await browser.close();
  fs.writeFileSync(path.join(output, 'browser-report.json'), JSON.stringify(report, null, 2) + '\n', {mode: 0o600});
}
console.log(JSON.stringify({passed: report.passed, checks: report.checks.length, error: report.error}));
if (!report.passed) process.exitCode = 1;
