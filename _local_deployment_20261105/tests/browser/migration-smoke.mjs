import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {randomBytes, createHash} from 'node:crypto';
import {chromium} from 'playwright';

// Real login against an existing-data clone. Password plaintext remains in
// process memory; the cloned password file is restored even after test failure.
// Only clone credentials and business records may be changed. This runner is
// deliberately unavailable for production targets and external destinations.
const [targetArgument, outputArgument] = process.argv.slice(2);
const denialDiagnosticOnly = process.argv.includes('--diagnose-denials');
if (!targetArgument || !outputArgument) {
  throw new Error('Usage: migration-smoke.mjs TARGET_ROOT REPORT_DIRECTORY');
}
const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const target = fs.realpathSync(targetArgument);
const output = path.resolve(outputArgument);
const markerPath = path.join(target, '.migration-target.json');
const marker = JSON.parse(fs.readFileSync(markerPath, 'utf8'));
const origin = marker.origin;
const uri = new URL(origin);
const project = marker.project;
if (target === sourceRoot || marker.rehearsal !== true ||
    !/^tm-migrate-test-[a-f0-9]{8,32}$/.test(project) ||
    uri.protocol !== 'https:' || uri.hostname !== '127.0.0.1' ||
    Number(uri.port) < 1024 || uri.username || uri.password ||
    uri.search || uri.hash || uri.pathname !== '/' ||
    (marker.targetRoot && path.resolve(marker.targetRoot) !== target)) {
  throw new Error('Refusing any target except a marked loopback migration rehearsal.');
}
const wrapper = fs.realpathSync(marker.composeWrapper || path.join(target, 'scripts/compose.sh'));
if (!wrapper.startsWith(target + path.sep)) {
  throw new Error('The Compose wrapper must belong to the restored target.');
}
fs.mkdirSync(output, {recursive: true, mode: 0o700});
fs.chmodSync(output, 0o700);
const report = {formatVersion: 1, project, origin, startedAt: new Date().toISOString(),
  scope: 'Real login, existing business objects and one disposable work comment in an isolated clone.',
  diagnosticOnly: denialDiagnosticOnly, checks: [], passed: false};
const contexts = [];
let browser;
let passwordPath;
let passwordOriginal;
let passwordInfo;
let passwordPublished;
let publishedComment;
const deniedTitles = [];
let stage = 'isolation';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const check = (name, passed) => {
  report.checks.push({name, passed: Boolean(passed)});
  if (!passed) throw new Error(name);
};
function command(program, args, input) {
  const result = spawnSync(program, args, {cwd: target, input,
    encoding: 'utf8', timeout: 120000, maxBuffer: 16 * 1024 * 1024});
  if (result.error || result.status !== 0) throw new Error('Command failed at ' + stage);
  return result.stdout;
}
function atomicPassword(bytes) {
  const temporary = path.join(path.dirname(passwordPath), '.migration-browser-' + randomBytes(8).toString('hex'));
  const fd = fs.openSync(temporary, 'wx', passwordInfo.mode & 0o777);
  try {
    fs.fchownSync(fd, passwordInfo.uid, passwordInfo.gid);
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(temporary, passwordPath);
}
function sample(items, predicate, limit = 1) {
  return items.filter(predicate).slice(0, limit);
}
async function render(page, route, label) {
  const response = await page.goto(origin + route, {waitUntil: 'domcontentloaded'});
  const body = await page.locator('body').innerText();
  check(label, response?.status() === 200 &&
    !/Unhandled Exception|Call to undefined method|Fatal error|Stack Trace/.test(body) &&
    new URL(page.url()).origin === origin && new URL(page.url()).pathname !== '/_login');
  return body;
}
async function objectPage(page, route, item, label) {
  const response = await page.goto(origin + route, {waitUntil: 'domcontentloaded'});
  const body = await page.locator('body').innerText();
  const title = await page.title();
  const accessDialog = page.locator('.aphront-access-dialog');
  const policyRejection = accessDialog.locator('.aphront-policy-rejection');
  const dialogHeading = await accessDialog.locator('.aphront-dialog-head').count() === 1
    ? (await accessDialog.locator('.aphront-dialog-head').innerText()).trim() : '';
  // PhabricatorStandardPageView::getTitle() prepends the application glyph
  // (or application name) to the document title. The native policy handler's
  // dialog heading is unprefixed. Require both its exact heading and the
  // policy handler's dedicated markup; a generic HTTP 200 dialog is not denial.
  const denialHeading = /^(?:You Shall Not Pass|Access Denied): .+$/.test(dialogHeading);
  const nativeDenial = response.status() === 200 &&
    await accessDialog.count() === 1 && await policyRejection.count() === 1 && denialHeading;
  if (!item.view) {
    const dialog = page.locator('.aphront-dialog-view');
    const dialogBody = await dialog.count() ? await dialog.first().innerText() : '';
    (report.objectDenials ||= []).push({check: label, status: response.status(),
      nativeDenial, titleStartsWithDenial: /^(?:You Shall Not Pass|Access Denied)/.test(title),
      titleContainsDeniedObjectName: title.includes(item.name),
      titleCategory: /^(?:You Shall Not Pass|Access Denied)/.test(title) ? 'policy-denial'
        : denialHeading && title.endsWith(' ' + dialogHeading) ? 'application-prefixed-policy-denial'
        : /^Unhandled Exception/.test(title) ? 'unhandled-exception'
        : /^Slow Down!/.test(title) ? 'rate-limit'
        : /^Query Overheated/.test(title) ? 'query-overheated'
        : title === '' ? 'empty' : 'other',
      nativePolicyRejectionPresent: await page.locator('.aphront-policy-rejection').count() > 0,
      nativeAccessDialogPresent: await page.locator('.aphront-access-dialog').count() > 0,
      dialogHeadingMatchesPolicyDenial: denialHeading,
      bodyContainsDeniedObjectName: body.includes(item.name),
      nativeDialogPresent: await dialog.count() > 0,
      dialogContainsDeniedObjectName: dialogBody.includes(item.name),
      projectProfilePresent: await page.locator('.project-view-home').count() > 0,
      policyExplanationLinkPresent: await page.locator('a[href*="/policy/explain/"]').count() > 0});
  }
  check(label, item.view
    ? response.status() === 200 && body.includes(item.name) &&
      !/Unhandled Exception|Fatal error/.test(body)
    : ([403, 404].includes(response.status()) || nativeDenial) && !body.includes(item.name));
}

try {
  const ids = command(wrapper, ['ps', '-q', 'phorge']).trim().split(/\s+/).filter(Boolean);
  check('one restored Phorge container is available', ids.length === 1);
  const inspected = JSON.parse(command('docker', ['inspect', ids[0]]))[0];
  check('native queries target the marked rehearsal project',
    inspected.Config.Labels['com.docker.compose.project'] === project &&
    inspected.Config.Labels['com.docker.compose.service'] === 'phorge');
  const containers = command(wrapper, ['ps', '-q']).trim().split(/\s+/).filter(Boolean);
  const details = JSON.parse(command('docker', ['inspect', ...containers]));
  const networks = new Set();
  check('every service uses only rehearsal-owned volumes and copied bind mounts', details.every(container =>
    container.Config.Labels['com.docker.compose.project'] === project &&
    container.Mounts.every(mount => mount.Type === 'volume'
      ? mount.Name.startsWith(project + '_')
      : mount.Type === 'bind' && mount.Source.startsWith(target + path.sep))));
  for (const container of details) {
    for (const network of Object.keys(container.NetworkSettings.Networks)) networks.add(network);
  }
  const networkDetails = JSON.parse(command('docker', ['network', 'inspect', ...networks]));
  check('all rehearsal Docker networks block external routing', networkDetails.every(network =>
    network.Internal && network.Labels['com.docker.compose.project'] === project));
  check('published rehearsal ports listen on loopback only', details.every(container =>
    Object.values(container.NetworkSettings.Ports || {}).flatMap(value => value || [])
      .every(binding => binding.HostIp === '127.0.0.1')));

  stage = 'existing-identity-description';
  const fixtureSource = fs.readFileSync(path.join(sourceRoot, 'tests/migration/browser_probe.php'), 'utf8');
  const fixture = JSON.parse(command(wrapper, ['exec', '-T', '-e', 'TEAM_MIGRATION_REHEARSAL=1',
    '-e', 'TEAM_MIGRATION_PROJECT=' + project, 'phorge', 'php'], fixtureSource));
  const directory = JSON.parse(fs.readFileSync(path.join(target, 'config/warden/users.json'), 'utf8'));
  const candidates = fixture.actors.filter(actor => directory.some(row =>
    row.user_id === actor.principal && row.status === 'active' &&
    String(row.mail).toLowerCase() === actor.email.toLowerCase()));
  const ordinary = candidates.filter(actor => !actor.admin).sort((left, right) =>
    Number(right.projects.some(row => row.view && !row.edit)) -
    Number(left.projects.some(row => row.view && !row.edit)));
  const actors = [...sample(candidates, actor => actor.admin), ...ordinary.slice(0, 2)];
  check('restored administrator and ordinary identities remain bound',
    actors.length >= 2 && actors.some(actor => actor.admin) && actors.some(actor => !actor.admin));
  report.actorsChecked = actors.length;

  stage = 'clone-only-passwords';
  passwordPath = path.join(target, 'config/passwords/users.json');
  passwordInfo = fs.lstatSync(passwordPath);
  check('password mutation is confined to a regular private clone file',
    passwordInfo.isFile() && !passwordInfo.isSymbolicLink() && passwordInfo.nlink === 1 &&
    (passwordInfo.mode & 0o777) === 0o600 && fs.realpathSync(passwordPath) === passwordPath);
  passwordOriginal = fs.readFileSync(passwordPath);
  const store = JSON.parse(passwordOriginal);
  for (const actor of actors) actor.password = randomBytes(30).toString('base64url');
  const hashes = JSON.parse(command('python3', ['-c',
    "import json,sys;sys.path.insert(0,sys.argv[1]);from credential_hashes import hash_password;print(json.dumps([hash_password(x) for x in json.load(sys.stdin)]))",
    path.join(target, 'config/registration')], JSON.stringify(actors.map(actor => actor.password))));
  actors.forEach((actor, index) => {
    store.users[actor.principal] = {password_hash: hashes[index], revision: cryptoRevision()};
  });
  passwordPublished = Buffer.from(JSON.stringify(store, null, 2) + '\n');
  atomicPassword(passwordPublished);

  stage = 'browser-launch';
  browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage']});
  for (const [index, actor] of actors.entries()) {
    if (denialDiagnosticOnly && index !== 1) continue;
    stage = 'actor-' + index + '-password-login';
    const context = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 1280, height: 900}});
    contexts.push(context);
    await context.route('**/*', route => new URL(route.request().url()).origin === origin
      ? route.continue() : route.abort());
    const page = await context.newPage();
    page.setDefaultTimeout(25000);
    const login = await page.goto(origin + '/_login', {waitUntil: 'domcontentloaded'});
    check('actor ' + index + ' sees the restored login form', login.status() === 200 &&
      await page.locator('#personalPasswordForm').count() === 1);
    if (index === 0) await page.screenshot({path: path.join(output, 'restored-login.png'), fullPage: true});
    await page.locator('#personalPasswordForm [name="password_identifier"]').fill(actor.email);
    await page.locator('#personalPasswordForm [name="password"]').fill(actor.password);
    const pending = page.waitForResponse(response =>
      new URL(response.url()).pathname === '/_login' && response.request().method() === 'POST');
    await page.locator('#personalPasswordForm button[type="submit"]').click();
    const accepted = await pending;
    check('actor ' + index + ' passes Stargate password and Warden admission', accepted.status() === 200);
    await page.waitForURL(url => url.origin === origin && url.pathname !== '/_login');
    await page.goto(origin + '/auth/login/traefik:traefik/', {waitUntil: 'domcontentloaded'});
    check('actor ' + index + ' reuses the existing Phorge account',
      await page.locator('input[name="username"]').count() === 0);
    await render(page, '/settings/', 'actor ' + index + ' opens existing account settings');
    const cookies = await context.cookies(origin);
    check('actor ' + index + ' receives both entry and native sessions',
      cookies.some(cookie => cookie.name === 'stargate_session_id' && cookie.value) &&
      cookies.some(cookie => cookie.name === 'phsid' && cookie.value) &&
      cookies.some(cookie => cookie.name === 'phusr' && cookie.value === actor.username));
    const csrf = await page.locator('input[name="__csrf__"]').first().inputValue();
    const who = await context.request.post(origin + '/api/user.whoami', {
      form: {params: '{}', output: 'json', __csrf__: csrf}});
    const identity = await who.json();
    check('actor ' + index + ' resolves to the original stable Phorge identity',
      who.status() === 200 && !identity.error_code && identity.result?.phid === actor.phid &&
      identity.result?.userName === actor.username);

    if (denialDiagnosticOnly) {
      stage = 'actor-' + index + '-denial-diagnostic';
      for (const item of sample(actor.projects, row => !row.view)) {
        await objectPage(page, '/project/profile/' + item.id + '/', item,
          'actor ' + index + ' project denial matches restored policy');
      }
      continue;
    }

    stage = 'actor-' + index + '-maintenance';
    if (actor.admin) {
      await render(page, '/maintenance/', 'administrator opens the restored account maintenance overview');
      const usersBody = await render(page, '/maintenance/users/',
        'administrator opens the restored user and allowlist page');
      check('maintenance RPC returns existing identity data to the administrator',
        usersBody.includes(actor.username) && usersBody.includes(actor.email) &&
        !usersBody.includes('维护服务暂时不可用'));
    } else {
      for (const route of ['/maintenance/', '/maintenance/users/']) {
        const denied = await context.request.get(origin + route);
        const html = await denied.text();
        // This Phorge version performs application-policy enforcement before
        // shouldRequireAdmin(), and renders its denial dialog with HTTP 200.
        // Accept that exact native denial only when no private maintenance
        // rows, action forms, password hashes or temporary passwords appear.
        const policyDialog = denied.status() === 200 &&
          /<title>(?:You Shall Not Pass|Access Denied): Restricted Application<\/title>/.test(html);
        const containsMaintenanceData =
          /data-maintenance-(?:user|registration|audit)-id=|id="maintenance-action-form"/.test(html);
        const containsCredentials = /scrypt\$32768\$8\$3\$[a-f0-9]{32}\$[a-f0-9]{64}/.test(html) ||
          actors.some(candidate => html.includes(candidate.password));
        (report.maintenanceDenials ||= []).push({actor: index, route,
          status: denied.status(), nativePolicyDialog: policyDialog,
          containsMaintenanceData, containsCredentials});
        check('actor ' + index + ' cannot access administrator maintenance',
          ([403, 404].includes(denied.status()) || policyDialog) &&
          !containsMaintenanceData && !containsCredentials);
      }
    }

    stage = 'actor-' + index + '-business-pages';
    await render(page, '/project/', 'actor ' + index + ' opens the restored project directory');
    await render(page, '/organization/', 'actor ' + index + ' opens the restored team directory');
    for (const item of [...sample(actor.projects, row => row.view && row.nodeID),
      ...sample(actor.projects, row => row.view && !row.nodeID),
      ...sample(actor.projects, row => !row.view)]) {
      await objectPage(page, '/project/profile/' + item.id + '/', item,
        'actor ' + index + ' project ' + (item.view ? 'access' : 'denial') + ' matches restored policy');
      if (item.view) {
        await render(page, '/project/progress/' + item.id + '/',
          'actor ' + index + ' opens the existing node history');
        if (item.nodeID) {
          await render(page, '/project/progress/' + item.id + '/?entry=' + item.nodeID,
            'actor ' + index + ' opens a preserved node permalink');
          check('actor ' + index + ' preserved node renders its native timeline',
            await page.locator('.team-project-progress-record').count() > 0);
        }
        if (item.edit) await render(page, '/organization/project/' + item.id + '/permissions/',
          'actor ' + index + ' can manage its existing project permissions');
      }
    }
    for (const item of [...sample(actor.tasks, row => row.view), ...sample(actor.tasks, row => !row.view)]) {
      await objectPage(page, '/T' + item.id, item,
        'actor ' + index + ' task ' + (item.view ? 'access' : 'denial') + ' matches restored policy');
    }
    for (const item of [...sample(actor.teams, row => row.view), ...sample(actor.teams, row => !row.view)]) {
      await objectPage(page, '/organization/view/' + item.id + '/', item,
        'actor ' + index + ' team ' + (item.view ? 'access' : 'denial') + ' matches restored policy');
    }
    stage = 'actor-' + index + '-attachments';
    for (const file of actor.files) {
      const fileURI = new URL(file.uri, origin);
      check('attachment URI remains on the restored origin', fileURI.origin === origin);
      const downloaded = await context.request.get(fileURI.toString());
      if (file.view) {
        const body = await downloaded.body();
        check('actor ' + index + ' downloads original attachment bytes',
          downloaded.status() === 200 && body.length === file.bytes && sha(body) === file.sha256);
      } else {
        check('actor ' + index + ' cannot download another private attachment',
          [403, 404].includes(downloaded.status()));
      }
    }

    stage = 'actor-' + index + '-clone-publish';
    const editable = actor.projects.find(row => row.view && row.edit);
    if (!publishedComment && editable) {
      const title = 'Migration rehearsal comment ' + randomBytes(10).toString('hex');
      const body = 'A disposable clone verifies that restored project history remains writable.';
      const route = '/project/progress/' + editable.id + '/';
      await render(page, route + '?compose=comment', 'restored project exposes its work comment form');
      const form = page.locator('form').filter({has: page.locator('input[name="title"]')});
      check('restored work comment form retains the authenticated publisher', await form.count() === 1);
      await form.locator('input[name="title"]').fill(title);
      await form.locator('textarea[name="body"]').fill(body);
      await Promise.all([page.waitForNavigation({waitUntil: 'domcontentloaded'}),
        form.locator('button[type="submit"], input[type="submit"]').first().click()]);
      const entryID = Number(new URL(page.url()).searchParams.get('entry'));
      check('submitting a restored comment creates a stable record permalink',
        Number.isInteger(entryID) && entryID > 0 &&
        (await page.locator('body').innerText()).includes(title));
      await render(page, route + '?entry=' + entryID, 'new clone comment persists after reloading its permalink');
      const record = page.locator('.team-project-progress-record');
      check('new clone comment shows its text and original account author',
        await record.count() === 1 && (await record.innerText()).includes(title) &&
        (await record.innerText()).includes(body) &&
        await record.locator('a[href="/p/' + actor.username + '/"]').count() > 0);
      publishedComment = {actorPHID: actor.phid, projectID: editable.id, entryID, title, body};
    }
    const readonly = actor.projects.find(row => row.view && !row.edit);
    if (readonly) {
      const route = '/project/progress/' + readonly.id + '/';
      await render(page, route, 'actor ' + index + ' reads a project without edit permission');
      check('actor ' + index + ' has no comment publishing form on its read-only project',
        await page.locator('input[name="title"]').count() === 0);
      const token = await page.evaluate(() => new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('CSRF refresh timed out.')), 15000);
        new JX.Request('/login/refresh/', data => {clearTimeout(timer); resolve(data.token);}).send();
      }));
      const rejectedTitle = 'Migration rejected comment ' + randomBytes(10).toString('hex');
      deniedTitles.push(rejectedTitle);
      const rejected = await context.request.post(origin + route, {maxRedirects: 0,
        form: {__csrf__: token, kind: 'comment', title: rejectedTitle,
          body: 'This unauthorized clone comment must not persist.'}});
      check('actor ' + index + ' cannot bypass restored publish permissions with a valid CSRF POST',
        rejected.status() === 403);
    }
  }
  if (!denialDiagnosticOnly) {
    stage = 'native-clone-write-verification';
    check('an editable restored project accepted a real comment', Boolean(publishedComment));
    check('a restored read-only project rejected a direct publication attempt', deniedTitles.length > 0);
    const verification = Buffer.from(JSON.stringify({...publishedComment, deniedTitles})).toString('base64');
    const verified = JSON.parse(command(wrapper, ['exec', '-T', '-e', 'TEAM_MIGRATION_REHEARSAL=1',
      '-e', 'TEAM_MIGRATION_PROJECT=' + project, 'phorge', 'php'],
    "<?php $migration_browser_verify = json_decode(base64_decode('" + verification + "'), true);\n" +
      fixtureSource.replace(/^<\?php/, '')));
    check('native transactions preserve the new comment author and reject every unauthorized write',
      verified.passed && verified.persistedComments === 1 && verified.deniedWritesPersisted === 0 && verified.authorMatches);
    report.cloneWriteVerification = verified;
  }
  report.passed = true;
} catch (error) {
  report.passed = false;
  report.failureStage = stage;
  // Avoid persisting usernames, full request URLs, page contents or credentials.
  report.errorType = error.constructor.name;
} finally {
  for (const context of contexts) await context.close().catch(() => {});
  if (browser) await browser.close().catch(() => {});
  if (passwordPublished) {
    try {
      if (!fs.readFileSync(passwordPath).equals(passwordPublished)) {
        throw new Error('Clone password file changed concurrently.');
      }
      atomicPassword(passwordOriginal);
      report.clonePasswordFileRestored = fs.readFileSync(passwordPath).equals(passwordOriginal);
      if (!report.clonePasswordFileRestored) report.passed = false;
    } catch (error) {
      report.clonePasswordFileRestored = false;
      report.passed = false;
    }
  }
  report.completedAt = new Date().toISOString();
  fs.writeFileSync(path.join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n', {mode: 0o600});
}
console.log(JSON.stringify({passed: report.passed, checks: report.checks.length,
  failureStage: report.failureStage, clonePasswordFileRestored: report.clonePasswordFileRestored}));
if (!report.passed) process.exitCode = 1;

function cryptoRevision() {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return bytes.toString('hex');
}
