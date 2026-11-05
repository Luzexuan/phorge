import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const pmURL = process.env.PM_URL || 'https://pm.localhost:8443';
export const authURL = process.env.AUTH_URL || 'https://auth.localhost:8443';
export const usernames = ['test_admin', 'a_lead', 'a_member', 'b_lead', 'b_member', 'guest'];
export const stateDir = path.join(root, 'state/acceptance/browser');
fs.mkdirSync(stateDir, {recursive:true, mode:0o700});
export const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function launch() {
  return chromium.launch({headless:true, args:['--no-sandbox', '--disable-dev-shm-usage']});
}

export async function waitMail(mail, since) {
  const directory = path.join(root, 'state/testing-mail');
  for (let attempt=0; attempt<100; attempt++) {
    for (const name of fs.readdirSync(directory).sort().reverse()) {
      if (!name.endsWith('.json')) continue;
      const data = JSON.parse(fs.readFileSync(path.join(directory, name), 'utf8'));
      if (data.received_at*1000 < since-1000 || !data.recipients.includes(mail)) continue;
      const match = data.body.match(/(?:验证码(?:是)?|verification code(?: is)?|code)[^0-9]{0,80}([0-9]{6})/i)
        || data.body.match(/(?<![0-9])([0-9]{6})(?![0-9])/);
      if (match) return match[1];
    }
    await delay(200);
  }
  throw new Error('No private captured verification mail received for '+mail);
}

export async function entryLogin(context, page, username) {
  const mail = username+'@acceptance.test';
  await page.goto(pmURL+'/', {waitUntil:'domcontentloaded'});
  if (!page.url().includes('/_login')) await page.goto(authURL+'/_login', {waitUntil:'domcontentloaded'});
  await page.locator('#mail').fill(mail);
  for (let attempt=0; attempt<3; attempt++) {
    const sentAt = Date.now();
    const pending = page.waitForResponse(r => r.url().includes('/_send_verify_code') && r.request().method()==='POST');
    await page.locator('#sendCodeBtn').click();
    const response = await pending;
    const json = response.headers()['content-type']?.includes('json') ? await response.json() : {};
    if (response.status()===429 || json.reason==='rate_limited' || json.reason==='resend_cooldown') {
      await delay(61000);
      continue;
    }
    if (!response.ok() || !json.success || json.debug_code) throw new Error('Code request failed: '+response.status()+' '+(json.reason||json.message));
    const code = await waitMail(mail, sentAt);
    await page.locator('#verify_code').fill(code);
    const loginResponse = page.waitForResponse(r => r.url().includes('/_login') && r.request().method()==='POST');
    await page.locator('#loginForm button[type=submit]').click();
    const logged = await loginResponse;
    if (!logged.ok()) throw new Error('OTP login failed: '+logged.status());
    await page.waitForURL(url => url.host===new URL(pmURL).host &&
      url.pathname!=='/_login' && !url.pathname.includes('_session_exchange'), {timeout:20000});
    await page.waitForLoadState('domcontentloaded');
    return {challengeID:json.challenge_id, code};
  }
  throw new Error('Verification request remained rate limited');
}

export async function phorgeLogin(context, page, username, {register=true}={}) {
  let registered = false;
  await page.goto(pmURL+'/auth/login/traefik:traefik/', {waitUntil:'domcontentloaded'});
  if (await page.locator('input[name=username]').count()) {
    if (!register) throw new Error('Unexpected registration request for existing user '+username);
    await page.locator('input[name=username]').fill(username);
    const realName = page.locator('input[name=realName]');
    if (await realName.count()) await realName.fill('Acceptance '+username);
    const email = page.locator('input[name=email]');
    if (await email.count()) await email.fill(username+'@acceptance.test');
    await Promise.all([
      page.waitForLoadState('domcontentloaded'),
      page.getByRole('button', {name:/Register Account|Create Admin Account/}).click(),
    ]);
    await page.waitForURL(url => !url.pathname.includes('/auth/register/'), {timeout:20000});
    registered = true;
  }
  const cookies = await context.cookies(pmURL);
  if (!cookies.some(c => c.name==='phsid')) {
    const body = await page.locator('body').innerText();
    throw new Error('No Phorge session for '+username+' at '+new URL(page.url()).pathname+'; '+body.slice(0,700));
  }
  const settingsResponse = await page.goto(pmURL+'/settings/', {waitUntil:'domcontentloaded'});
  if (settingsResponse.status() !== 200) throw new Error('Account settings refused with HTTP '+settingsResponse.status()+' for '+username);
  const body = await page.locator('body').innerText();
  await context.storageState({path:path.join(stateDir, username+'.json')});
  fs.chmodSync(path.join(stateDir, username+'.json'), 0o600);
  await page.screenshot({path:path.join(stateDir, username+'-settings.png'), fullPage:true});
  const pendingApproval = body.includes('Wait for Approval') || body.includes('Wait For Approval');
  if (!body.includes(username) && !pendingApproval && !cookies.some(c => c.name==='phusr' && c.value===username)) {
    fs.writeFileSync(path.join(stateDir, username+'-settings.txt'), new URL(page.url()).pathname+'\n'+body, {mode:0o600});
    throw new Error('Account settings does not identify '+username);
  }
  return {username, registeredOrLoggedIn:true, operation:registered?'registered':'loggedIn', pmURL, pendingApproval,
    identityCookieMatches: cookies.some(c => c.name==='phusr' && c.value===username)};
}

async function main() {
  const selected = process.argv.slice(2).filter(x=>!x.startsWith('--'));
  const people = selected.length ? selected : usernames;
  const browser = await launch();
  const results = [];
  try {
    for (const username of people) {
      const context = await browser.newContext({ignoreHTTPSErrors:true});
      const page = await context.newPage();
      await entryLogin(context, page, username);
      results.push(await phorgeLogin(context, page, username, {register:!process.argv.includes('--existing-only')}));
      await context.close();
      console.log('PASS real OTP and Phorge browser registration/login: '+username);
    }
  } finally {
    await browser.close();
    const report = {verifiedAt:new Date().toISOString(), pmURL, authURL, results,
      scope:'Real Stargate→Warden→Herald→TLS→herald-smtp→private SMTP→OTP verification; no external mail delivery'};
    const target = path.join(root, 'state/acceptance/identity-browser.json');
    if (fs.existsSync(target)) {
      const previous = JSON.parse(fs.readFileSync(target, 'utf8'));
      if (previous.pmURL === pmURL) {
        report.results = [...(previous.results || []).filter(x => !results.some(y => x.username === y.username)), ...results];
      }
    }
    fs.writeFileSync(target, JSON.stringify(report,null,2)+'\n', {mode:0o600});
  }
}

if (process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  main().catch(error => {console.error(error.message); process.exitCode=1;});
}
