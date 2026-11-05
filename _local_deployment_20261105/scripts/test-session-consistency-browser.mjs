// Real local two-host G02/G03 checks. Tickets/cookies/OTP stay in process memory.
import fs from 'node:fs';
import path from 'node:path';
import {launch, entryLogin, phorgeLogin, pmURL, authURL, stateDir, root, delay}
  from '../tests/browser/identity.mjs';

const checks = [];
function check(name, ok, status) {
  checks.push({name, passed:Boolean(ok), ...(status===undefined ? {} : {httpStatus:status})});
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${status===undefined ? '' : ` (${status})`}`);
  if (!ok) throw new Error(name);
}
function hasEntryCookie(response) {
  return response.headersArray().some(h => h.name.toLowerCase()==='set-cookie' &&
    h.value.startsWith('stargate_session_id=') && !h.value.includes('deleted'));
}
function saveReport() {
  fs.writeFileSync(path.join(root, 'state/acceptance/session-browser.json'),
    JSON.stringify({verifiedAt:new Date().toISOString(), passed:checks.length>0 && checks.every(c=>c.passed),
      pmURL, authURL, checks, scope:'Real HTTP/session state; no cookies, tickets or OTP persisted in report'},null,2)+'\n',
    {mode:0o600});
}

const browser = await launch();
let replacement;
let replacementReady = false;
let phase = 'exchange checks';
async function appLogin(context, page) {
  for (let attempt=0; attempt<3; attempt++) {
    try {return await phorgeLogin(context,page,'a_lead',{register:false});}
    catch (error) {
      if (!String(error.message).includes('ERR_NETWORK_CHANGED') || attempt===2) throw error;
      await delay(1000);
    }
  }
}
try {
  const b = await browser.newContext({ignoreHTTPSErrors:true,
    storageState:path.join(stateDir,'b_lead.json')});
  const anonymous = await browser.newContext({ignoreHTTPSErrors:true});
  async function ticket() {
    const response = await b.request.get(authURL+'/_login?callback='+encodeURIComponent(new URL(pmURL).host),
      {maxRedirects:0});
    const location = response.headers().location;
    if (response.status()!==302 || !location || !new URL(location).searchParams.has('ticket'))
      throw new Error('Authenticated ticket issuance failed');
    return location;
  }
  const location = await ticket();
  const wrongHost = authURL+new URL(location).pathname+new URL(location).search;
  let response = await anonymous.request.get(wrongHost,{maxRedirects:0});
  check('G02 fresh ticket rejected on wrong host without authenticated cookie',
    [401,404].includes(response.status()) && !hasEntryCookie(response),response.status());
  response = await anonymous.request.get(location,{maxRedirects:0,
    headers:{Host:new URL(pmURL).hostname+':9443'}});
  check('G02 fresh ticket rejected for wrong audience port at exchange handler',
    response.status()===401 && !hasEntryCookie(response),response.status());
  response = await anonymous.request.get(location,{maxRedirects:0});
  check('G02 correctly addressed unused ticket establishes entry session',
    response.status()===302 && hasEntryCookie(response),response.status());
  response = await anonymous.request.get(location,{maxRedirects:0});
  check('G02 consumed ticket replay rejected',response.status()===401 && !hasEntryCookie(response),response.status());
  const expiryLocation = await ticket();
  const expiryStarted = Date.now();

  // Restore A after the cross-user suite, then bind this new Phorge session.
  phase = 'prepare original A application session';
  const original = await browser.newContext({ignoreHTTPSErrors:true,
    storageState:path.join(stateDir,'a_lead.json')});
  await appLogin(original,await original.newPage());
  const oldCookies = await original.cookies(pmURL);
  const oldPhsid = oldCookies.find(c=>c.name==='phsid');
  const oldEntry = oldCookies.find(c=>c.name==='stargate_session_id');
  response = await original.request.post(authURL+'/_logout',{maxRedirects:0});
  check('G03 actual entry logout succeeds',response.status()===200,response.status());
  response = await original.request.get(pmURL+'/settings/user/a_lead/',{maxRedirects:0});
  check('G03 logged-out entry cannot use still-present Phorge cookie',
    response.status()===302 && new URL(response.headers().location).pathname==='/_login',response.status());

  replacement = await browser.newContext({ignoreHTTPSErrors:true});
  const page = await replacement.newPage();
  phase = 'same-user real OTP relogin';
  await entryLogin(replacement,page,'a_lead');
  replacementReady = true;
  const newEntry = (await replacement.cookies(pmURL)).find(c=>c.name==='stargate_session_id');
  check('G03 same user real OTP relogin receives a new entry session',newEntry.value!==oldEntry.value);
  await replacement.addCookies([oldPhsid]);
  response = await replacement.request.post(pmURL+'/api/user.whoami',
    {form:{params:'{}',output:'json'},maxRedirects:0});
  const body = await response.text();
  check('G03 old phsid rejected after real entry logout and same-user relogin',
    response.status()===409 && body.includes('ENTRY_SESSION_MISMATCH'),response.status());
  check('G03 rejection provides actionable current-identity login link',
    body.includes('/auth/login/traefik:traefik/'),response.status());
  check('G03 same-user stale Phorge cookie is cleared',
    !(await replacement.cookies(pmURL)).some(c=>c.name==='phsid'),response.status());
  phase = 'restore replacement A application session';
  await appLogin(replacement,page);
  check('G03 real Phorge login restores usable A session',true);
  replacementReady = false;

  // TTL is 120 seconds in the pinned Stargate source. Use the actual issued
  // ticket and wall clock; no signing key access or test-only clock override.
  while (Date.now()-expiryStarted < 122000) {
    await delay(Math.min(30000,122000-(Date.now()-expiryStarted)));
  }
  response = await anonymous.request.get(expiryLocation,{maxRedirects:0});
  check('G02 unused ticket expires after real 120-second TTL',
    response.status()===401 && !hasEntryCookie(response),response.status());
} catch (error) {
  // Playwright errors can contain full request URLs. Do not print those because
  // session exchange URLs contain bearer tickets.
  const safeMessage = String(error.message).replace(/https?:\/\/\S+/g,'[URL]')
    .replace(/[A-Za-z0-9_-]{24,}/g,'[REDACTED]').replace(/\b\d{6}\b/g,'[CODE]').slice(0,800);
  if (!checks.some(c=>!c.passed)) checks.push({name:'Unexpected test operation failed',phase,passed:false,detail:safeMessage});
  console.error('Session browser suite failed at '+phase+': '+safeMessage);
  process.exitCode = 1;
} finally {
  if (replacement && replacementReady) {
    try {
      await replacement.clearCookies({name:'phsid'});
      await phorgeLogin(replacement,await replacement.newPage(),'a_lead',{register:false});
      checks.push({name:'A session restored during cleanup',passed:true});
    } catch {
      checks.push({name:'A session cleanup requires real relogin',passed:false});
    }
  }
  saveReport();
  await browser.close();
}
