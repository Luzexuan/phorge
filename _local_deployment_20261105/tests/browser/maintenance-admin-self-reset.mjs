import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {chromium} from 'playwright';

// Deployment acceptance, intentionally gated by --run and a successful primary
// lifecycle. Only its dedicated synthetic C may receive a temporary admin role.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const origin='https://45.77.36.106';
const folder=path.join(root,'state/acceptance/maintenance');
const privatePath=path.join(folder,'lifecycle-private.json');
const statePath=path.join(folder,'stale-admin.json');
const reportPath=path.join(root,'state/acceptance/maintenance-admin-self-reset.json');
const report={verifiedAt:new Date().toISOString(),checks:[],scope:'Dedicated synthetic C administrator self-reset through the native maintenance form, browser cookie clearing, and same-browser login to the original native identity.'};
const cookieNames=['phusr','phsid','stargate_session_id'];
let browser,context,actor,fixture,promotionAttempted=false,succeeded=false,step='preflight';

function check(name,passed) {
  report.checks.push({name,passed:!!passed});
  console.log((passed?'PASS ':'FAIL ')+name);
  if(!passed)throw new Error('Self-reset acceptance check failed');
}
function readPrivate(file) {
  const stat=fs.lstatSync(file);
  if(!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077))throw new Error('Private fixture is not a protected regular file');
  return JSON.parse(fs.readFileSync(file,'utf8'));
}
function savePrivate(file,value) {
  const temporary=file+'.self-reset-'+randomBytes(6).toString('hex');
  try {
    fs.writeFileSync(temporary,JSON.stringify(value,null,2)+'\n',{mode:0o600,flag:'wx'});
    fs.chmodSync(temporary,0o600);
    fs.renameSync(temporary,file);
  } finally {if(fs.existsSync(temporary))fs.unlinkSync(temporary);}
}
function safeActor(value) {
  return value?.key==='c' && value.approved===true &&
    /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value.registrationId) && value.principal==='reg-'+value.registrationId &&
    /^PHID-USER-[a-zA-Z0-9]{20}$/.test(value.phid) &&
    /^maint_c_[a-z0-9]+$/.test(value.username) &&
    /^maintenance_c_[a-z0-9]+@acceptance\.test$/.test(value.email) &&
    value.username==='maint_c_'+fixture.stamp && value.email==='maintenance_c_'+fixture.stamp+'@acceptance.test';
}
function setSyntheticAdmin(admin) {
  if(!safeActor(actor))throw new Error('Unsafe synthetic administrator target');
  // Include no credential or browser state in the PHP input or process args.
  const spec={phid:actor.phid,username:actor.username,principal:actor.principal,email:actor.email};
  const encoded=Buffer.from(JSON.stringify(spec)).toString('base64');
  const source=`<?php
require '/opt/phorge/phorge/scripts/__init_script__.php';
$spec=json_decode(base64_decode('${encoded}'),true);
$viewer=PhabricatorUser::getOmnipotentUser();
$user=id(new PhabricatorPeopleQuery())->setViewer($viewer)->withPHIDs(array($spec['phid']))->executeOne();
$email=$user?id(new PhabricatorUserEmail())->loadOneWhere('userPHID = %s AND isPrimary = 1',$user->getPHID()):null;
if(!$user || $user->getPHID()!==$spec['phid'] || $user->getUsername()!==$spec['username'] || !preg_match('/^maint_c_[a-z0-9]+$/D',$user->getUsername()) || in_array($user->getUsername(),array('siteadmin','test_admin','admin','root')) || !$email || $email->getAddress()!==$spec['email'] || !preg_match('/@acceptance\\.test$/D',$email->getAddress()) || $user->getIsSystemAgent() || $user->getIsMailingList()){throw new Exception('Unsafe synthetic actor');}
if(${admin?'true':'false'} && ($user->getIsDisabled() || !$user->getIsApproved())){throw new Exception('Synthetic actor is not eligible for promotion');}
$configs=id(new PhabricatorAuthProviderConfigQuery())->setViewer($viewer)->withProviderClasses(array('PhabricatorTraefikAuthProvider'))->withIsEnabled(true)->execute();
if(count($configs)!==1){throw new Exception('Ambiguous synthetic provider');}
$accounts=id(new PhabricatorExternalAccountQuery())->setViewer($viewer)->withProviderConfigPHIDs(array(head($configs)->getPHID()))->withUserPHIDs(array($user->getPHID()))->needAccountIdentifiers(true)->execute();
if(count($accounts)!==1){throw new Exception('Ambiguous synthetic binding');}
$ids=head($accounts)->getAccountIdentifiers();
if(count($ids)!==1 || head($ids)->getIdentifierRaw()!==$spec['principal']){throw new Exception('Different synthetic binding');}
$guard=AphrontWriteGuard::beginScopedUnguardedWrites();
$user->setIsAdmin(${admin?'1':'0'})->save();
unset($guard);
echo json_encode(array('admin'=>(bool)$user->getIsAdmin()))."\\n";
`;
  const result=spawnSync(path.join(root,'scripts/compose.sh'),['exec','-T','phorge','php'],{cwd:root,input:source,encoding:'utf8',timeout:30000,maxBuffer:1024*1024});
  if(result.status!==0)throw new Error('Synthetic role transition failed');
  let data;try{data=JSON.parse(result.stdout);}catch{throw new Error('Synthetic role response unavailable');}
  if(data.admin!==admin)throw new Error('Synthetic role verification failed');
}
async function identity(page,admin) {
  const response=await page.goto(origin+'/settings/',{waitUntil:'domcontentloaded'});
  if(response.status()!==200 || !new URL(page.url()).pathname.startsWith('/settings/'))throw new Error('Synthetic browser session unavailable');
  const csrf=await page.locator('input[name="__csrf__"]').first().inputValue();
  const result=await context.request.post(origin+'/api/user.whoami',{form:{params:'{}',output:'json',__csrf__:csrf}});
  const data=await result.json();
  return result.status()===200 && !data.error_code && data.result?.phid===actor.phid &&
    data.result?.userName===actor.username && data.result?.roles?.includes('approved') &&
    !data.result?.roles?.includes('disabled') && !!data.result?.roles?.includes('admin')===admin;
}
async function cooldown(response) {
  let remaining=(Math.min(120,Number(response.headers()['retry-after'])||61)+1)*1000;
  while(remaining>0){const delay=Math.min(30000,remaining);await new Promise(resolve=>setTimeout(resolve,delay));remaining-=delay;}
}
async function loginSameContext(page,password) {
  for(let attempt=0;attempt<3;attempt++) {
    await page.goto(origin+'/_login',{waitUntil:'domcontentloaded'});
    await page.locator('#password_identifier').fill(actor.email);
    await page.locator('#personal_password').fill(password);
    const pending=page.waitForResponse(r=>new URL(r.url()).pathname==='/_login'&&r.request().method()==='POST');
    await page.locator('#personalPasswordForm button[type="submit"]').click();
    const response=await pending;
    if(response.status()===429){await cooldown(response);continue;}
    if(response.status()!==200)throw new Error('Synthetic new password login rejected');
    await page.waitForURL(url=>url.origin===origin&&url.pathname!=='/_login');
    const native=await page.goto(origin+'/auth/login/traefik:traefik/',{waitUntil:'domcontentloaded'});
    if(native.status()===409)throw new Error('Stale native cookie conflicted with new entry session');
    return;
  }
  throw new Error('Synthetic login rate window exhausted');
}

try {
  if(!process.argv.includes('--run'))throw new Error('Explicit --run is required after the main lifecycle completes');
  const lifecycle=JSON.parse(fs.readFileSync(path.join(root,'state/acceptance/maintenance-lifecycle.json'),'utf8'));
  if(lifecycle.passed!==true || !Array.isArray(lifecycle.checks) || !lifecycle.checks.length || lifecycle.checks.some(c=>c.passed!==true))throw new Error('Primary lifecycle has not passed');
  fixture=readPrivate(privatePath);
  const candidates=fixture.actors?.filter(value=>value.key==='c');
  if(candidates?.length!==1)throw new Error('Synthetic actor C is not unique');
  actor=candidates[0];
  if(!safeActor(actor))throw new Error('Invalid synthetic actor C');
  const security=readPrivate(path.join(folder,'security-fixtures.json'));
  if(security.origin!==origin || security.staleAdmin?.phid!==actor.phid || security.staleAdmin?.username!==actor.username || security.staleAdmin?.principal!==actor.principal || security.staleAdminState!=='state/acceptance/maintenance/stale-admin.json')throw new Error('Security handoff does not identify the same actor C');
  const state=readPrivate(statePath);
  check('successful lifecycle and private handoff identify only dedicated synthetic C',true);
  browser=await chromium.launch({headless:true});
  context=await browser.newContext({ignoreHTTPSErrors:true,storageState:state});
  context.setDefaultTimeout(45000);context.setDefaultNavigationTimeout(120000);
  const page=await context.newPage();
  step='ordinary C identity';
  check('existing synthetic C session retains its original ordinary native identity',await identity(page,false));
  const before=await context.cookies(origin);
  check('synthetic session initially has native and Stargate cookies',cookieNames.every(name=>before.some(cookie=>cookie.name===name&&cookie.value)));
  step='strictly scoped fixture promotion';
  promotionAttempted=true;
  setSyntheticAdmin(true);
  check('strict fixture-only promotion grants the same native identity an administrator role',await identity(page,true));
  const overview=await page.goto(origin+'/maintenance/',{waitUntil:'domcontentloaded'});
  check('new synthetic administrator can access maintenance in its existing browser session',overview.status()===200);

  step='administrator self password reset';
  const password='  SelfReset-'+randomBytes(20).toString('base64url')+'-新密钥🔐  ';
  actor.nextPassword=password;savePrivate(privatePath,fixture);
  const form=await page.goto(origin+'/maintenance/user/password/?id='+encodeURIComponent(actor.principal),{waitUntil:'domcontentloaded'});
  check('synthetic administrator can open its own password form',form.status()===200&&await page.locator('#maintenance-action-form').count()===1);
  await page.locator('[name="password"]').fill(password);
  await page.locator('[name="password_confirm"]').fill(password);
  await page.locator('[name="reason"]').fill('maintenance-admin-self-reset-'+fixture.stamp);
  await page.locator('#maintenance-confirm').check();
  const pending=page.waitForResponse(r=>new URL(r.url()).pathname==='/maintenance/user/password/'&&r.request().method()==='POST');
  await page.locator('#maintenance-action-form button[type="submit"]').click();
  const changed=await pending;
  check('administrator self-reset returns HTTP 303 directly to the login entry',changed.status()===303&&new URL(changed.headers().location||'/',origin).pathname==='/_login');
  // Persist the now-live password before further assertions so a failed browser
  // assertion cannot leave the synthetic account's new credential unavailable.
  actor.currentPassword=password;delete actor.nextPassword;savePrivate(privatePath,fixture);
  await page.waitForURL(url=>url.origin===origin&&url.pathname==='/_login');
  await page.waitForLoadState('domcontentloaded');
  const cleared=await context.cookies(origin);
  check('self-reset clears phusr, phsid and Stargate from the same browser',cookieNames.every(name=>!cleared.some(cookie=>cookie.name===name&&cookie.value)));
  check('redirected login form does not retain the submitted password',(await page.locator('#personal_password').inputValue())==='');

  step='same-browser login with new password';
  let conflicts=0;
  const onResponse=response=>{if(new URL(response.url()).origin===origin&&response.status()===409)conflicts++;};
  context.on('response',onResponse);
  await loginSameContext(page,password);
  check('new Unicode password with outer spaces logs into the original administrator PHID',await identity(page,true));
  const reopened=await page.goto(origin+'/maintenance/',{waitUntil:'domcontentloaded'});
  check('same browser regains maintenance access without a stale-cookie HTTP 409',reopened.status()===200&&conflicts===0);
  context.off('response',onResponse);
  const renewed=await context.cookies(origin);
  check('new login restores identity cookies with fresh native and Stargate sessions',cookieNames.every(name=>{
    const current=renewed.find(cookie=>cookie.name===name),previous=before.find(cookie=>cookie.name===name);
    return current?.value && (name==='phusr'||current.value!==previous?.value);
  }));
  savePrivate(statePath,await context.storageState());
  actor.selfResetDone=true;savePrivate(privatePath,fixture);
  check('latest private C session and password are saved for the stale-admin security test',!(fs.statSync(statePath).mode&0o077)&&!(fs.statSync(privatePath).mode&0o077));
  succeeded=true;
  report.handoff={state:'state/acceptance/maintenance/stale-admin.json',temporarySyntheticAdminRetained:true,nextAction:'Security matrix must demote synthetic C and verify old-cookie rejection.'};
} catch(error) {
  // Never log Playwright diagnostics, request payloads, PHP stdout/stderr,
  // passwords, or browser cookies, even when an assertion fails.
  report.error={step,type:error?.name||'Error'};
} finally {
  if(promotionAttempted&&!succeeded) {
    try{setSyntheticAdmin(false);report.cleanupDemotedSyntheticAdmin=true;}
    catch{report.cleanupDemotedSyntheticAdmin=false;report.cleanupRequired=true;}
  }
  if(context)await context.close().catch(()=>{});
  if(browser)await browser.close().catch(()=>{});
  report.completedAt=new Date().toISOString();
  report.passed=succeeded&&!report.error&&report.checks.length>0&&report.checks.every(value=>value.passed);
  savePrivate(reportPath,report);
  console.log(JSON.stringify({passed:report.passed,checks:report.checks.length,error:report.error,cleanupRequired:report.cleanupRequired||false}));
  if(!report.passed)process.exitCode=1;
}
