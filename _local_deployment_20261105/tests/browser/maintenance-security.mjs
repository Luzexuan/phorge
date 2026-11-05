import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomBytes,createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {chromium} from 'playwright';

// Explicit, deployment-only acceptance. The parent supplies dedicated synthetic
// sessions. This never changes the real siteadmin password or directory entry.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const fixtureFlag=process.argv.indexOf('--fixtures');
const fixtureFile=path.resolve(root,fixtureFlag>=0?process.argv[fixtureFlag+1]:'state/acceptance/maintenance/security-fixtures.json');
const output=path.join(root,'state/acceptance/maintenance-security-browser.json');
const report={verifiedAt:new Date().toISOString(),checks:[],scope:'Native maintenance authorization, CSRF, same-origin, secret handling, dedicated stale-admin and mixed-session rejection. Synthetic fixtures only.'};
const contexts=[];
let browser,fixture,stage='preflight',enabled=false,demoted=false;
const randomID=()=>randomBytes(16).toString('hex');
const sensitivePassword='  Maintenance-'+randomBytes(18).toString('base64url')+'-密碼  ';
function check(name,passed,detail) {
  report.checks.push({name,passed:!!passed,...(detail?{detail}:{})});
  console.log((passed?'PASS ':'FAIL ')+name);
  if(!passed)throw new Error('Acceptance check failed');
}
const hashFile=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function syntheticCredentialFingerprint(actor) {
  if(!safeFixture(actor))throw new Error('Unsafe credential snapshot target');
  const passwords=JSON.parse(fs.readFileSync(path.join(root,'config/passwords/users.json'),'utf8'));
  const entry=passwords.users?.[actor.principal];
  if(!entry || typeof entry.password_hash!=='string' || typeof entry.revision!=='string')throw new Error('Synthetic target lacks a password record');
  // Only the dedicated target is digested; never emit credential records or
  // their fingerprints to reports or the tool output.
  return createHash('sha256').update(JSON.stringify(entry)).digest('hex');
}
function stateFile(value) {
  const file=path.resolve(root,value);
  if(!file.startsWith(path.join(root,'state/acceptance/maintenance')+path.sep))throw new Error('Session fixture outside private acceptance directory');
  const info=fs.lstatSync(file);
  if(!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077))throw new Error('Session fixture is not private');
  return file;
}
function safeFixture(actor) {
  return actor && /^reg-[a-f0-9-]{36}$/.test(actor.principal) &&
    typeof actor.username==='string' && !['siteadmin','test_admin','admin','root'].includes(actor.username) &&
    /^PHID-USER-[a-zA-Z0-9]{20}$/.test(actor.phid);
}
async function context(state) {
  const ctx=await browser.newContext({ignoreHTTPSErrors:true,...(state?{storageState:stateFile(state)}:{})});
  contexts.push(ctx);return ctx;
}
function noSecret(body) {
  return !body.includes(sensitivePassword) && !/scrypt\$32768\$8\$3\$[a-f0-9]{32}\$[a-f0-9]{64}/.test(body);
}
async function maintenanceDenied(response) {
  const body=await response.text();
  // Phorge's application policy check runs before our controller and renders
  // its native restricted-application dialog with HTTP 200 in this version.
  // Require that exact denial, and no maintenance rows/form or secret echo.
  const policyDialog=response.status()===200 && /<title>(?:You Shall Not Pass|Access Denied): Restricted Application<\/title>/.test(body);
  return ([403,404].includes(response.status()) || policyDialog) && noSecret(body) &&
    !/data-maintenance-(?:user|registration|audit)-id=|id="maintenance-action-form"/.test(body);
}
function auditPosition() {
  const source="import sqlite3,json; c=sqlite3.connect('file:state/maintenance/maintenance.sqlite3?mode=ro',uri=True); print(json.dumps(c.execute('SELECT COUNT(*),COALESCE(MAX(id),0) FROM audit').fetchone())); c.close()";
  const result=spawnSync('python3',['-c',source],{cwd:root,encoding:'utf8',timeout:10000,maxBuffer:1024});
  if(result.status!==0)throw new Error('Audit boundary snapshot is unavailable');
  return JSON.stringify(JSON.parse(result.stdout));
}
function loginRedirect(response) {
  return [302,303,307,308].includes(response.status()) &&
    new URL(response.headers().location || '/',fixture.origin).pathname==='/_login';
}
async function identity(ctx,expected,admin) {
  const page=await ctx.newPage();
  try {
    const response=await page.goto(fixture.origin+'/settings/',{waitUntil:'domcontentloaded'});
    if(response.status()!==200 || !new URL(page.url()).pathname.startsWith('/settings/'))throw new Error('Supplied session is not usable');
    const csrf=await page.locator('input[name="__csrf__"]').first().inputValue();
    const who=await ctx.request.post(fixture.origin+'/api/user.whoami',{form:{params:'{}',output:'json',__csrf__:csrf}});
    const data=await who.json();
    const passed=who.status()===200 && !data.error_code && data.result?.userName===expected.username &&
      (!expected.phid || data.result?.phid===expected.phid) && data.result?.roles?.includes('approved') &&
      !data.result?.roles?.includes('disabled') && (!!data.result?.roles?.includes('admin')===admin);
    if(!passed)throw new Error('Supplied session has a different native identity');
    return {csrf,phid:data.result.phid};
  } finally {await page.close();}
}
async function userState(ctx,principal) {
  const page=await ctx.newPage();
  try {
    const response=await page.goto(fixture.origin+'/maintenance/users/?q='+encodeURIComponent(principal),{waitUntil:'domcontentloaded'});
    if(response.status()!==200)throw new Error('Unable to inspect target state');
    const marker=page.locator('span[data-maintenance-user-id="'+principal+'"]');
    if(await marker.count()!==1)throw new Error('Target state is ambiguous');
    return await marker.evaluate(element=>({entry:element.getAttribute('data-maintenance-entry-status'),disabled:element.getAttribute('data-maintenance-native-disabled'),password:element.getAttribute('data-maintenance-has-password')}));
  } finally {await page.close();}
}
function actionPath(action,target) {
  return '/maintenance/'+action+'/?id='+encodeURIComponent(target);
}
function form(action,csrf) {
  const common={__form__:'1',__csrf__:csrf,request_id:randomID(),confirm:'1'};
  if(action==='registration/approve')return {...common,note:'Synthetic denied-request security check'};
  if(action==='registration/reject')return {...common,reason:'Synthetic denied-request security check'};
  if(action==='user/status')return {...common,new_status:'inactive',reason:'Synthetic denied-request security check'};
  return {...common,password:sensitivePassword,password_confirm:sensitivePassword,reason:'Synthetic denied-request security check'};
}
async function post(ctx,url,data,headers={}) {
  return ctx.request.post(fixture.origin+url,{maxRedirects:0,form:data,headers:{Origin:fixture.origin,'Sec-Fetch-Site':'same-origin',...headers}});
}
function demoteFixture() {
  if(!enabled || !fixture?.staleAdmin || !safeFixture(fixture.staleAdmin))throw new Error('Unsafe stale-admin fixture');
  const encoded=Buffer.from(JSON.stringify(fixture.staleAdmin)).toString('base64');
  const source=`<?php
require '/opt/phorge/phorge/scripts/__init_script__.php';
$spec=json_decode(base64_decode('${encoded}'),true);
$viewer=PhabricatorUser::getOmnipotentUser();
$user=id(new PhabricatorPeopleQuery())->setViewer($viewer)->withPHIDs(array($spec['phid']))->executeOne();
$email=$user?id(new PhabricatorUserEmail())->loadOneWhere('userPHID = %s AND isPrimary = 1',$user->getPHID()):null;
if(!$user || $user->getUsername()!==$spec['username'] || in_array($user->getUsername(),array('siteadmin','test_admin','admin','root')) || !$email || !preg_match('/@acceptance\\.test$/D',$email->getAddress()) || $user->getIsSystemAgent() || $user->getIsMailingList()){throw new Exception('Unsafe synthetic actor');}
$config=id(new PhabricatorAuthProviderConfigQuery())->setViewer($viewer)->withProviderClasses(array('PhabricatorTraefikAuthProvider'))->withIsEnabled(true)->executeOne();
$accounts=id(new PhabricatorExternalAccountQuery())->setViewer($viewer)->withProviderConfigPHIDs(array($config->getPHID()))->withUserPHIDs(array($user->getPHID()))->needAccountIdentifiers(true)->execute();
if(count($accounts)!==1){throw new Exception('Ambiguous synthetic binding');}
$ids=head($accounts)->getAccountIdentifiers();
if(count($ids)!==1 || head($ids)->getIdentifierRaw()!==$spec['principal']){throw new Exception('Different synthetic binding');}
$guard=AphrontWriteGuard::beginScopedUnguardedWrites();
$user->setIsAdmin(0)->save();
unset($guard);
echo json_encode(array('demoted'=>!$user->getIsAdmin()))."\\n";
`;
  const result=spawnSync(path.join(root,'scripts/compose.sh'),['exec','-T','phorge','php'],{cwd:root,input:source,encoding:'utf8',timeout:30000,maxBuffer:1024*1024});
  if(result.status!==0 || JSON.parse(result.stdout).demoted!==true)throw new Error('Synthetic actor demotion failed');
  demoted=true;
}

try {
  if(!process.argv.includes('--run'))throw new Error('Explicit --run is required after deployment and fixture approval');
  fixture=JSON.parse(fs.readFileSync(fixtureFile,'utf8'));
  if(fixture.origin!=='https://45.77.36.106' || !safeFixture(fixture.ordinary) || !safeFixture(fixture.other) || !/^[a-f0-9-]{36}$/.test(fixture.registrationId))throw new Error('Invalid dedicated fixture metadata');
  if(fixture.staleAdmin && !safeFixture(fixture.staleAdmin))throw new Error('Invalid stale administrator fixture');
  enabled=true;
  stage='private service boundary';
  const inspection=spawnSync('docker',['inspect','team-management-maintenance-1'],{cwd:root,encoding:'utf8',timeout:10000,maxBuffer:1024*1024});
  if(inspection.status!==0)throw new Error('Maintenance container is unavailable');
  const container=JSON.parse(inspection.stdout)[0];
  check('maintenance service has no published host port',Object.keys(container.HostConfig.PortBindings || {}).length===0);
  check('maintenance runs as the dedicated unprivileged user with a read-only root filesystem',container.Config.User==='10001:10001' && container.HostConfig.ReadonlyRootfs===true && container.HostConfig.Privileged===false);
  check('maintenance has no Docker socket or host root mount',container.Mounts.every(m=>!m.Source.endsWith('/docker.sock') && m.Source!=='/'));
  check('maintenance drops Linux capabilities and blocks privilege escalation',(container.HostConfig.CapDrop || []).includes('ALL') && (container.HostConfig.SecurityOpt || []).includes('no-new-privileges:true'));
  const networks=container.NetworkSettings.Networks;
  const privateNetwork=Object.entries(networks).find(([name])=>name.endsWith('_maintenance'))?.[1];
  const coreNetwork=Object.entries(networks).find(([name])=>name.endsWith('_core'))?.[1];
  if(!privateNetwork?.IPAddress || !coreNetwork?.IPAddress)throw new Error('Expected private networks are unavailable');
  let reachableOnCore=false;
  try {await fetch('http://'+coreNetwork.IPAddress+':8086/healthz',{signal:AbortSignal.timeout(3000)});reachableOnCore=true;}catch{}
  check('maintenance RPC listener is unavailable on its database network interface',!reachableOnCore);
  const unsigned=await fetch('http://'+privateNetwork.IPAddress+':8086/rpc',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"action":"overview"}',signal:AbortSignal.timeout(3000)});
  check('private maintenance RPC rejects an unsigned request from a non-Phorge peer',unsigned.status===403);
  browser=await chromium.launch({headless:true});
  const originalFiles=[fixture.adminState,fixture.ordinaryState,fixture.otherState,fixture.staleAdminState].filter(Boolean).map(value=>{const file=stateFile(value);return {file,digest:hashFile(file)};});
  const admin=await context(fixture.adminState);
  const ordinary=await context(fixture.ordinaryState);
  const other=await context(fixture.otherState);
  const anonymous=await context();
  const adminIdentity=await identity(admin,{username:'siteadmin'},true);
  const ordinaryIdentity=await identity(ordinary,fixture.ordinary,false);
  await identity(other,fixture.other,false);
  check('provided sessions retain their expected native administrator and ordinary identities',true);
  const beforeA=await userState(admin,fixture.ordinary.principal);
  const beforeB=await userState(admin,fixture.other.principal);
  const credentialA=syntheticCredentialFingerprint(fixture.ordinary);
  const credentialB=syntheticCredentialFingerprint(fixture.other);
  const pages=['/maintenance/','/maintenance/registrations/','/maintenance/users/','/maintenance/audit/'];
  stage='administrator read access';
  for(const route of pages) {
    const response=await admin.request.get(fixture.origin+route,{maxRedirects:0});
    const body=await response.text();
    check('administrator can open '+route,response.status()===200);
    check('maintenance page prevents shared caching and retains no credential material '+route,
      /no-store/.test(response.headers()['cache-control'] || '') && noSecret(body));
    check('maintenance page retains framing and CSP protections with a usable same-origin form policy '+route,
      (response.headers()['x-frame-options'] || '').toLowerCase()==='deny' &&
      !!response.headers()['content-security-policy'] && response.headers()['referrer-policy']==='same-origin');
  }
  stage='anonymous and ordinary authorization';
  const auditBeforeOrdinary=auditPosition();
  const actions=[['registration/approve',fixture.registrationId],['registration/reject',fixture.registrationId],['user/status',fixture.other.principal],['user/password',fixture.other.principal]];
  for(const route of [...pages,...actions.map(([action,target])=>actionPath(action,target))]) {
    const unauth=await anonymous.request.get(fixture.origin+route,{maxRedirects:0});
    check('anonymous visitor cannot read '+route.split('?')[0],loginRedirect(unauth));
    const member=await ordinary.request.get(fixture.origin+route,{maxRedirects:0});
    check('ordinary member cannot read '+route.split('?')[0],await maintenanceDenied(member));
  }
  for(const [action,target] of actions) {
    const url=actionPath(action,target);
    const payload={...form(action,ordinaryIdentity.csrf),actor_phid:adminIdentity.phid,actor_principal:'linkerbot-site-admin',approved_by:'siteadmin'};
    const response=await post(ordinary,url,payload);
    check('ordinary member with valid CSRF and forged actor fields cannot execute '+action,await maintenanceDenied(response));
  }
  const forged=await ordinary.request.get(fixture.origin+'/maintenance/',{maxRedirects:0,headers:{'X-Auth-User':'linkerbot-site-admin','X-Auth-Email':'177000177@qq.com','X-Auth-Role':'admin','X-Forwarded-User':'siteadmin'}});
  check('forged public identity and role headers do not grant maintenance access',await maintenanceDenied(forged));
  const alias=await ordinary.request.get(fixture.origin+'/?__path__=/maintenance/users/',{maxRedirects:0});
  check('rewritten maintenance path retains ordinary-user authorization checks',await maintenanceDenied(alias));
  check('ordinary-user attempts never reach a maintenance mutation intent',auditPosition()===auditBeforeOrdinary);
  stage='CSRF and same-origin boundaries';
  for(const [action,target] of actions) {
    const url=actionPath(action,target);
    const missing=form(action,adminIdentity.csrf);delete missing.__csrf__;
    const noToken=await post(admin,url,missing);
    check('missing CSRF rejects '+action,[400,403].includes(noToken.status()));
    const wrong=await post(admin,url,form(action,ordinaryIdentity.csrf));
    check('another user CSRF rejects '+action,[400,403].includes(wrong.status()));
  }
  const passwordURL=actionPath('user/password',fixture.other.principal);
  for(const [label,headers] of [
    ['foreign origin',{Origin:'https://example.invalid','Sec-Fetch-Site':'cross-site'}],
    ['null origin',{Origin:'null'}],
    ['cross-site fetch metadata',{Origin:fixture.origin,'Sec-Fetch-Site':'cross-site'}],
  ]) {
    const response=await post(admin,passwordURL,form('user/password',adminIdentity.csrf),headers);
    check('valid CSRF does not bypass '+label,response.status()===403);
    check('rejected '+label+' does not echo a submitted password',noSecret(await response.text()));
  }
  const withoutOrigin=await admin.request.post(fixture.origin+passwordURL,{maxRedirects:0,form:form('user/password',adminIdentity.csrf)});
  check('missing Origin rejects a maintenance mutation',withoutOrigin.status()===403);
  const unsupported=await admin.request.put(fixture.origin+passwordURL,{maxRedirects:0,headers:{Origin:fixture.origin}});
  check('unsupported mutation method is rejected',unsupported.status()===405);
  const json=await admin.request.post(fixture.origin+passwordURL,{maxRedirects:0,headers:{Origin:fixture.origin,'Content-Type':'application/json'},data:JSON.stringify(form('user/password',adminIdentity.csrf))});
  check('raw JSON cannot bypass the native form CSRF boundary',[400,403].includes(json.status()));
  const invalidID=form('user/password',adminIdentity.csrf);invalidID.request_id='../../invalid-operation';
  const malformed=await post(admin,passwordURL,invalidID);
  check('malformed operation identifier is rejected',[400,409].includes(malformed.status()));
  const notConfirmed=form('user/password',adminIdentity.csrf);delete notConfirmed.confirm;
  const confirmation=await post(admin,passwordURL,notConfirmed);
  check('password change requires explicit form confirmation',confirmation.status()===400 && noSecret(await confirmation.text()));
  const getMutation=await admin.request.get(fixture.origin+actionPath('user/status',fixture.ordinary.principal)+'&new_status=inactive&confirm=1&request_id='+randomID(),{maxRedirects:0});
  check('GET status request only displays a confirmation form',getMutation.status()===200 && (await getMutation.text()).includes('maintenance-action-form'));
  check('denied requests and GET requests preserve the ordinary A directory and native state',JSON.stringify(await userState(admin,fixture.ordinary.principal))===JSON.stringify(beforeA));
  check('denied requests preserve the ordinary B directory and native state',JSON.stringify(await userState(admin,fixture.other.principal))===JSON.stringify(beforeB));
  check('denied requests preserve both synthetic password hashes and session revisions',syntheticCredentialFingerprint(fixture.ordinary)===credentialA && syntheticCredentialFingerprint(fixture.other)===credentialB);

  stage='stale native administrator';
  if(fixture.staleAdmin && fixture.staleAdminState) {
    const stale=await context(fixture.staleAdminState);
    const identified=await identity(stale,fixture.staleAdmin,true);
    const before=await stale.request.get(fixture.origin+'/maintenance/',{maxRedirects:0});
    check('dedicated temporary administrator initially has maintenance access',before.status()===200);
    const selfBefore=await userState(admin,fixture.staleAdmin.principal);
    const self=await post(stale,actionPath('user/status',fixture.staleAdmin.principal),form('user/status',identified.csrf));
    check('an administrator cannot disable their own account',[400,409].includes(self.status()) && JSON.stringify(await userState(admin,fixture.staleAdmin.principal))===JSON.stringify(selfBefore));
    demoteFixture();
    check('dedicated temporary administrator was returned to an ordinary native role',demoted);
    const oldCookie=await stale.request.get(fixture.origin+'/maintenance/',{maxRedirects:0});
    check('previously authorized administrator cookie loses maintenance read access after demotion',await maintenanceDenied(oldCookie));
    const oldPost=await post(stale,passwordURL,form('user/password',identified.csrf));
    check('old administrator cookie and CSRF cannot mutate after demotion',await maintenanceDenied(oldPost));
  } else {
    report.limitations=['No dedicated elevated synthetic actor was supplied; real HTTP stale-admin demotion was not exercised.'];
  }
  stage='mixed native and entry identities';
  const mixed=await browser.newContext({ignoreHTTPSErrors:true,storageState:stateFile(fixture.ordinaryState)});contexts.push(mixed);
  const bEntry=(await other.cookies(fixture.origin)).find(cookie=>cookie.name==='stargate_session_id');
  if(!bEntry)throw new Error('Other actor lacks an entry cookie');
  await mixed.addCookies([bEntry]);
  const denied=await mixed.request.get(fixture.origin+'/maintenance/',{maxRedirects:0});
  check('mixed entry and native identities are rejected before maintenance controllers',denied.status()===409);
  await identity(other,fixture.other,false);
  check('mixed-session denial does not change the other ordinary actor identity',true);
  check('stale-administrator and mixed-session probes preserve both synthetic credentials',syntheticCredentialFingerprint(fixture.ordinary)===credentialA && syntheticCredentialFingerprint(fixture.other)===credentialB);
  check('security run never overwrites supplied private browser session files',originalFiles.every(({file,digest})=>hashFile(file)===digest));
} catch(error) {
  // Playwright exception strings can include submitted values, cookies or URLs.
  report.error={stage,type:error?.name || 'Error'};
} finally {
  if(enabled && fixture?.staleAdmin && !demoted) {
    try {demoteFixture();report.cleanupDemotedSyntheticAdmin=true;}
    catch {report.cleanupError='Synthetic administrator role could not be removed';}
  }
  for(const ctx of contexts)await ctx.close().catch(()=>{});
  if(browser)await browser.close();
  report.completedAt=new Date().toISOString();
  report.passed=!report.error && !report.cleanupError && report.checks.length>0 && report.checks.every(check=>check.passed);
  if(enabled)fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n',{mode:0o600});
  console.log(JSON.stringify({passed:report.passed,checks:report.checks.length,error:report.error,cleanupError:report.cleanupError}));
  if(!report.passed)process.exitCode=1;
}
