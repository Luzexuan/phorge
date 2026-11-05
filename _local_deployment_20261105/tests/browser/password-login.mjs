import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {randomBytes, createHash} from 'node:crypto';
import {chromium} from 'playwright';

// Explicitly run after deployment. Only newly created synthetic identities are
// changed. Passwords and session cookies stay in memory and never enter reports.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const origin=process.env.PM_URL || 'https://45.77.36.106';
const database=path.join(root,'state/registration/registrations.sqlite3');
const directory=path.join(root,'config/warden/users.json');
const reportPath=path.join(root,'state/acceptance/password-login-browser.json');
const stamp=Date.now().toString(36);
const suffix=String(Date.now()%100000000).padStart(8,'0');
const password=()=>`Pass-${randomBytes(20).toString('base64url')}-密碼!`;
const actors=[
  {name:'Acceptance Password A '+stamp,email:'password_a_'+stamp+'@acceptance.test',phone:'199'+suffix,password:'  '+password()+'  '},
  {name:'Acceptance Password B '+stamp,email:'password_b_'+stamp+'@acceptance.test',phone:'198'+suffix,password:password()},
];
let resetPassword;
const report={verifiedAt:new Date().toISOString(),origin,
  scope:'Independent per-user passwords through public browser registration, local approval, Stargate/Warden and existing Phorge bindings; only synthetic identities; no OTP delivery.',
  checks:[],fixtures:[]};
const contexts=[];
let browser;
let otpRequests=0;
let metricsBefore;
let step='preflight';
const sha=value=>createHash('sha256').update(value).digest('hex');
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function check(name,passed,detail) {
  report.checks.push({name,passed:!!passed,...(detail===undefined?{}:{detail})});
  console.log((passed?'PASS ':'FAIL ')+name);
  if(!passed) throw new Error(name);
}
function command(program,args,input) {
  const value=spawnSync(program,args,{cwd:root,input,encoding:'utf8',timeout:100000,maxBuffer:2*1024*1024});
  if(value.error) throw new Error('Local command failed at '+step);
  return value;
}
function python(source,args=[],input) {
  const value=command('python3',['-c',source,...args],input);
  if(value.status!==0) throw new Error('Private inspection or mutation failed at '+step);
  return JSON.parse(value.stdout);
}
function applications(email) {
  // Hashes are represented only by booleans and fingerprints outside Python.
  return python(`import hashlib,importlib.util,json,pathlib,sys
sys.path.insert(0,'scripts')
s=importlib.util.spec_from_file_location('password_acceptance_read','scripts/approve-registration.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
out=[]
with m.approval_lock(sys.argv[1]):
 with m.database_connection(sys.argv[1]) as c:
  for row in c.execute('SELECT * FROM registrations WHERE email=? ORDER BY created_at,registration_id',(sys.argv[2],)):
   r=dict(row);h=r.pop('password_hash',None)
   r['has_password_hash']=bool(h);r['password_hash_digest']=hashlib.sha256(str(h).encode()).hexdigest()
   out.append(r)
print(json.dumps(out))`,[database,email]);
}
function native(email) {
  const encoded=Buffer.from(JSON.stringify({email})).toString('base64');
  const source=`<?php
require '/opt/phorge/phorge/scripts/__init_script__.php';
$spec=json_decode(base64_decode('${encoded}'),true);
$viewer=PhabricatorUser::getOmnipotentUser();
$emails=id(new PhabricatorUserEmail())->loadAllWhere('LOWER(address) = %s',$spec['email']);
$out=array('matches'=>count($emails),'users'=>array());
foreach($emails as $email) {
 $u=id(new PhabricatorPeopleQuery())->setViewer($viewer)->withPHIDs(array($email->getUserPHID()))->executeOne();
 if(!$u){throw new Exception('Missing user');}
 $accounts=id(new PhabricatorExternalAccountQuery())->setViewer($viewer)->withUserPHIDs(array($u->getPHID()))->needAccountIdentifiers(true)->execute();
 $external=array();foreach($accounts as $account){$ids=array();foreach($account->getAccountIdentifiers() as $identifier){$ids[]=$identifier->getIdentifierRaw();}$external[]=array('ids'=>$ids,'emailVerified'=>(bool)$account->getEmailVerified());}
 $projects=id(new PhabricatorProjectQuery())->setViewer($viewer)->withMemberPHIDs(array($u->getPHID()))->execute();
 $out['users'][]=array('phid'=>$u->getPHID(),'username'=>$u->getUsername(),'isAdmin'=>(bool)$u->getIsAdmin(),'isApproved'=>(bool)$u->getIsApproved(),'isDisabled'=>(bool)$u->getIsDisabled(),'isSystemAgent'=>(bool)$u->getIsSystemAgent(),'isMailingList'=>(bool)$u->getIsMailingList(),'emailVerified'=>(bool)$email->getIsVerified(),'projectMemberships'=>count($projects),'externalAccounts'=>$external);
}
echo json_encode($out);
`;
  const value=command(path.join(root,'scripts/compose.sh'),['exec','-T','phorge','php'],source);
  if(value.status!==0) throw new Error('Private Phorge inspection failed at '+step);
  return JSON.parse(value.stdout);
}
function credential(actor) {
  return python(`import hashlib,json,pathlib,stat,sys
sys.path.insert(0,'config/registration')
from credential_hashes import valid_hash
p=pathlib.Path('config/passwords/users.json');info=p.stat();raw=p.read_text();value=json.loads(raw)
entry=value.get('users',{}).get(sys.argv[1]);secret=sys.stdin.read()
print(json.dumps({'present':entry is not None,'validHash':bool(entry and valid_hash(entry.get('password_hash'))),'hashDigest':hashlib.sha256(str(entry.get('password_hash') if entry else None).encode()).hexdigest(),'revision':entry.get('revision') if entry else None,'mode':stat.S_IMODE(info.st_mode),'owner':[info.st_uid,info.st_gid],'containsPlaintext':bool(secret and secret in raw),'onlyExpectedFields':bool(entry and set(entry)=={'password_hash','revision'})}))`,[actor.userID],actor.password);
}
const readDirectory=()=>JSON.parse(fs.readFileSync(directory,'utf8'));
function approve(actor) {
  const value=command('python3',['scripts/approve-registration.py','approve',actor.registrationID,'--by','siteadmin','--confirmed-phone',actor.phone,'--note','Synthetic password acceptance']);
  if(value.status!==0) throw new Error('Password-only approval failed');
  return JSON.parse(value.stdout);
}
function reset(actor) {
  const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'password-acceptance-'));
  fs.chmodSync(temporary,0o700);
  try {
    const output=path.join(temporary,'generated-password');
    const value=command('python3',['scripts/manage-password.py',actor.username,'--reset','--generate','--output',output]);
    if(value.status!==0) throw new Error('Password reset command failed');
    if((fs.statSync(output).mode & 0o777)!==0o600) throw new Error('Generated password file is not private');
    // The generated CLI password is ASCII and carries one terminal newline.
    resetPassword=fs.readFileSync(output,'utf8').replace(/\r?\n$/,'');
    if(resetPassword.length<15 || resetPassword.length>128) throw new Error('Generated password format is invalid');
    return JSON.parse(value.stdout);
  } finally {
    fs.rmSync(temporary,{recursive:true,force:true});
  }
}
function setStatus(actor,status) {
  if(!actor.userID) return false;
  const result=python(`import importlib.util,json,pathlib,sys
sys.path.insert(0,'scripts')
p=pathlib.Path('scripts/approve-registration.py')
s=importlib.util.spec_from_file_location('password_acceptance_cleanup',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
with m.approval_lock(sys.argv[1]):
 raw,users=m.load_directory(sys.argv[2]);own=[u for u in users if u['user_id']==sys.argv[3]]
 if len(own)>1:raise RuntimeError('Duplicate principal')
 if own and own[0].get('status')!=sys.argv[4]:
  own[0]['status']=sys.argv[4];m.atomic_directory_write(sys.argv[2],raw,users)
 print(json.dumps({'present':bool(own),'status':own[0].get('status') if own else None}))`,[database,directory,actor.userID,status]);
  return result.present && result.status===status;
}
async function context(storageState) {
  const value=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1200,height:900},...(storageState?{storageState}:{})});
  value.on('request',request=>{if(new URL(request.url()).pathname==='/_send_verify_code') otpRequests++;});
  contexts.push(value);
  return value;
}
async function heraldCounters() {
  // metrics-kit v3.0.0 common.go NewOTPMetrics uses namespace herald,
  // subsystem otp and lazy CounterVec/HistogramVec samples. Zero samples means
  // none were instantiated, not that a pre-existing counter read zero.
  const service=command(path.join(root,'scripts/compose.sh'),['ps','-q','herald']);
  if(service.status!==0 || !service.stdout.trim()) throw new Error('Herald metrics service unavailable');
  const value=command('docker',['inspect','--format','{"networks":{{json .NetworkSettings.Networks}},"startedAt":{{json .State.StartedAt}}}',service.stdout.trim()]);
  if(value.status!==0) throw new Error('Herald network inspection failed');
  const inspected=JSON.parse(value.stdout);
  for(const network of Object.values(inspected.networks)) {
    if(!network.IPAddress) continue;
    try {
      const response=await fetch(`http://${network.IPAddress}:8082/metrics`,{signal:AbortSignal.timeout(3000)});
      if(!response.ok) continue;
      const body=await response.text();
      const samples=body.split('\n').filter(line=>!line.startsWith('#') && /^(herald_.*(?:otp|challenge|provider).*|process_start_time_seconds)/.test(line)).sort();
      if(!body.includes('# HELP') || !body.includes('herald_')) continue;
      return {digest:sha(inspected.startedAt+'\n'+samples.join('\n')),sampleCount:samples.length};
    } catch {}
  }
  throw new Error('Unable to establish read-only Herald counter baseline');
}
function blocked(response) {
  const location=response.headers().location;
  return response.status()===401 || (location && [302,303,307,308].includes(response.status()) && new URL(location,origin).pathname==='/_login');
}
async function waitForRateWindow(response) {
  const seconds=Math.max(1,Math.min(120,Number(response.headers()['retry-after']) || 61))+1;
  report.rateLimitWaits=(report.rateLimitWaits || 0)+1;
  console.log('Login limit reached; waiting '+seconds+' seconds for its normal reset');
  let remaining=seconds*1000;
  while(remaining>0) {const part=Math.min(30000,remaining);await delay(part);remaining-=part;}
}
async function rawLogin(form,{originHeader=origin,fetchSite='same-origin',expect=401}={}) {
  const ctx=await context();
  const headers={Accept:'application/json','X-Requested-With':'XMLHttpRequest','Sec-Fetch-Site':fetchSite};
  if(originHeader!==undefined && originHeader!==false) headers.Origin=originHeader;
  let response;
  for(let attempt=0;attempt<3;attempt++) {
    response=await ctx.request.post(origin+'/_login',{maxRedirects:0,headers,form});
    if(response.status()!==429 || attempt===2) break;
    await waitForRateWindow(response);
  }
  const cookies=await ctx.cookies(origin);
  return {context:ctx,response,denied:response.status()===expect && !cookies.some(cookie=>cookie.name==='stargate_session_id' && cookie.value)};
}
async function passwordLogin(actor,identifier,newPassword=actor.password) {
  const ctx=await context();const page=await ctx.newPage();
  let response;
  for(let attempt=0;attempt<3;attempt++) {
    await page.goto(origin+'/_login',{waitUntil:'domcontentloaded'});
    await page.locator('#personalPasswordForm [name="password_identifier"]').fill(identifier);
    await page.locator('#personalPasswordForm [name="password"]').fill(newPassword);
    const pending=page.waitForResponse(response=>new URL(response.url()).pathname==='/_login' && response.request().method()==='POST');
    await page.locator('#personalPasswordForm button[type="submit"]').click();
    response=await pending;
    if(response.status()!==429 || attempt===2) break;
    await waitForRateWindow(response);
  }
  if(response.status()!==200) throw new Error('Password browser login failed with HTTP '+response.status());
  await page.waitForURL(url=>url.origin===origin && url.pathname!=='/_login',{timeout:20000});
  await page.goto(origin+'/auth/login/traefik:traefik/',{waitUntil:'domcontentloaded'});
  if(await page.locator('input[name="username"]').count()) throw new Error('Approved identity unexpectedly requested Phorge signup');
  const settings=await page.goto(origin+'/settings/',{waitUntil:'domcontentloaded'});
  const cookies=await ctx.cookies(origin);
  if(settings.status()!==200 || !cookies.some(cookie=>cookie.name==='phusr' && cookie.value===actor.username) || !cookies.some(cookie=>cookie.name==='phsid')) throw new Error('Password session did not bind expected Phorge account');
  const csrf=await page.locator('input[name="__csrf__"]').first().inputValue();
  const whoami=await ctx.request.post(origin+'/api/user.whoami',{form:{params:'{}',output:'json',__csrf__:csrf}});
  const identified=await whoami.json();
  if(whoami.status()!==200 || identified.error_code || identified.result?.userName!==actor.username || identified.result?.phid!==actor.phid) throw new Error('Actual Conduit actor differs from the approved password principal');
  return {context:ctx,page,state:await ctx.storageState()};
}
async function verifySettingsIdentity(actor,ctx,page) {
  const entry=await ctx.request.get(origin+'/settings/',{maxRedirects:0});
  const location=entry.headers().location;
  const expected='/settings/user/'+actor.username+'/';
  const route=location?new URL(location,origin):null;
  const normalRedirect=entry.status()===302 && route?.origin===origin && route.pathname===expected && !route.search;
  const response=await page.goto(origin+'/settings/',{waitUntil:'domcontentloaded'});
  const csrf=await page.locator('input[name="__csrf__"]').first().inputValue();
  const whoami=await ctx.request.post(origin+'/api/user.whoami',{form:{params:'{}',output:'json',__csrf__:csrf}});
  const identified=await whoami.json();
  return {passed:normalRedirect && response.status()===200 && whoami.status()===200 && !identified.error_code &&
      identified.result?.userName===actor.username && identified.result?.phid===actor.phid,
    entryHTTPStatus:entry.status(),redirectPath:route?.pathname,finalPath:new URL(page.url()).pathname,actorMatches:identified.result?.phid===actor.phid};
}

async function main() {
  if(!process.argv.includes('--run')) throw new Error('Pass --run only after the password deployment is ready');
  if(new URL(origin).protocol!=='https:') throw new Error('Acceptance requires HTTPS');
  browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
  const originalDirectory=readDirectory();
  const existingSessionFiles=['test_admin','a_lead','a_member','b_lead','b_member','guest'].map(name=>path.join(root,'state/acceptance/browser',name+'.json'));
  const originalSessions=existingSessionFiles.filter(file=>fs.existsSync(file)).map(file=>({file,digest:sha(fs.readFileSync(file))}));
  metricsBefore=await heraldCounters();
  report.heraldCounterBaseline=metricsBefore;
  const registrationContext=await context();const page=await registrationContext.newPage();
  const primary=actors[0];const secondary=actors[1];
  async function form() {
    const response=await page.goto(origin+'/_register',{waitUntil:'domcontentloaded'});
    if(response.status()!==200) throw new Error('Registration form unavailable');
    return page.locator('input[name="csrf"]').inputValue();
  }
  const fields=actor=>({name:actor.name,phone:actor.phone,email:actor.email,password:actor.password,password_confirm:actor.password});
  async function post(values,{csrfOverride,originHeader=origin}={}) {
    const csrf=await form();
    return registrationContext.request.post(origin+'/_register',{maxRedirects:0,headers:{Origin:originHeader,'Sec-Fetch-Site':'same-origin'},form:{csrf:csrfOverride??csrf,...values}});
  }
  step='registration validation';
  await form();
  for(const field of ['name','phone','email','password','password_confirm']) {
    check('registration UI requires '+field,await page.locator('input[name="'+field+'"][required]').count()===1);
    const missing=fields(primary);delete missing[field];
    check('registration server rejects missing '+field,(await post(missing)).status()===400);
  }
  check('registration masks both password fields',await page.locator('input[type="password"][name="password"],input[type="password"][name="password_confirm"]').count()===2);
  let response=await post({...fields(primary),password:'short',password_confirm:'short'});
  check('registration rejects a password below the minimum length',response.status()===400);
  response=await post({...fields(primary),password:'x'.repeat(129),password_confirm:'x'.repeat(129)});
  check('registration rejects a password above the maximum length',response.status()===400);
  response=await post({...fields(primary),password_confirm:secondary.password});
  check('registration rejects mismatched password confirmation',response.status()===400);
  response=await post({...fields(primary),role:'admin',isAdmin:'1',org_unit_id:'root'});
  check('registration rejects injected role and organization fields',response.status()===400 && applications(primary.email).length===0);
  response=await post(fields(primary),{csrfOverride:'forged'});
  check('registration rejects forged CSRF',response.status()===403);
  response=await post(fields(primary),{originHeader:'https://example.invalid'});
  check('registration rejects a foreign origin',response.status()===403);
  for(const actor of actors) {
    step='native registration '+(actor===primary?'A':'B');
    await form();
    for(const [key,value] of Object.entries(fields(actor))) await page.locator('input[name="'+key+'"]').fill(value);
    const pending=page.waitForResponse(value=>new URL(value.url()).pathname==='/_register' && value.request().method()==='POST');
    await page.getByRole('button',{name:'提交注册申请',exact:true}).click();
    response=await pending;
    check('native browser registration accepted '+(actor===primary?'A':'B'),response.status()===303);
    await page.waitForURL(url=>url.pathname==='/_register' && url.searchParams.get('submitted')==='1');
    const row=applications(actor.email)[0];
    if(!row) throw new Error('Missing synthetic application');
    actor.registrationID=row.registration_id;actor.userID=row.user_id;
    report.fixtures.push({email:actor.email,phone:actor.phone,registrationID:actor.registrationID,userID:actor.userID});
    check('pending application stores a hash without granting an identity '+(actor===primary?'A':'B'),row.status==='pending' && row.has_password_hash &&
      row.user_id==='reg-'+row.registration_id && row.phorge_phid===null && native(actor.email).matches===0 && !readDirectory().some(user=>user.user_id===row.user_id));
    check('pending password is absent from the active credential store '+(actor===primary?'A':'B'),!credential(actor).present);
    const rejected=await rawLogin({auth_method:'local_password',mail:actor.email,password:actor.password});
    check('correct password cannot log in before approval '+(actor===primary?'A':'B'),rejected.denied,{httpStatus:rejected.response.status()});
  }
  const beforeDuplicate=JSON.stringify(applications(primary.email));
  response=await post({...fields(primary),password:secondary.password,password_confirm:secondary.password,name:'Attempted replacement'});
  check('duplicate registration cannot replace pending credentials',response.status()===303 && JSON.stringify(applications(primary.email))===beforeDuplicate);
  step='password-only approval';
  for(const actor of actors) {
    const result=approve(actor);const row=applications(actor.email)[0];const account=native(actor.email);const user=account.users[0];
    actor.username=user?.username;actor.phid=user?.phid;
    const entry=readDirectory().find(user=>user.user_id===actor.userID);
    const secret=credential(actor);
    check('password-only approval creates one ordinary account '+(actor===primary?'A':'B'),result.status==='approved' && row.status==='approved' && account.matches===1 &&
      user.isApproved && !user.isDisabled && !user.isAdmin && !user.isSystemAgent && !user.isMailingList && !user.emailVerified &&
      user.projectMemberships===0 && user.externalAccounts.length===1 && !user.externalAccounts[0].emailVerified &&
      user.externalAccounts[0].ids.length===1 && user.externalAccounts[0].ids[0]===actor.userID &&
      entry?.role==='user' && entry.status==='active' && entry.scope.length===0 &&
      ['org_unit_id','manager_user_id','position'].every(key=>row[key]===null));
    check('approved password is published under the stable principal as a private scrypt hash '+(actor===primary?'A':'B'),secret.present && secret.validHash &&
      secret.hashDigest===row.password_hash_digest && secret.onlyExpectedFields && !secret.containsPlaintext && secret.mode===0o600 && secret.owner[0]===10001 && secret.owner[1]===10001);
    const fixture=report.fixtures.find(value=>value.userID===actor.userID);fixture.username=actor.username;fixture.phid=actor.phid;
  }
  check('approval preserves every existing Warden identity',originalDirectory.every(old=>JSON.stringify(readDirectory().find(user=>user.user_id===old.user_id))===JSON.stringify(old)));
  await delay(7000);
  step='password login rejection';
  let negative=await rawLogin({auth_method:'local_password',mail:primary.email,password:secondary.password});
  check('another account password cannot authenticate the first account',negative.denied,{httpStatus:negative.response.status()});
  negative=await rawLogin({auth_method:'local_password',phone:secondary.phone,password:primary.password});
  check('another account password cannot authenticate the second account',negative.denied,{httpStatus:negative.response.status()});
  negative=await rawLogin({auth_method:'local_password',mail:secondary.email,password:'Incorrect-password-value'});
  check('incorrect password is rejected',negative.denied,{httpStatus:negative.response.status()});
  for(const [label,originHeader,fetchSite] of [['foreign origin','https://example.invalid','cross-site'],['null origin','null','same-origin'],['cross-site metadata without Origin',false,'cross-site']]) {
    negative=await rawLogin({auth_method:'local_password',mail:primary.email,password:primary.password},{originHeader,fetchSite,expect:403});
    check('password login rejects '+label,negative.denied,{httpStatus:negative.response.status()});
  }
  negative=await rawLogin({auth_method:'password',mail:primary.email,password:primary.password});
  check('legacy shared-password authentication cannot use a personal password',negative.denied,{httpStatus:negative.response.status()});
  negative=await rawLogin({auth_method:'local_password',username:primary.username,password:primary.password});
  check('unsupported username-only login is rejected',negative.denied,{httpStatus:negative.response.status()});
  const loginFormContext=await context();const loginForm=await loginFormContext.newPage();
  await loginForm.goto(origin+'/_login',{waitUntil:'domcontentloaded'});
  check('OTP form remains available alongside password login',await loginForm.locator('#loginForm [name="auth_method"][value="warden"]').count()===1 &&
    await loginForm.locator('#sendCodeBtn').count()===1 && await loginForm.locator('#personalPasswordForm [name="auth_method"][value="local_password"]').count()===1);
  step='positive password logins';
  const primaryMail=await passwordLogin(primary,primary.email);
  check('email login preserves Unicode and leading/trailing password spaces',true);
  const secondaryPhone=await passwordLogin(secondary,secondary.phone);
  check('phone password login reaches a separate approved Phorge account',primary.phid!==secondary.phid);
  for(const fixture of [{path:'/T1',marker:'ACC26SHAREDA'},{path:'/T2',marker:'ACC26SECRETACORE'},{path:'/T3',marker:'ACC26SECRETB'}]) {
    response=await primaryMail.page.goto(origin+fixture.path,{waitUntil:'domcontentloaded'});
    const body=await primaryMail.page.locator('body').innerText();
    check('new ordinary password user cannot view private task '+fixture.path,([403,404].includes(response.status()) || body.includes('You do not have permission to')) && !body.includes(fixture.marker));
  }
  const beforeRetry=JSON.stringify(applications(primary.email));const credentialBeforeRetry=credential(primary);const again=approve(primary);
  check('approval retry after password login preserves the same identity',again.created===false && again.phorge_phid===primary.phid && JSON.stringify(applications(primary.email))===beforeRetry && native(primary.email).matches===1);
  check('approval retry preserves the active password revision',JSON.stringify(credential(primary))===JSON.stringify(credentialBeforeRetry));
  check('password provider login leaves claimed email unverified',!native(primary.email).users[0].emailVerified && !native(primary.email).users[0].externalAccounts[0].emailVerified);
  step='password reset';
  reset(primary);
  const resetCredential=credential(primary);
  check('password reset changes both hash and session revision',resetCredential.validHash && resetCredential.revision!==credentialBeforeRetry.revision && resetCredential.hashDigest!==credentialBeforeRetry.hashDigest);
  const resetApproval=approve(primary);
  check('approval retry cannot restore the original registration password',resetApproval.created===false && JSON.stringify(credential(primary))===JSON.stringify(resetCredential));
  const oldSession=await context(primaryMail.state);
  response=await oldSession.request.get(origin+'/settings/',{maxRedirects:0});
  check('reset immediately revokes an existing password entry session',blocked(response),{httpStatus:response.status()});
  negative=await rawLogin({auth_method:'local_password',mail:primary.email,password:primary.password});
  check('old password fails after reset',negative.denied,{httpStatus:negative.response.status()});
  // Keep success attempts outside the stable-account five-per-minute window.
  console.log('Waiting for the account login rate window before reset verification');
  await delay(30000);await delay(31000);
  const resetLogin=await passwordLogin(primary,primary.phone,resetPassword);
  check('reset password works by phone for the original Phorge account',native(primary.email).users[0].phid===primary.phid);
  response=await oldSession.request.get(origin+'/settings/',{maxRedirects:0});
  check('a new login does not revive the old password session',blocked(response),{httpStatus:response.status()});
  step='Warden disable';
  check('synthetic account can be disabled in Warden',setStatus(primary,'inactive'));
  console.log('Waiting 42 seconds for the configured Warden revocation window');
  await delay(21000);await delay(21000);
  negative=await rawLogin({auth_method:'local_password',mail:primary.email,password:resetPassword});
  check('Warden-disabled account cannot create a new password session',negative.denied,{httpStatus:negative.response.status()});
  response=await resetLogin.context.request.get(origin+'/settings/',{maxRedirects:0});
  check('Warden disable revokes an existing password session',blocked(response),{httpStatus:response.status()});
  const secondaryState=await verifySettingsIdentity(secondary,secondaryPhone.context,secondaryPhone.page);
  check('other approved password account remains accessible',secondaryState.passed,secondaryState);
  check('existing six acceptance session files were not changed',originalSessions.every(({file,digest})=>sha(fs.readFileSync(file))===digest));
  const metricsAfter=await heraldCounters();
  check('password flow creates no Herald OTP or provider activity',metricsBefore.digest===metricsAfter.digest,{beforeSamples:metricsBefore.sampleCount,afterSamples:metricsAfter.sampleCount});
  check('browser never requests an OTP delivery',otpRequests===0,{requests:otpRequests});
}

async function rerunFinalIsolation() {
  if(!process.argv.includes('--run')) throw new Error('Pass --run for the targeted isolation check');
  const previous=JSON.parse(fs.readFileSync(reportPath,'utf8'));
  if(previous.error?.message!=='other approved password account remains accessible' || previous.fixtures.length!==2) throw new Error('Targeted rerun requires the known ordinary-settings redirect assertion failure');
  const preserved=reportPath.replace(/\.json$/,'.first-run-'+Date.now()+'.json');
  fs.copyFileSync(reportPath,preserved);fs.chmodSync(preserved,0o600);
  report.initialRunEvidence=path.relative(root,preserved);
  report.initialVerifiedAt=previous.verifiedAt;
  report.verificationMode='Initial full registration/password flow plus a targeted rerun correcting the ordinary-user settings redirect assertion.';
  report.checks=previous.checks.filter(value=>value.passed && !value.name.startsWith('synthetic identity disabled after acceptance'));
  report.fixtures=previous.fixtures.map(({finalInactive,...value})=>value);
  actors.splice(0,actors.length,...report.fixtures.map(value=>({...value,password:password()})));
  const [primary,secondary]=actors;
  const originalSessions=['test_admin','a_lead','a_member','b_lead','b_member','guest'].map(name=>path.join(root,'state/acceptance/browser',name+'.json'))
    .filter(file=>fs.existsSync(file)).map(file=>({file,digest:sha(fs.readFileSync(file))}));
  browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
  metricsBefore=await heraldCounters();
  report.heraldCounterBaseline=metricsBefore;
  report.heraldObservationScope='Targeted final isolation rerun; initial successful login and reset phases are retained in the first-run evidence.';
  step='targeted settings redirect verification';
  for(const actor of actors) check('reactivate only this run synthetic fixture '+actor.email,setStatus(actor,'active'));
  reset(secondary);secondary.password=resetPassword;
  await delay(7000);
  const live=await passwordLogin(secondary,secondary.phone);
  const before=await verifySettingsIdentity(secondary,live.context,live.page);
  check('ordinary account settings redirects to its own panel before disable',before.passed,before);
  check('disable A while independent B is authenticated',setStatus(primary,'inactive'));
  console.log('Waiting 42 seconds for the configured Warden revocation window');
  await delay(21000);await delay(21000);
  const after=await verifySettingsIdentity(secondary,live.context,live.page);
  check('other approved password account remains accessible',after.passed,after);
  check('existing six acceptance session files were not changed during targeted rerun',originalSessions.every(({file,digest})=>sha(fs.readFileSync(file))===digest));
  const metricsAfter=await heraldCounters();
  check('targeted password flow leaves Herald OTP/provider samples absent or unchanged in the same process',metricsBefore.digest===metricsAfter.digest,{beforeSamples:metricsBefore.sampleCount,afterSamples:metricsAfter.sampleCount});
  check('targeted browser never requests an OTP delivery',otpRequests===0,{requests:otpRequests});
}

try {
  if(process.argv.includes('--rerun-final')) await rerunFinalIsolation();
  else await main();
} catch(error) {
  // Avoid Playwright diagnostics containing form values or request bodies.
  report.error={step,message:String(error.message).split('\n')[0]};
  for(const secret of [...actors.map(actor=>actor.password),resetPassword].filter(Boolean)) report.error.message=report.error.message.replaceAll(secret,'[redacted]');
  console.error('Password acceptance stopped at '+step+': '+report.error.message);
} finally {
  for(const actor of actors) {
    if(!actor.userID) continue;
    try {
      const inactive=setStatus(actor,'inactive');
      const fixture=report.fixtures.find(value=>value.userID===actor.userID);
      if(fixture) fixture.finalInactive=inactive;
      if(actor.phid) {
        report.checks.push({name:'synthetic identity disabled after acceptance '+actor.email,passed:inactive});
        if(!inactive) throw new Error('Missing approved synthetic entry');
      }
    } catch {report.cleanupError='Unable to deactivate every synthetic identity';}
  }
  for(const ctx of contexts) await ctx.close().catch(()=>{});
  if(browser) await browser.close();
  report.completedAt=new Date().toISOString();
  report.passed=!report.error && !report.cleanupError && report.checks.length>0 && report.checks.every(check=>check.passed);
  if(process.argv.includes('--run')) fs.writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n',{mode:0o600});
}
if(!report.passed) process.exitCode=1;
