import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {launch,root,waitMail,phorgeLogin} from './identity.mjs';

// Registration and approval acceptance. Never requests an OTP for an approved
// identity through DingTalk, sends an external message, or fabricates a session.
const origin=process.env.PM_URL||'https://45.77.36.106';
const stamp=Date.now().toString(36);
const phoneSuffix=String(Date.now()%100000000).padStart(8,'0');
const primary={name:'Acceptance Registrar '+stamp,phone:'199'+phoneSuffix,email:'registrar_'+stamp+'@acceptance.test'};
const rejected={name:'Acceptance Rejected '+stamp,phone:'198'+phoneSuffix,email:'rejected_'+stamp+'@acceptance.test'};
const database=path.join(root,'state/registration/registrations.sqlite3');
const directory=path.join(root,'config/warden/users.json');
const report={verifiedAt:new Date().toISOString(),origin,scope:'Public application submission, local operator approval and real OTP login using only private captured test email; real DingTalk delivery remains unverified.',checks:[],fixtures:{primary,rejected}};
const sha=value=>createHash('sha256').update(value).digest('hex');
function check(name,passed,detail) {report.checks.push({name,passed:!!passed,detail});console.log((passed?'PASS ':'FAIL ')+name);}
function command(program,args,input) {
  const result=spawnSync(program,args,{cwd:root,input,encoding:'utf8',timeout:100000,maxBuffer:1024*1024});
  if(result.error) throw result.error;
  return result;
}
function rows(email) {
  const script="import json,sqlite3,sys\nc=sqlite3.connect(sys.argv[1]); c.row_factory=sqlite3.Row\nprint(json.dumps([dict(r) for r in c.execute('SELECT * FROM registrations WHERE email=? ORDER BY created_at,registration_id',(sys.argv[2],))]))\n";
  const result=command('python3',['-c',script,database,email]);
  if(result.status) throw new Error('Registration inspection failed');
  return JSON.parse(result.stdout);
}
function native(email) {
  const encoded=Buffer.from(JSON.stringify({email})).toString('base64');
  const source=`<?php
require '/opt/phorge/phorge/scripts/__init_script__.php';
$spec=json_decode(base64_decode('${encoded}'),true);
$viewer=PhabricatorUser::getOmnipotentUser();
$emails=id(new PhabricatorUserEmail())->loadAllWhere('LOWER(address) = %s',$spec['email']);
$result=array('matches'=>count($emails),'users'=>array());
foreach($emails as $email) {
  $u=id(new PhabricatorPeopleQuery())->setViewer($viewer)->withPHIDs(array($email->getUserPHID()))->executeOne();
  if(!$u) {throw new Exception('Email has no user');}
  $accounts=id(new PhabricatorExternalAccountQuery())->setViewer($viewer)->withUserPHIDs(array($u->getPHID()))->needAccountIdentifiers(true)->execute();
  $external=array();
  foreach($accounts as $a) {
    $identifiers=array(); foreach($a->getAccountIdentifiers() as $i){$identifiers[]=$i->getIdentifierRaw();}
    $external[]=array('identifiers'=>$identifiers,'emailVerified'=>(bool)$a->getEmailVerified(),'registrationID'=>$a->getProperty('registration.id'),'registrationPhone'=>$a->getProperty('registration.phone'));
  }
  $projects=id(new PhabricatorProjectQuery())->setViewer($viewer)->withMemberPHIDs(array($u->getPHID()))->execute();
  $result['users'][]=array('phid'=>$u->getPHID(),'username'=>$u->getUsername(),'name'=>$u->getRealName(),'isAdmin'=>(bool)$u->getIsAdmin(),'isApproved'=>(bool)$u->getIsApproved(),'isDisabled'=>(bool)$u->getIsDisabled(),'isSystemAgent'=>(bool)$u->getIsSystemAgent(),'isMailingList'=>(bool)$u->getIsMailingList(),'emailVerified'=>(bool)$email->getIsVerified(),'projectMemberships'=>count($projects),'externalAccounts'=>$external);
}
echo json_encode($result);
`;
  const result=command(path.join(root,'scripts/compose.sh'),['exec','-T','phorge','php'],source);
  if(result.status) throw new Error('Phorge account inspection failed');
  return JSON.parse(result.stdout);
}
function cli(args,expectSuccess=true) {
  const result=command('python3',['scripts/approve-registration.py',...args]);
  if(expectSuccess && result.status) throw new Error('Approval command failed: '+result.stderr.trim());
  return {status:result.status,data:result.status===0?JSON.parse(result.stdout):null};
}
const readDirectory=()=>JSON.parse(fs.readFileSync(directory));
const stableRows=email=>JSON.stringify(rows(email).map(({updated_at,...row})=>row));
function deactivateFixture() {
  if(!report.fixtures.stableUserID) return false;
  const source=`import importlib.util,json,pathlib,sys\np=pathlib.Path('scripts/approve-registration.py')\ns=importlib.util.spec_from_file_location('approval_acceptance_cleanup',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nchanged=False\nwith m.approval_lock(sys.argv[1]):\n raw,users=m.load_directory(sys.argv[2])\n for user in users:\n  if user['user_id']==sys.argv[3] and user.get('status')!='inactive':\n   user['status']='inactive';changed=True\n if changed:m.atomic_directory_write(sys.argv[2],raw,users)\nprint(json.dumps({'inactive':any(u['user_id']==sys.argv[3] and u.get('status')=='inactive' for u in users)}))\n`;
  const result=command('python3',['-c',source,database,directory,report.fixtures.stableUserID]);
  if(result.status) throw new Error('Synthetic phone entry deactivation failed');
  return JSON.parse(result.stdout).inactive;
}
const browser=await launch();
try {
  if(!fs.existsSync(database)) throw new Error('Activate registration service before acceptance');
  const initialDirectory=readDirectory();
  const initialDirectoryHash=sha(fs.readFileSync(directory));
  const existingAdministrator=initialDirectory.find(user=>String(user.mail).toLowerCase()==='177000177@qq.com');
  if(!existingAdministrator) throw new Error('Known administrator directory entry is required for collision acceptance');
  const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1200,height:900}});
  const page=await context.newPage();
  async function form() {
    const response=await page.goto(origin+'/_register',{waitUntil:'domcontentloaded'});
    if(response.status()!==200) throw new Error('Registration form HTTP '+response.status());
    return page.locator('input[name="csrf"]').inputValue();
  }
  async function post(fields,{originHeader=origin,csrfOverride}={}) {
    const csrf=await form();
    return context.request.post(origin+'/_register',{maxRedirects:0,
      headers:{Origin:originHeader,'Sec-Fetch-Site':'same-origin'},form:{csrf:csrfOverride??csrf,...fields}});
  }
  await form();
  check('public form requires phone, email and name',await page.locator('input[name="phone"][required]').count()===1 &&
    await page.locator('input[name="email"][required]').count()===1 && await page.locator('input[name="name"][required]').count()===1);
  check('public form has no password, role or organization enrollment fields',await page.locator('input[name="password"],input[name="role"],input[name="org_unit_id"]').count()===0);
  let response=await post({name:primary.name,email:primary.email});
  check('server rejects missing phone',response.status()===400);
  response=await post({phone:primary.phone,email:primary.email});
  check('server rejects missing name',response.status()===400);
  response=await post({phone:primary.phone,name:primary.name});
  check('server rejects missing email',response.status()===400);
  response=await post({...primary,phone:'123'});
  check('server rejects malformed phone',response.status()===400);
  response=await post({...primary,role:'admin',isAdmin:'1',org_unit_id:'root'});
  check('server rejects role and organization injection',response.status()===400 && rows(primary.email).length===0);
  response=await post(primary,{csrfOverride:'tampered'});
  check('server rejects forged CSRF token',response.status()===403 && rows(primary.email).length===0);
  response=await post(primary,{originHeader:'https://example.invalid'});
  check('server rejects foreign origin',response.status()===403 && rows(primary.email).length===0);

  await form();
  for(const key of ['name','phone','email']) await page.locator('input[name="'+key+'"]').fill(primary[key]);
  const submitted=page.waitForResponse(r=>new URL(r.url()).pathname==='/_register' && r.request().method()==='POST');
  await page.getByRole('button',{name:'提交注册申请',exact:true}).click();
  const submittedResponse=await submitted;
  report.submissionHTTPStatus=submittedResponse.status();
  if(submittedResponse.status()!==303) throw new Error('Browser registration submission HTTP '+submittedResponse.status()+': '+(await page.locator('body').innerText()).slice(0,600));
  await page.waitForURL(url=>url.pathname==='/_register' && url.searchParams.get('submitted')==='1');
  check('real browser submit reaches pending receipt',submittedResponse.status()===303 && (await page.locator('body').innerText()).includes('管理员审核通过后'));
  let application=rows(primary.email)[0];
  if(!application) throw new Error('Successful submission did not create an application');
  report.fixtures.registrationID=application.registration_id;
  report.fixtures.stableUserID=application.user_id;
  check('submission stores pending identity with empty organization fields',application.status==='pending' &&
    application.user_id==='reg-'+application.registration_id && ['org_unit_id','manager_user_id','position','phorge_username','phorge_phid'].every(key=>application[key]===null));
  check('pending submission creates no Phorge account',native(primary.email).matches===0);
  check('pending submission does not enter Warden',!readDirectory().some(user=>user.user_id===application.user_id || user.mail===primary.email));
  response=await context.request.post(origin+'/_send_verify_code',{form:{mail:primary.email,deliver_via:'dingtalk'},maxRedirects:0});
  check('pending identity is rejected by login before code delivery',response.status()===401,{httpStatus:response.status()});
  const beforeDuplicate=JSON.stringify(rows(primary.email));
  response=await post({...primary,name:'Attempted replacement',phone:'197'+phoneSuffix});
  check('duplicate email keeps stable identity and original claims',response.status()===303 && JSON.stringify(rows(primary.email))===beforeDuplicate);
  response=await post({...primary,email:existingAdministrator.mail,name:'Attempted administrator replacement'});
  check('public application cannot overwrite administrator or authoritative directory',response.status()===303 && sha(fs.readFileSync(directory))===initialDirectoryHash &&
    rows(String(existingAdministrator.mail).toLowerCase()).length===0);

  const base=['approve',application.registration_id,'--by','siteadmin','--confirmed-phone',primary.phone,'--acceptance-only'];
  let result=cli([...base,'--username','siteadmin'],false);
  check('operator path rejects reserved administrator username before provisioning',result.status!==0 && native(primary.email).matches===0 && rows(primary.email)[0].phorge_username===null);
  result=cli(base);
  application=rows(primary.email)[0];
  const account=native(primary.email);
  const user=account.users[0];
  const entry=readDirectory().find(value=>value.user_id===application.user_id);
  report.fixtures.approvedUsername=user?.username;
  report.fixtures.approvedPhorgePHID=user?.phid;
  check('operator approval creates one enabled ordinary Phorge user',result.status===0 && account.matches===1 && user.isApproved && !user.isAdmin && !user.isSystemAgent && !user.isMailingList && !user.isDisabled);
  check('claimed email remains unverified in Phorge and external identity',!user.emailVerified && user.externalAccounts.length===1 && !user.externalAccounts[0].emailVerified);
  check('external identity binds exact stable registration ID',user.externalAccounts[0].identifiers.length===1 && user.externalAccounts[0].identifiers[0]===application.user_id &&
    user.externalAccounts[0].registrationID===application.registration_id && user.externalAccounts[0].registrationPhone===primary.phone);
  check('approval grants no project membership or organization assignment',user.projectMemberships===0 && ['org_unit_id','manager_user_id','position'].every(key=>application[key]===null));
  check('Warden publication is ordinary and matches approved claims',application.status==='approved' && application.phorge_phid===user.phid && entry?.role==='user' &&
    entry.status==='active' && Array.isArray(entry.scope) && entry.scope.length===0 && entry.phone===primary.phone && entry.mail===primary.email);
  check('approval preserves every pre-existing authoritative identity',initialDirectory.every(old=>JSON.stringify(readDirectory().find(user=>user.user_id===old.user_id))===JSON.stringify(old)));
  const approvedState=stableRows(primary.email);
  const approvedDirectoryHash=sha(fs.readFileSync(directory));
  result=cli(base);
  check('approval retry reuses the same user without changing approval state or directory',result.data.created===false && stableRows(primary.email)===approvedState && sha(fs.readFileSync(directory))===approvedDirectoryHash && native(primary.email).matches===1);
  result=cli(['reject',application.registration_id,'--by','siteadmin','--reason','Must not reject approved identity'],false);
  check('approved identity cannot be reset through rejection',result.status!==0 && rows(primary.email)[0].status==='approved' && sha(fs.readFileSync(directory))===approvedDirectoryHash);

  if(fs.existsSync(path.join(root,'.dingtalk-enabled'))) throw new Error('Acceptance login must never use live DingTalk');
  await new Promise(resolve=>setTimeout(resolve,6500)); // Warden file polling.
  const loginContext=await browser.newContext({ignoreHTTPSErrors:true});
  const loginPage=await loginContext.newPage();
  await loginPage.goto(origin+'/_login',{waitUntil:'domcontentloaded'});
  await loginPage.locator('#mail').fill(primary.email);
  await loginPage.locator('#deliver_email').check();
  const sentAt=Date.now();
  const challengeResponse=loginPage.waitForResponse(response=>new URL(response.url()).pathname==='/_send_verify_code' && response.request().method()==='POST');
  await loginPage.locator('#sendCodeBtn').click();
  const challengeHTTP=await challengeResponse;
  const challenge=await challengeHTTP.json();
  check('approved identity obtains a real non-debug challenge through private test email',challengeHTTP.status()===200 && challenge.success && !!challenge.challenge_id && !challenge.debug_code);
  if(challengeHTTP.status()!==200 || !challenge.success) throw new Error('Approved OTP challenge refused; no code was bypassed');
  const code=await waitMail(primary.email,sentAt);
  await loginPage.locator('#verify_code').fill(code);
  const loginResponse=loginPage.waitForResponse(response=>new URL(response.url()).pathname==='/_login' && response.request().method()==='POST');
  await loginPage.locator('#loginForm button[type="submit"]').click();
  const loggedIn=await loginResponse;
  check('approved identity completes real OTP login',loggedIn.status()===200);
  await loginPage.waitForURL(url=>url.origin===origin && url.pathname!=='/_login');
  await phorgeLogin(loginContext,loginPage,user.username,{register:false});
  check('approved identity logs into pre-provisioned Phorge account without re-registration',
    (await loginContext.cookies(origin)).some(cookie=>cookie.name==='phusr' && cookie.value===user.username) &&
    new URL(loginPage.url()).pathname.startsWith('/settings/'));
  const afterLogin=native(primary.email);
  check('OTP login preserves unverified contact email flags',!afterLogin.users[0].emailVerified && !afterLogin.users[0].externalAccounts[0].emailVerified);
  const afterLoginState=stableRows(primary.email);
  result=cli(base);
  check('approval retry after actual provider login preserves immutable mapping',result.data.created===false &&
    result.data.phorge_phid===user.phid && stableRows(primary.email)===afterLoginState && native(primary.email).matches===1 &&
    native(primary.email).users[0].externalAccounts[0].identifiers[0]===application.user_id);
  for(const fixture of [{path:'/T1',marker:'ACC26SHAREDA'},{path:'/T2',marker:'ACC26SECRETACORE'},{path:'/T3',marker:'ACC26SECRETB'}]) {
    const response=await loginPage.goto(origin+fixture.path,{waitUntil:'domcontentloaded'});
    const body=await loginPage.locator('body').innerText();
    check('new ordinary account has no private project/task access '+fixture.path,
      ([403,404].includes(response.status()) || body.includes('You do not have permission to')) && !body.includes(fixture.marker));
  }
  await loginContext.close();

  response=await post(rejected);
  const rejectRow=rows(rejected.email)[0];
  if(response.status()!==303 || !rejectRow) throw new Error('Rejection fixture submission failed');
  check('registration service still writes pending rows after root approval',rejectRow.status==='pending');
  cli(['reject',rejectRow.registration_id,'--by','siteadmin','--reason','Synthetic acceptance rejection']);
  const rejectionState=JSON.stringify(rows(rejected.email));
  cli(['reject',rejectRow.registration_id,'--by','siteadmin','--reason','Repeat rejection must preserve original audit']);
  check('rejection is idempotent and creates no login identity',JSON.stringify(rows(rejected.email))===rejectionState && native(rejected.email).matches===0 &&
    !readDirectory().some(user=>user.mail===rejected.email));
  result=cli(['approve',rejectRow.registration_id,'--by','siteadmin','--confirmed-phone',rejected.phone,'--acceptance-only'],false);
  check('rejected application cannot be approved in place',result.status!==0 && rows(rejected.email)[0].status==='rejected');
  response=await post(rejected);
  const reapplications=rows(rejected.email);
  const fresh=reapplications.find(row=>row.status==='pending');
  check('reapplication creates a new pending request without reviving rejection',response.status()===303 && reapplications.length===2 && !!fresh &&
    fresh.registration_id!==rejectRow.registration_id && fresh.user_id!==rejectRow.user_id && reapplications.some(row=>row.status==='rejected'));
  report.fixtures.rejectedRegistrationID=rejectRow.registration_id;
  report.fixtures.reapplicationID=fresh?.registration_id;
  await context.close();
} catch(error) {
  report.error=error.message;
  console.error(report.error);
} finally {
  try {
    const inactive=deactivateFixture();
    if(report.fixtures.approvedPhorgePHID) check('synthetic approved phone is disabled before future DingTalk activation',inactive);
    report.syntheticPhoneInactive=inactive;
  } catch(error) {
    report.cleanupError=error.message;
    console.error(error.message);
  }
  await browser.close();
  report.passed=!report.error && !report.cleanupError && report.checks.every(check=>check.passed);
  fs.writeFileSync(path.join(root,'state/acceptance/registration-browser.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
}
if(!report.passed) process.exitCode=1;
