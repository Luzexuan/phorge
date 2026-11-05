import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomBytes} from 'node:crypto';
import {chromium} from 'playwright';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const origin='https://45.77.36.106';
const folder=path.join(root,'state/acceptance/maintenance');
fs.mkdirSync(folder,{recursive:true,mode:0o700});fs.chmodSync(folder,0o700);
const privatePath=path.join(folder,'lifecycle-private.json');
const reportPath=path.join(root,'state/acceptance/maintenance-lifecycle.json');
const report={verifiedAt:new Date().toISOString(),checks:[],scope:'Real browser public registration and native administrator maintenance UI. No CLI approval, password reset or whitelist edits.'};
const save=(file,value)=>{fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{mode:0o600});fs.chmodSync(file,0o600);};
const check=(name,passed,detail)=>{report.checks.push({name,passed:!!passed,...(detail?{detail}:{})});if(!passed)throw new Error('Lifecycle check failed');console.log('PASS '+name);};
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let browser,step='preflight',fixture,admin;
const contexts=[];
async function context(state) {const c=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1360,height:1000},...(state?{storageState:state}:{})});c.setDefaultTimeout(45000);c.setDefaultNavigationTimeout(120000);contexts.push(c);return c;}
async function cooldown(response) {let remaining=(Math.min(120,Number(response.headers()['retry-after'])||61)+1)*1000;while(remaining>0){const n=Math.min(remaining,30000);await pause(n);remaining-=n;}}
async function login(identifier,password) {
  const c=await context();const page=await c.newPage();
  for(let n=0;n<3;n++) {
    await page.goto(origin+'/_login',{waitUntil:'domcontentloaded'});
    await page.locator('#password_identifier').fill(identifier);await page.locator('#personal_password').fill(password);
    const pending=page.waitForResponse(r=>new URL(r.url()).pathname==='/_login'&&r.request().method()==='POST');
    await page.locator('#personalPasswordForm button[type="submit"]').click();
    const response=await pending;
    if(response.status()===429){await cooldown(response);continue;}
    if(response.status()!==200)throw new Error('Login rejected');
    await page.waitForURL(url=>url.origin===origin&&url.pathname!=='/_login');
    await page.goto(origin+'/auth/login/traefik:traefik/',{waitUntil:'domcontentloaded'});
    await page.goto(origin+'/settings/',{waitUntil:'domcontentloaded'});
    const csrf=await page.locator('input[name="__csrf__"]').first().inputValue();
    const r=await c.request.post(origin+'/api/user.whoami',{form:{params:'{}',output:'json',__csrf__:csrf}});
    const body=await r.json();if(body.error_code||!body.result?.phid)throw new Error('Native identity unavailable');
    return {context:c,page,actor:body.result};
  }
  throw new Error('Login rate window exhausted');
}
async function denied(identifier,password) {
  const c=await context();
  for(let n=0;n<3;n++) {
    const r=await c.request.post(origin+'/_login',{headers:{Origin:origin,Accept:'application/json','Sec-Fetch-Site':'same-origin'},form:{auth_method:'local_password',mail:identifier.includes('@')?identifier:'',phone:identifier.includes('@')?'':identifier,password},maxRedirects:0});
    if(r.status()===429){await cooldown(r);continue;}
    return r.status()===401;
  }
  throw new Error('Login rate window exhausted');
}
function entryBlocked(response) {const loc=response.headers().location;return response.status()===401 || ([302,303,307,308].includes(response.status())&&loc&&new URL(loc,origin).pathname==='/_login');}
async function formSubmit(page,done) {
  await page.locator('#maintenance-confirm').check();
  const pending=page.waitForResponse(r=>new URL(r.url()).pathname.startsWith('/maintenance/')&&r.request().method()==='POST');
  await page.locator('#maintenance-action-form button[type="submit"]').click();
  const response=await pending;
  report.submissions??=[];report.submissions.push({step,httpStatus:response.status(),hasLocation:!!response.headers().location});
  if(![200,302,303].includes(response.status())) {
    await page.screenshot({path:path.join(folder,'failed-form.png'),fullPage:true});
    throw new Error('Maintenance form rejected');
  }
  await page.waitForURL(u=>u.pathname.startsWith('/maintenance/')&&u.searchParams.get('done')===done,{timeout:15000});
}
async function findRegistration(actor) {
  await admin.page.goto(origin+'/maintenance/registrations/?status=all&q='+encodeURIComponent(actor.email),{waitUntil:'domcontentloaded'});
  const marker=admin.page.locator('[data-maintenance-registration-id]');
  if(await marker.count()!==1)throw new Error('Registration row unavailable');
  actor.registrationId=await marker.getAttribute('data-maintenance-registration-id');actor.principal='reg-'+actor.registrationId;
  save(privatePath,fixture);return marker;
}
async function userRow(actor) {
  await admin.page.goto(origin+'/maintenance/users/?q='+encodeURIComponent(actor.principal),{waitUntil:'domcontentloaded'});
  return admin.page.locator('[data-maintenance-user-id="'+actor.principal+'"]');
}
async function status(actor,value,reason) {
  await admin.page.goto(origin+'/maintenance/user/status/?id='+encodeURIComponent(actor.principal),{waitUntil:'domcontentloaded'});
  await admin.page.locator('[name="new_status"]').selectOption(value);
  await admin.page.locator('[name="reason"]').fill(reason);
  await formSubmit(admin.page,'status');
  const row=await userRow(actor);
  check('web status updates Warden and native account together: '+value,
    await row.getAttribute('data-maintenance-entry-status')===value&&await row.getAttribute('data-maintenance-native-disabled')===(value==='inactive'?'1':'0'));
}

try {
  if(!process.argv.includes('--run'))throw new Error('Explicit run required');
  if(fs.existsSync(privatePath)) {
    if(!process.argv.includes('--resume'))throw new Error('Existing fixture requires explicit resume');
    fixture=JSON.parse(fs.readFileSync(privatePath,'utf8'));
  } else {
    const stamp=Date.now().toString(36),suffix=String(Date.now()%100000000).padStart(8,'0');
    fixture={stamp,actors:['a','b','c','d'].map((key,i)=>({key,name:'维护验收 '+key+' '+stamp,email:'maintenance_'+key+'_'+stamp+'@acceptance.test',phone:String(199-i)+suffix,username:'maint_'+key+'_'+stamp,password:'  Maint-'+randomBytes(20).toString('base64url')+'-密钥🔐  '}))};
    save(privatePath,fixture);
  }
  browser=await chromium.launch({headless:true});
  step='administrator login';
  admin=await login('177000177@qq.com',fs.readFileSync(path.join(root,'state/private/siteadmin-initial-password.txt'),'utf8').replace(/\n$/,''));
  check('existing siteadmin retains administrator identity',admin.actor.userName==='siteadmin'&&admin.actor.roles.includes('admin'));
  let response=await admin.page.goto(origin+'/maintenance/',{waitUntil:'domcontentloaded'});
  check('native administrator maintenance overview available',response.status()===200&&(await admin.page.locator('body').innerText()).includes('账户维护'));
  await admin.context.storageState({path:path.join(folder,'admin.json')});fs.chmodSync(path.join(folder,'admin.json'),0o600);
  await admin.page.screenshot({path:path.join(folder,'overview.png'),fullPage:true});
  for(const actor of fixture.actors) {
    step='public registration '+actor.key;
    if(!actor.submitted) {
      const c=await context();const page=await c.newPage();await page.goto(origin+'/_register',{waitUntil:'domcontentloaded'});
      for(const [name,value] of Object.entries({name:actor.name,phone:actor.phone,email:actor.email,password:actor.password,password_confirm:actor.password}))await page.locator('[name="'+name+'"]').fill(value);
      await Promise.all([page.waitForURL(u=>u.pathname==='/_register'&&u.searchParams.get('submitted')==='1'),page.locator('button[type="submit"]').click()]);
      actor.submitted=true;save(privatePath,fixture);
    }
    const marker=await findRegistration(actor);const state=await marker.getAttribute('data-maintenance-status');
    if(state==='pending')check('pending applicant cannot log in '+actor.key,await denied(actor.email,actor.password));
    step='web approval '+actor.key;
    if(actor.key==='d') {
      if(state!=='rejected') {
        await admin.page.goto(origin+'/maintenance/registration/reject/?id='+actor.registrationId,{waitUntil:'domcontentloaded'});
        await admin.page.locator('[name="reason"]').fill('Synthetic browser rejection '+fixture.stamp);
        await formSubmit(admin.page,'rejected');
      }
      check('web rejection recorded without account admission',await (await findRegistration(actor)).getAttribute('data-maintenance-status')==='rejected'&&await denied(actor.email,actor.password));
      actor.rejected=true;save(privatePath,fixture);continue;
    }
    if(state!=='approved') {
      await admin.page.goto(origin+'/maintenance/registration/approve/?id='+actor.registrationId,{waitUntil:'domcontentloaded'});
      await admin.page.locator('[name="username"]').fill(actor.username);await admin.page.locator('[name="note"]').fill('Synthetic browser approval '+fixture.stamp);
      await formSubmit(admin.page,'approved');
    }
    check('registration approved entirely through browser '+actor.key,await (await findRegistration(actor)).getAttribute('data-maintenance-status')==='approved');
    actor.approved=true;save(privatePath,fixture);
  }
  const [a,b,c]=fixture.actors;
  step='approved user identity';
  let aLogin=await login(a.email,a.currentPassword||a.password);
  const bLogin=await login(b.phone,b.password);const cLogin=await login(c.email,c.password);
  for(const [actor,logged] of [[a,aLogin],[b,bLogin],[c,cLogin]]) {
    actor.phid=logged.actor.phid;
    check('approved user has original ordinary native identity '+actor.key,logged.actor.userName===actor.username&&!logged.actor.roles.includes('admin')&&logged.actor.roles.includes('approved'));
  }
  save(privatePath,fixture);
  for(const task of ['/T1','/T2','/T3']) {
    const r=await aLogin.page.goto(origin+task,{waitUntil:'domcontentloaded'});const text=await aLogin.page.locator('body').innerText();
    check('web-approved ordinary account cannot access private task '+task,[403,404].includes(r.status())||text.includes('You do not have permission to'));
  }
  step='web password reset';
  if(!a.resetDone) {
    const fresh='  Changed-'+randomBytes(20).toString('base64url')+'-新密钥🔐  ';
    a.nextPassword=fresh;save(privatePath,fixture);
    await admin.page.goto(origin+'/maintenance/user/password/?id='+encodeURIComponent(a.principal),{waitUntil:'domcontentloaded'});
    await admin.page.locator('[name="password"]').fill(fresh);await admin.page.locator('[name="password_confirm"]').fill(fresh);
    await admin.page.locator('[name="reason"]').fill('maintenance-browser-reset-'+fixture.stamp);
    await formSubmit(admin.page,'password');a.currentPassword=fresh;a.resetDone=true;delete a.nextPassword;save(privatePath,fixture);
  }
  check('web reset revokes prior password session',entryBlocked(await aLogin.context.request.get(origin+'/settings/',{maxRedirects:0})));
  check('web reset rejects original password',await denied(a.email,a.password));
  aLogin=await login(a.phone,a.currentPassword);
  check('new Unicode password with outer spaces logs into same user',aLogin.actor.phid===a.phid);
  step='web account disable and enable';
  await status(a,'inactive','maintenance-browser-disable-'+fixture.stamp);
  check('web disable immediately blocks old password session',entryBlocked(await aLogin.context.request.get(origin+'/settings/',{maxRedirects:0})));
  let remaining=42000;while(remaining>0){await pause(Math.min(21000,remaining));remaining-=21000;}
  check('web-disabled account cannot start a new login',await denied(a.email,a.currentPassword));
  await bLogin.page.goto(origin+'/settings/',{waitUntil:'domcontentloaded'});
  check('another account still accesses its settings after one account disabled',new URL(bLogin.page.url()).pathname.startsWith('/settings/'));
  await status(a,'active','maintenance-browser-enable-'+fixture.stamp);
  await pause(6000);aLogin=await login(a.email,a.currentPassword);
  check('web re-enable preserves original account and password',aLogin.actor.phid===a.phid);
  step='audit and test handoff';
  await admin.page.goto(origin+'/maintenance/audit/',{waitUntil:'domcontentloaded'});
  const audit=await admin.page.locator('body').innerText();
  check('audit shows actual administrator and operation reason',audit.includes('siteadmin')&&audit.includes('maintenance-browser-reset-'+fixture.stamp)&&audit.includes('maintenance-browser-disable-'+fixture.stamp));
  check('audit does not expose submitted password or credential encoding',!audit.includes(a.currentPassword)&&!audit.includes(a.password)&&!audit.includes('scrypt$'));
  for(const [name,logged] of [['admin',admin],['ordinary',aLogin],['other',bLogin],['stale-admin',cLogin]]) {
    const file=path.join(folder,name+'.json');await logged.context.storageState({path:file});fs.chmodSync(file,0o600);
  }
  save(path.join(folder,'security-fixtures.json'),{origin,adminState:'state/acceptance/maintenance/admin.json',ordinaryState:'state/acceptance/maintenance/ordinary.json',otherState:'state/acceptance/maintenance/other.json',ordinary:{principal:a.principal,username:a.username,phid:a.phid},other:{principal:b.principal,username:b.username,phid:b.phid},registrationId:fixture.actors[3].registrationId,staleAdminState:'state/acceptance/maintenance/stale-admin.json',staleAdmin:{principal:c.principal,username:c.username,phid:c.phid}});
  report.fixtureHandoff='state/acceptance/maintenance/security-fixtures.json';
  report.pendingCleanup=fixture.actors.filter(a=>a.approved).map(a=>a.principal);
} catch(error) {
  // Avoid Playwright diagnostics which can contain typed passwords or cookies.
  report.error={step,type:error?.name||'Error'};
} finally {
  for(const c of contexts)await c.close().catch(()=>{});
  if(browser)await browser.close();
  report.completedAt=new Date().toISOString();report.passed=!report.error&&report.checks.length>0&&report.checks.every(c=>c.passed);
  save(reportPath,report);console.log(JSON.stringify({passed:report.passed,checks:report.checks.length,error:report.error}));
  if(!report.passed)process.exitCode=1;
}
