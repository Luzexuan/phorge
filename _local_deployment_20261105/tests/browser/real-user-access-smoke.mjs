import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {chromium} from 'playwright';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const origin='https://45.77.36.106',mail='a_member@acceptance.test';
const temporary=path.join(root,'state/acceptance/real-user-smoke');
const report={verifiedAt:new Date().toISOString(),checks:[],scope:'Existing synthetic ordinary member, real private-test-mail OTP, trusted public HTTPS, read-only page authorization and create-form access. No account registration or business mutation.'};
let browser,ctx,stage='preflight',logged=false;
function check(name,passed){report.checks.push({name,passed:!!passed});if(!passed)throw new Error('Access smoke assertion failed');console.log('PASS '+name);}
function inspect(name){const result=spawnSync('docker',['inspect',name],{encoding:'utf8',timeout:10000,maxBuffer:1024*1024});if(result.status!==0)throw new Error('Container preflight failed');return JSON.parse(result.stdout)[0];}
function env(c){return Object.fromEntries(c.Config.Env.filter(v=>v.includes('=')).map(v=>{const p=v.indexOf('=');return [v.slice(0,p),v.slice(p+1)];}));}
function auditPosition(){const source="import sqlite3,json;c=sqlite3.connect('file:/workspace/state/maintenance/maintenance.sqlite3?mode=ro',uri=True);print(json.dumps(c.execute('SELECT COUNT(*),COALESCE(MAX(id),0) FROM audit').fetchone()));c.close()";const r=spawnSync(path.join(root,'scripts/compose.sh'),['exec','-T','maintenance','python3','-c',source],{encoding:'utf8',timeout:20000});if(r.status!==0)throw new Error('Audit snapshot failed');return r.stdout.trim();}
async function post(url,form){return ctx.request.post(origin+url,{form,maxRedirects:0,headers:{Origin:origin,'Sec-Fetch-Site':'same-origin',Accept:'application/json','X-Requested-With':'XMLHttpRequest'}});}
async function waitCode(since){for(let n=0;n<120;n++){for(const file of fs.readdirSync(path.join(root,'state/testing-mail')).filter(f=>f.endsWith('.json')).sort().reverse()){const d=JSON.parse(fs.readFileSync(path.join(root,'state/testing-mail',file),'utf8'));if(d.received_at*1000<since-1000||!d.recipients.includes(mail))continue;const m=d.body.match(/(?:验证码(?:是)?|verification code(?: is)?|code)[^0-9]{0,80}([0-9]{6})/i)||d.body.match(/(?<![0-9])([0-9]{6})(?![0-9])/);if(m)return m[1];}await new Promise(r=>setTimeout(r,250));}throw new Error('Private captured code unavailable');}
async function denied(response){const body=await response.text();const policy=response.status()===200&&/<title>[^<]*(?:You Shall Not Pass|Access Denied|Restricted Application|Administrator|Forbidden|权限|禁止)[^<]*<\/title>/i.test(body);return ([401,403,404].includes(response.status())||policy)&&!body.includes('maintenance-action-form')&&!/data-maintenance-(?:user|registration|audit)-id=/.test(body)&&!body.includes('177000177@qq.com');}
try{
  if(!process.argv.includes('--run'))throw new Error('Explicit run required');
  const herald=env(inspect('team-management-herald-1')),smtp=env(inspect('team-management-herald-smtp-1'));
  const testmail=inspect('team-management-identity-test-mail-1');
  check('DingTalk is disabled and OTP delivery terminates only in the private acceptance mailbox',!fs.existsSync(path.join(root,'.dingtalk-enabled'))&&herald.HERALD_SMTP_API_URL==='https://identity-test-mail:8443'&&smtp.SMTP_HOST==='identity-test-mail'&&smtp.SMTP_PORT==='1025'&&Object.keys(testmail.HostConfig.PortBindings||{}).length===0);
  const users=JSON.parse(fs.readFileSync(path.join(root,'config/warden/users.json'),'utf8'));
  check('existing exact synthetic recipient is active without changing directory state',users.filter(u=>u.mail===mail&&u.status==='active').length===1);
  fs.mkdirSync(temporary,{recursive:true,mode:0o700});fs.chmodSync(temporary,0o700);
  browser=await chromium.launch({headless:true});ctx=await browser.newContext();
  stage='private OTP login';
  const since=Date.now();const sent=await post('/_send_verify_code',{mail,deliver_via:'email'});const challenge=await sent.json();
  check('trusted public HTTPS issues a real non-debug test challenge',sent.status()===200&&challenge.success&&challenge.challenge_id&&!challenge.debug_code);
  const code=await waitCode(since);const login=await post('/_login',{auth_method:'warden',mail,challenge_id:challenge.challenge_id,verify_code:code});
  check('captured private-test-mail code logs into the existing identity',login.status()===200);logged=true;
  const page=await ctx.newPage();page.setDefaultTimeout(30000);
  await page.goto(origin+'/auth/login/traefik:traefik/',{waitUntil:'domcontentloaded'});
  check('native entry resolves an existing account without registration',!new URL(page.url()).pathname.startsWith('/auth/register/'));
  await page.goto(origin+'/settings/',{waitUntil:'domcontentloaded'});
  const csrf=await page.locator('input[name="__csrf__"]').first().inputValue();
  const who=await ctx.request.post(origin+'/api/user.whoami',{form:{params:'{}',output:'json',__csrf__:csrf}});const identity=await who.json();
  check('HTTP Conduit confirms approved ordinary a_member and no administrator role',!identity.error_code&&identity.result?.userName==='a_member'&&identity.result.roles.includes('approved')&&!identity.result.roles.includes('admin'));
  const state=path.join(temporary,'ordinary.json');await ctx.storageState({path:state});fs.chmodSync(state,0o600);
  const auditBefore=auditPosition();stage='read-only authorization boundaries';
  for(const route of ['/maintenance/','/maintenance/users/','/maintenance/registrations/','/maintenance/audit/','/maintenance/user/password/?id=linkerbot-site-admin','/%6daintenance/','/?__path__=/maintenance/users/','/config/','/people/create/','/people/new/standard/','/applications/edit/PhabricatorProjectApplication/']){
    const response=await ctx.request.get(origin+route,{maxRedirects:0});
    check('ordinary user is denied protected route '+route,await denied(response));
  }
  const forged=await ctx.request.get(origin+'/maintenance/',{maxRedirects:0,headers:{'X-Auth-User':'linkerbot-site-admin','X-Auth-Email':'177000177@qq.com','X-Auth-Role':'admin','X-Forwarded-User':'siteadmin'}});
  check('forged administrator identity headers do not grant access',await denied(forged));
  check('read-only probes leave maintenance audit unchanged',auditPosition()===auditBefore);
  const create=await page.goto(origin+'/project/edit/',{waitUntil:'domcontentloaded'});
  check('ordinary user can open actual project creation form',create.status()===200&&await page.locator('input[name="name"]').count()===1);
  check('project creation page offers the readable private default', (await page.locator('body').innerText()).includes('项目创建者与站点管理员'));
  const logout=await post('/_logout',{});logged=false;
  check('temporary ordinary test entry session is logged out',logout.status()===200&&!(await ctx.cookies(origin)).some(c=>c.name==='stargate_session_id'&&c.value));
}catch(error){report.error={stage,type:error?.name||'Error'};}
finally{
  if(logged&&ctx)await post('/_logout',{}).catch(()=>{});
  if(ctx)await ctx.close().catch(()=>{});if(browser)await browser.close().catch(()=>{});
  fs.rmSync(temporary,{recursive:true,force:true});
  report.completedAt=new Date().toISOString();report.passed=!report.error&&report.checks.length>0&&report.checks.every(c=>c.passed);
  const out=path.join(root,'state/acceptance/real-user-access-smoke.json');fs.writeFileSync(out,JSON.stringify(report,null,2)+'\n',{mode:0o600});fs.chmodSync(out,0o600);
  console.log(JSON.stringify({passed:report.passed,checks:report.checks.length,error:report.error}));if(!report.passed)process.exitCode=1;
}
