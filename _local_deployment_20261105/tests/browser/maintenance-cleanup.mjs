import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const dir=path.join(root,'state/acceptance/maintenance');
const origin='https://45.77.36.106';
const report={verifiedAt:new Date().toISOString(),checks:[],scope:'Disable only the three dedicated maintenance acceptance accounts using actual administrator forms.'};
let browser,ctx,stage='preflight';
function check(name,passed){report.checks.push({name,passed:!!passed});if(!passed)throw new Error('Cleanup check failed');console.log('PASS '+name);}
try {
  if(!process.argv.includes('--run'))throw new Error('Explicit run required');
  const fixture=JSON.parse(fs.readFileSync(path.join(dir,'lifecycle-private.json'),'utf8'));
  if(!JSON.parse(fs.readFileSync(path.join(root,'state/acceptance/maintenance-security-browser.json'),'utf8')).passed)throw new Error('Security checks must finish first');
  const actors=fixture.actors.filter(a=>a.approved);
  if(actors.length!==3 || actors.map(a=>a.key).sort().join('')!=='abc' || actors.some(a=>a.email!==`maintenance_${a.key}_${fixture.stamp}@acceptance.test`||a.username!==`maint_${a.key}_${fixture.stamp}`||a.principal!=='reg-'+a.registrationId||!/^reg-[a-f0-9-]{36}$/.test(a.principal)||!/^PHID-USER-[a-zA-Z0-9]{20}$/.test(a.phid)))throw new Error('Unsafe cleanup targets');
  browser=await chromium.launch({headless:true});
  ctx=await browser.newContext({ignoreHTTPSErrors:true,storageState:path.join(dir,'admin.json')});
  const page=await ctx.newPage();page.setDefaultTimeout(45000);
  await page.goto(origin+'/settings/',{waitUntil:'domcontentloaded'});
  const initialCSRF=await page.locator('input[name="__csrf__"]').first().inputValue();
  const initialWho=await ctx.request.post(origin+'/api/user.whoami',{form:{params:'{}',output:'json',__csrf__:initialCSRF}});
  const initialIdentity=await initialWho.json();
  check('cleanup starts from the expected approved siteadmin session',!initialIdentity.error_code&&initialIdentity.result?.userName==='siteadmin'&&initialIdentity.result.roles.includes('admin')&&initialIdentity.result.roles.includes('approved')&&!initialIdentity.result.roles.includes('disabled'));
  for(const actor of actors) {
    stage='web cleanup '+actor.key;
    await page.goto(origin+'/maintenance/user/status/?id='+encodeURIComponent(actor.principal),{waitUntil:'domcontentloaded'});
    await page.locator('[name="new_status"]').selectOption('inactive');
    await page.locator('[name="reason"]').fill('maintenance-acceptance-cleanup-'+fixture.stamp);
    await page.locator('#maintenance-confirm').check();
    await Promise.all([page.waitForURL(u=>u.pathname.startsWith('/maintenance/')&&u.searchParams.get('done')==='status'),page.locator('#maintenance-action-form button[type="submit"]').click()]);
    await page.goto(origin+'/maintenance/users/?q='+encodeURIComponent(actor.principal),{waitUntil:'domcontentloaded'});
    const row=page.locator('[data-maintenance-user-id="'+actor.principal+'"]');
    check('synthetic '+actor.key+' admission inactive and native account disabled',await row.count()===1&&await row.getAttribute('data-maintenance-entry-status')==='inactive'&&await row.getAttribute('data-maintenance-native-disabled')==='1');
  }
  stage='administrator identity after cleanup';
  await page.goto(origin+'/settings/',{waitUntil:'domcontentloaded'});
  const csrf=await page.locator('input[name="__csrf__"]').first().inputValue();
  const response=await ctx.request.post(origin+'/api/user.whoami',{form:{params:'{}',output:'json',__csrf__:csrf}});
  const who=await response.json();
  check('original siteadmin remains enabled and approved administrator',!who.error_code&&who.result?.userName==='siteadmin'&&who.result.roles.includes('admin')&&who.result.roles.includes('approved')&&!who.result.roles.includes('disabled'));
  // Invalidate this acceptance browser's entry session without changing the
  // administrator password or other active administrator sessions.
  const logout=await ctx.request.post(origin+'/_logout',{headers:{Origin:origin,'Sec-Fetch-Site':'same-origin'},maxRedirects:0});
  check('acceptance administrator entry cookie removed',logout.status()===200&&!(await ctx.cookies(origin)).some(c=>c.name==='stargate_session_id'&&c.value));
  fs.unlinkSync(path.join(dir,'lifecycle-private.json'));
  report.syntheticPasswordFileRemoved=true;
} catch(error) {report.error={stage,type:error?.name||'Error'};}
finally {
  if(ctx)await ctx.close().catch(()=>{});if(browser)await browser.close();
  report.passed=!report.error&&report.checks.length===6&&report.checks.every(c=>c.passed);
  report.completedAt=new Date().toISOString();
  const out=path.join(root,'state/acceptance/maintenance-cleanup.json');fs.writeFileSync(out,JSON.stringify(report,null,2)+'\n',{mode:0o600});fs.chmodSync(out,0o600);
  console.log(JSON.stringify({passed:report.passed,checks:report.checks.length,error:report.error}));if(!report.passed)process.exitCode=1;
}
