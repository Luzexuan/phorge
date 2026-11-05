import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright';

// The actual administrator password and cookies stay out of reports/screenshots.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const origin='https://45.77.36.106';
const output=path.join(root,'state/acceptance/password-admin-browser.json');
const report={verifiedAt:new Date().toISOString(),checks:[]};
let browser,adminContext,stage='initialization';
const check=(name,passed)=>{
  report.checks.push({name,passed:!!passed});
  if(!passed)throw new Error('Check failed');
};
try {
  if(!process.argv.includes('--run'))throw new Error('Explicit run flag required');
  const password=fs.readFileSync(path.join(root,'state/private/siteadmin-initial-password.txt'),'utf8').replace(/\n$/,'');
  browser=await chromium.launch({headless:true});
  adminContext=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1100,height:900}});
  const page=await adminContext.newPage();
  stage='administrator login';
  await page.goto(origin+'/_login',{waitUntil:'domcontentloaded'});
  check('personal password and verification-code forms both visible',
    await page.locator('#personalPasswordForm').count()===1 && await page.locator('#loginForm').count()===1);
  stage='login-page screenshot';
  await page.screenshot({path:path.join(root,'state/acceptance/screenshots/password-login.png'),fullPage:true});
  stage='administrator form fill';
  await page.locator('#password_identifier').fill('177000177@qq.com');
  await page.locator('#personal_password').fill(password);
  const pending=page.waitForResponse(r=>new URL(r.url()).pathname==='/_login' && r.request().method()==='POST');
  stage='administrator form submit';
  await page.locator('#personalPasswordForm button[type="submit"]').click();
  const response=await pending;
  stage='administrator login response';
  report.adminResponse={status:response.status(),contentType:response.headers()['content-type']};
  check('siteadmin password form accepted',response.status()===200);
  await page.waitForURL(url=>url.origin===origin && url.pathname!=='/_login');
  await page.goto(origin+'/auth/login/traefik:traefik/',{waitUntil:'domcontentloaded'});
  check('administrator existing identity requires no new registration',await page.locator('input[name="username"]').count()===0);
  await page.goto(origin+'/settings/',{waitUntil:'domcontentloaded'});
  const cookie=(await adminContext.cookies(origin)).find(c=>c.name==='phusr');
  check('password session binds original siteadmin',cookie?.value==='siteadmin');
  const csrf=await page.locator('input[name="__csrf__"]').first().inputValue();
  const who=await adminContext.request.post(origin+'/api/user.whoami',{form:{params:'{}',output:'json',__csrf__:csrf}});
  const actor=await who.json();
  check('actual Conduit caller remains enabled approved site administrator',!actor.error_code && actor.result?.userName==='siteadmin'
    && actor.result?.roles?.includes('admin') && actor.result?.roles?.includes('approved') && !actor.result?.roles?.includes('disabled'));
  stage='existing OTP sessions';
  for(const username of ['test_admin','a_lead','a_member','b_lead','b_member','guest']) {
    const context=await browser.newContext({ignoreHTTPSErrors:true,storageState:path.join(root,'state/acceptance/browser',username+'.json')});
    try {
      const oldPage=await context.newPage();
      const settings=await oldPage.goto(origin+'/settings/',{waitUntil:'domcontentloaded'});
      const oldCookie=(await context.cookies(origin)).find(c=>c.name==='phusr');
      check('existing OTP session remains usable: '+username,settings.status()===200 && oldCookie?.value===username && new URL(oldPage.url()).pathname.startsWith('/settings/'));
      const token=await oldPage.locator('input[name="__csrf__"]').first().inputValue();
      const response=await context.request.post(origin+'/api/user.whoami',{form:{params:'{}',output:'json',__csrf__:token}});
      const body=await response.json();
      check('existing OTP session keeps its actual API identity: '+username,!body.error_code && body.result?.userName===username);
    } finally {await context.close();}
  }
} catch(error) {
  // Playwright exception messages may echo filled values; never retain them.
  report.error={stage,type:error?.name || 'Error'};
} finally {
  if(adminContext) {
    try {
      const response=await adminContext.request.post(origin+'/_logout',{headers:{Origin:origin},maxRedirects:0});
      report.adminEntryLoggedOut=[200,302,303].includes(response.status());
      if(!report.adminEntryLoggedOut)report.cleanupError='Administrator entry logout failed';
    } catch {report.cleanupError='Administrator entry logout failed';}
    await adminContext.close();
  }
  if(browser)await browser.close();
  report.passed=!report.error && !report.cleanupError && report.checks.length>0 && report.checks.every(c=>c.passed);
  fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n',{mode:0o600});
  console.log(JSON.stringify({passed:report.passed,checks:report.checks.length,error:report.error,cleanupError:report.cleanupError}));
  if(!report.passed)process.exitCode=1;
}
