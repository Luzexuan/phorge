import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {launch, stateDir, root} from './identity.mjs';

// Read-only evidence: file detail ACL versus a copied bearer download URL.
const fixture = JSON.parse(fs.readFileSync(path.join(root,'state/permissions-acceptance.json'))).fixtures.files.a_secret;
const origin = process.env.PM_URL || JSON.parse(fs.readFileSync(path.join(root,'state/acceptance/identity-browser.json'))).pmURL;
const report = {verifiedAt:new Date().toISOString(), origin, results:[]};
const browser = await launch();
try {
  for (const username of (process.argv.length>2 ? process.argv.slice(2) : ['test_admin','b_member','guest'])) {
    const context = await browser.newContext({ignoreHTTPSErrors:true, storageState:path.join(stateDir,username+'.json')});
    const page = await context.newPage();
    const settings = await page.goto(origin+'/settings/', {waitUntil:'domcontentloaded'});
    const authenticated = settings.status()===200 && new URL(page.url()).pathname.startsWith('/settings/') &&
      (await context.cookies(origin)).some(cookie=>cookie.name==='phusr' && cookie.value===username);
    if (!authenticated) throw new Error('No authenticated session for '+username);
    const detail = await page.goto(origin+fixture.url, {waitUntil:'domcontentloaded'});
    const detailBody = await page.locator('body').innerText();
    const entry = {username, authenticated, detailStatus:detail.status(), detailDenied:detailBody.includes('You do not have permission to'), detailContainsFilename:detailBody.includes('ACC26-private-attachment.txt')};
    const response = await page.goto(origin+new URL(fixture.downloadUrl).pathname, {waitUntil:'domcontentloaded'});
    entry.downloadGetStatus = response.status();
    const downloadBody = await page.locator('body').innerText();
    entry.downloadGetDenied = [403,404].includes(response.status()) || downloadBody.includes('You do not have permission to');
    entry.downloadGetContainsMarker = downloadBody.includes(fixture.marker);
    entry.interstitial = await page.getByRole('button',{name:'Download File',exact:true}).count() > 0;
    if (entry.interstitial) {
      page.on('response', response => {
        if (response.request().method()==='POST' && new URL(response.url()).pathname===new URL(fixture.downloadUrl).pathname) {
          entry.downloadPostStatus=response.status();
          entry.downloadCacheControl=response.headers()['cache-control'];
        }
      });
      const [download] = await Promise.all([
        page.waitForEvent('download', {timeout:10000}),
        page.getByRole('button',{name:'Download File',exact:true}).click(),
      ]);
      const stream = await download.createReadStream();
      const chunks = [];
      for await (const chunk of stream) chunks.push(chunk);
      const bytes = Buffer.concat(chunks);
      entry.downloadBytes = bytes.length;
      entry.downloadSha256 = createHash('sha256').update(bytes).digest('hex');
      entry.exactPrivateBytes = entry.downloadSha256===fixture.sha256 && bytes.length===fixture.bytes;
    }
    report.results.push(entry);
    console.log(JSON.stringify(entry));
    await context.close();
  }
} catch (error) {
  report.error=error.message;
  console.error(error.message);
  process.exitCode=1;
} finally {
  await browser.close();
  fs.writeFileSync(path.join(root,'state/acceptance/file-bearer-browser.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
}
