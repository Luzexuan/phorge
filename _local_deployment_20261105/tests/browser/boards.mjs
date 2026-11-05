import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {launch, stateDir, pmURL, root, usernames} from './identity.mjs';

// This suite uses real OTP-created browser sessions, real pages and UI actions.
// No Conduit service credentials, session synthesis or policy bypasses.
const fixtureReport = JSON.parse(fs.readFileSync(path.join(root, 'state/permissions-acceptance.json')));
if (!fixtureReport.passed) throw new Error('Create and verify policy fixtures first');
const fixtures = fixtureReport.fixtures;
const evidenceDir = path.join(root, 'state/acceptance/screenshots');
fs.mkdirSync(evidenceDir, {recursive:true, mode:0o700});
const report = {verifiedAt:new Date().toISOString(), url:pmURL, checks:[]};
function check(name, passed, detail) {
  report.checks.push({name, passed:!!passed, detail});
  console.log((passed?'PASS ':'FAIL ')+name);
}
function denied(response, body) {
  // Phorge renders some Policy denial pages with HTTP 200. Assert the denial
  // message and absence of protected content instead of assuming HTTP 403.
  return [403,404].includes(response.status()) ||
    (response.status()===200 && body.includes('You do not have permission to'));
}
async function visit(page, route) {
  for (let n=0;n<3;n++) {
    try { return await page.goto(pmURL+route, {waitUntil:'domcontentloaded'}); }
    catch (error) { if(n===2 || !String(error).includes('ERR_NETWORK_CHANGED')) throw error; }
  }
}
const browser = await launch();
try {
  const selected = process.argv.slice(2);
  for (const username of (selected.length ? selected : usernames)) {
    const context = await browser.newContext({ignoreHTTPSErrors:true,
      storageState:path.join(stateDir,username+'.json'), viewport:{width:1440,height:1000}});
    const page = await context.newPage();
    let response = await visit(page, '/settings/');
    let body = await page.locator('body').innerText();
    const signedUser=(await context.cookies(pmURL)).find(c=>c.name==='phusr')?.value;
    check(username+'/authenticated settings', response.status()===200
      && new URL(page.url()).pathname.startsWith('/settings/')
      && signedUser===username && body.includes('Settings') && !body.includes('Wait for Approval'));
    const csrf=await page.locator('input[name="__csrf__"]').first().inputValue();
    const actorResponse=await context.request.post(pmURL+'/api/user.whoami',
      {form:{params:'{}',output:'json',__csrf__:csrf}});
    const actor=await actorResponse.json();
    check(username+'/actual HTTP Conduit actor', !actor.error_code && actor.result?.userName===username);

    await visit(page, '/project/query/active/');
    body = await page.locator('body').innerText();
    for (const [key, project] of Object.entries(fixtures.projects)) {
      check(username+'/project list/'+key,
        body.includes(project.name)===project.visibleTo.includes(username));
    }
    for (const key of ['a_shared','a_secret','b_main','a_invited']) {
      const project = fixtures.projects[key];
      response = await visit(page, project.boardUrl);
      body = await page.locator('body').innerText();
      const allowed = project.visibleTo.includes(username);
      check(username+'/board/'+key, allowed
        ? response.status()===200 && body.includes(project.name)
        : denied(response,body) && !body.includes(project.name));
      if (key==='a_shared' && username==='a_member') {
        check('mixed board filters confidential card', !body.includes('ACC26SECRETACORE'));
      }
    }
    for (const key of ['a_shared','a_secret','b_private','a_invited']) {
      const task = fixtures.tasks[key];
      response = await visit(page, task.url);
      body = await page.locator('body').innerText();
      const allowed = task.visibleTo.includes(username);
      check(username+'/direct task/'+key, allowed
        ? response.status()===200 && body.includes(task.title)
        : denied(response,body) && !body.includes(task.title));
    }
    const document=fixtures.documents.a_secret;
    response=await visit(page,document.url); body=await page.locator('body').innerText();
    check(username+'/private document', document.visibleTo.includes(username)
      ? response.status()===200 && body.includes(document.marker)
      : denied(response,body) && !body.includes(document.marker));
    const file=fixtures.files.a_secret;
    const filePath=new URL(file.downloadUrl).pathname;
    response=await visit(page,filePath);
    check(username+'/private attachment response disables caching',
      (response.headers()['cache-control']||'').includes('no-store'));
    if(file.visibleTo.includes(username)) {
      const [download,downloadResponse]=await Promise.all([page.waitForEvent('download'),
        page.waitForResponse(r=>r.request().method()==='POST' && new URL(r.url()).pathname===filePath),
        page.getByRole('button',{name:'Download File',exact:true}).click()]);
      const stream=await download.createReadStream(); const chunks=[];
      for await (const chunk of stream) chunks.push(chunk);
      const bytes=Buffer.concat(chunks);
      check(username+'/private attachment exact UI download', bytes.length===file.bytes
        && createHash('sha256').update(bytes).digest('hex')===file.sha256);
      check(username+'/private binary response disables caching',
        (downloadResponse.headers()['cache-control']||'').includes('no-store'));
    } else {
      body=await page.locator('body').innerText();
      check(username+'/private attachment secret URL denied', denied(response,body)
        && !body.includes(file.marker) && !body.includes('ACC26-private-attachment.txt'));
      const attempt=await context.request.post(pmURL+filePath,{form:{__form__:'1',__csrf__:csrf}});
      const bytes=await attempt.body();
      check(username+'/private attachment direct POST denied', [403,404].includes(attempt.status())
        && createHash('sha256').update(bytes).digest('hex')!==file.sha256);
    }

    if (username==='a_member') {
      await visit(page, fixtures.projects.a_shared.boardUrl);
      await page.waitForLoadState('networkidle');
      const card = page.locator('[data-sigil~="project-card"]').filter({hasText:fixtures.tasks.a_shared.title});
      const columns=page.locator('[data-sigil~="project-column"]');
      const originalColumn=(await columns.allTextContents()).findIndex(text=>text.includes(fixtures.tasks.a_shared.title));
      const targetColumn=originalColumn===2?1:2;
      const target=columns.nth(targetColumn);
      const from = await card.boundingBox(); const to = await target.boundingBox();
      if (!from || !to) throw new Error('Card or destination column missing');
      // Phorge deliberately ignores drags which begin inside a title link.
      // Start on the card's padding, as a user would when dragging its edge.
      await page.mouse.move(from.x+4,from.y+from.height-5);
      await page.mouse.down();
      await page.mouse.move(from.x+14,from.y+from.height-5,{steps:4});
      await page.waitForTimeout(300);
      await page.mouse.move(to.x+100,to.y+30,{steps:25});
      await page.waitForTimeout(300);
      await page.mouse.up();
      // Reload verifies persistence, not only a temporary DOM drag.
      await page.waitForTimeout(1000);
      await page.reload({waitUntil:'domcontentloaded'});
      check('UI member drag persists in a different column', originalColumn!==targetColumn &&
        (await columns.nth(targetColumn).innerText()).includes(fixtures.tasks.a_shared.title),
        {fromColumn:originalColumn,toColumn:targetColumn});
      await page.screenshot({path:path.join(evidenceDir,'a-member-board.png'),fullPage:true});
      await visit(page, fixtures.tasks.a_shared.url);
      const comment='Browser acceptance by a_member '+report.verifiedAt;
      await page.locator('textarea[name="comment"]').fill(comment);
      await page.locator('button[name="__submit__"]').click();
      await page.getByText(comment,{exact:true}).first().waitFor();
      await page.reload({waitUntil:'domcontentloaded'});
      body=await page.locator('body').innerText();
      check('UI member comment persists with expected actor', body.includes(comment)
        && body.includes('a_member added a comment'));

      // Use ordinary form defaults copied from an authorized task. The server
      // still validates the submitted policies and creator permission.
      await visit(page,'/maniphest/task/edit/'+fixtures.tasks.a_shared.id+'/');
      const viewPolicy=await page.locator('input[name="policy.view"]').inputValue();
      const editPolicy=await page.locator('input[name="policy.edit"]').inputValue();
      const parameters=new URLSearchParams({'policy.view':viewPolicy,'policy.edit':editPolicy,
        projects:fixtures.projects.a_shared.phid});
      await visit(page,'/maniphest/task/edit/form/default/?'+parameters);
      if (await page.locator('input[name="policy.view"]').inputValue()!==viewPolicy ||
          await page.locator('input[name="policy.edit"]').inputValue()!==editPolicy)
        throw new Error('Private task form policies did not prefill; creation stopped');
      const title='ACC26 browser private card '+report.verifiedAt;
      await page.locator('input[name="title"]').fill(title);
      await page.locator('textarea[name="description"]').fill('Synthetic UI-created private card with explicit Team A policies.');
      await page.getByRole('button',{name:'Create New Task',exact:true}).click();
      await page.waitForURL(url=>/^\/T[0-9]+$/.test(url.pathname));
      const newTaskPath=new URL(page.url()).pathname;
      report.createdTask={path:newTaskPath,title};
      check('UI creates private card with explicit policies', (await page.locator('body').innerText()).includes(title));
      const other=await browser.newContext({ignoreHTTPSErrors:true,storageState:path.join(stateDir,'b_member.json')});
      const otherPage=await other.newPage();
      const deniedResponse=await visit(otherPage,newTaskPath);
      const otherBody=await otherPage.locator('body').innerText();
      check('UI-created private task denied to other team', denied(deniedResponse,otherBody) && !otherBody.includes(title));
      await other.close();
      await visit(page,fixtures.projects.a_shared.boardUrl);
      check('UI-created task appears on intended Team A board',
        (await page.locator('[data-sigil~="jx-workboard"]').innerText()).includes(title));
    }
    if (username==='guest') {
      await visit(page, fixtures.tasks.a_invited.url);
      const comment='Browser invited guest comment '+report.verifiedAt;
      await page.locator('textarea[name="comment"]').fill(comment);
      await page.locator('button[name="__submit__"]').click();
      await page.getByText(comment,{exact:true}).first().waitFor();
      await page.reload({waitUntil:'domcontentloaded'});
      body=await page.locator('body').innerText();
      check('UI guest comment permitted with expected actor', body.includes(comment)
        && body.includes('guest added a comment'));
      response=await visit(page,'/maniphest/task/edit/'+fixtures.tasks.a_invited.id+'/');
      check('UI guest cannot open task edit form', denied(response,await page.locator('body').innerText()));
      await visit(page, fixtures.projects.a_invited.boardUrl);
      await page.screenshot({path:path.join(evidenceDir,'guest-invited-board.png'),fullPage:true});
      response=await visit(page,fixtures.tasks.a_secret.url);
      await page.screenshot({path:path.join(evidenceDir,'guest-secret-denied.png'),fullPage:true});
    }
    await context.close();
  }
} catch(error) {
  report.error=String(error.message);
  console.error(report.error);
} finally {
  await browser.close();
  report.passed=!report.error && report.checks.every(x=>x.passed);
  fs.writeFileSync(path.join(root,'state/acceptance/boards-browser.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
}
if(!report.passed) process.exitCode=1;
