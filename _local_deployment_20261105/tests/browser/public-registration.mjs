import fs from 'node:fs';
import path from 'node:path';
import {root,launch,delay,entryLogin,phorgeLogin,pmURL,authURL} from './identity.mjs';

const browser=await launch();
const report={verifiedAt:new Date().toISOString(),pmURL,authURL,results:[]};
try {
  if(new URL(pmURL).hostname!=='45.77.36.106'||pmURL!==authURL) throw new Error('Run this probe with both URLs set to the public IP');
  await delay(6000); // Warden polls its source file every five seconds.
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const page=await context.newPage();
  await entryLogin(context,page,'public_signup_probe');
  const result=await phorgeLogin(context,page,'public_signup_probe',{register:true});
  report.results.push({name:'Whitelisted public-IP user completes browser registration',passed:result.operation==='registered',...result});
  report.results.push({name:'New public account remains gated by administrator approval',passed:result.pendingApproval});
  const outsider=await browser.newContext({ignoreHTTPSErrors:true});
  let response;
  for(let attempt=0;attempt<3;attempt++) {
    response=await outsider.request.post(authURL+'/_send_verify_code',{form:{mail:'unlisted_public_probe@acceptance.test',deliver_via:'email'},maxRedirects:0});
    if(response.status()!==429) break;
    await delay(61000);
  }
  report.results.push({name:'Unlisted public-IP registration identity is rejected before OTP',passed:response.status()===401,httpStatus:response.status()});
  for(const result of report.results) console.log((result.passed?'PASS ':'FAIL ')+result.name);
  if(report.results.some(x=>!x.passed)) process.exitCode=1;
} finally {
  await browser.close();
  fs.writeFileSync(path.join(root,'state/acceptance/public-registration.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
}
