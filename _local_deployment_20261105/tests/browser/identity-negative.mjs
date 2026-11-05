import fs from 'node:fs';
import path from 'node:path';
import {root,pmURL,authURL,launch,delay,waitMail,phorgeLogin,stateDir} from './identity.mjs';

const browser=await launch();
const results=[];
let originalStatus;
const directory=path.join(root,'config/warden/users.json');
function status(value) {
  const users=JSON.parse(fs.readFileSync(directory,'utf8'));
  const guest=users.find(u=>u.user_id==='acc-guest');
  if(!guest) throw new Error('guest allowlist fixture missing');
  if(originalStatus===undefined) originalStatus=guest.status;
  guest.status=value;
  fs.writeFileSync(directory,JSON.stringify(users,null,2)+'\n');
}
function check(name,condition,details={}) {
  results.push({name,passed:!!condition,...details});
  console.log((condition?'PASS ':'FAIL ')+name);
  if(!condition) throw new Error(name+' failed');
}
async function post(context,url,form) {
  for(let attempt=0;attempt<4;attempt++) {
    const response=await context.request.post(url,{form,maxRedirects:0,headers:{Accept:'application/json','X-Requested-With':'XMLHttpRequest'}});
    if(response.status()!==429) return response;
    await delay(61000);
  }
  throw new Error('API stayed rate limited');
}
try {
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const outsider=await post(context,authURL+'/_send_verify_code',{mail:'outsider@acceptance.test',deliver_via:'email'});
  check('Warden rejects unlisted identity',outsider.status()===401,{httpStatus:outsider.status()});
  const sentAt=Date.now();
  const response=await post(context,authURL+'/_send_verify_code',{mail:'guest@acceptance.test',deliver_via:'email'});
  const challenge=await response.json();
  check('Herald creates real non-debug challenge',response.status()===200&&challenge.success&&!!challenge.challenge_id&&!challenge.debug_code);
  const code=await waitMail('guest@acceptance.test',sentAt);
  const form={auth_method:'warden',mail:'guest@acceptance.test',challenge_id:challenge.challenge_id};
  const wrong=await post(context,authURL+'/_login',{...form,verify_code:code==='000000'?'111111':'000000'});
  check('Incorrect OTP denied',wrong.status()===401,{httpStatus:wrong.status()});
  const callback=new URL(pmURL).host!==new URL(authURL).host ? {callback:new URL(pmURL).host} : {};
  const accepted=await post(context,authURL+'/_login',{...form,verify_code:code,...callback});
  check('Correct OTP succeeds after one incorrect attempt',accepted.status()===200,{httpStatus:accepted.status()});
  const acceptedJSON=await accepted.json();
  const page=await context.newPage();
  await page.goto(acceptedJSON.redirect || pmURL+'/',{waitUntil:'domcontentloaded'});
  await phorgeLogin(context,page,'guest',{register:false});
  const replayContext=await browser.newContext({ignoreHTTPSErrors:true});
  const replay=await post(replayContext,authURL+'/_login',{...form,verify_code:code});
  check('Consumed OTP cannot create a second login',replay.status()===401,{httpStatus:replay.status()});
  await replayContext.close();
  status('inactive');
  await delay(42000);
  const blocked=await post(context,authURL+'/_send_verify_code',{mail:'guest@acceptance.test',deliver_via:'email'});
  check('Warden disabled identity cannot request OTP',blocked.status()===401,{httpStatus:blocked.status()});
  const guarded=await context.request.get(pmURL+'/settings/',{maxRedirects:0});
  const redirectPath=guarded.headers().location ? new URL(guarded.headers().location,pmURL).pathname : null;
  check('Existing session loses entry after Warden disable',guarded.status()===401||([302,303,307].includes(guarded.status())&&redirectPath==='/_login'),{httpStatus:guarded.status(),redirectPath});
  status(originalStatus);
  await delay(12000);
  const old=await browser.newContext({ignoreHTTPSErrors:true,storageState:path.join(stateDir,'guest.json')});
  const revoked=await old.request.get(pmURL+'/settings/',{maxRedirects:0});
  const revokedPath=revoked.headers().location ? new URL(revoked.headers().location,pmURL).pathname : null;
  check('Reactivation does not restore revoked entry session',revoked.status()===401||revokedPath==='/_login',{httpStatus:revoked.status(),redirectPath:revokedPath});
  await old.close();
  await context.close();
} finally {
  if(originalStatus!==undefined) status(originalStatus);
  await browser.close();
  fs.writeFileSync(path.join(root,'state/acceptance/identity-negative.json'),JSON.stringify({verifiedAt:new Date().toISOString(),pmURL,authURL,results},null,2)+'\n',{mode:0o600});
}
