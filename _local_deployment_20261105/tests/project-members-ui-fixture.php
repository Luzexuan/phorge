<?php
require_once '/opt/phorge/phorge/scripts/__init_script__.php';
if (getenv('TEAM_PROJECT_ISOLATED_UI') !== '1' ||
    PhabricatorEnv::getEnvConfig('storage.default-namespace') !== 'project_regression_base' ||
    !preg_match('/^team-project-regression-[a-f0-9]{8}-db$/D', PhabricatorEnv::getEnvConfig('mysql.host'))) {
  throw new Exception('Only the disposable project member regression database is allowed.');
}
function member_ui_check($ok, $message) { if (!$ok) { throw new Exception($message); } }
function member_ui_user($phid) {
  return id(new PhabricatorPeopleQuery())->setViewer(PhabricatorUser::getOmnipotentUser())
    ->withPHIDs(array($phid))->needUserSettings(true)->executeOne();
}
function member_ui_project($phid) {
  return id(new PhabricatorProjectQuery())->setViewer(PhabricatorUser::getOmnipotentUser())
    ->withPHIDs(array($phid))->needMembers(true)->needAncestorMembers(true)->executeOne();
}
if (isset($argv[1]) && $argv[1] === '--verify') {
  $f = phutil_json_decode(file_get_contents('php://stdin'));
  $owner = member_ui_user($f['owner']['phid']);
  $created = id(new PhabricatorProjectQuery())->setViewer($owner)
    ->withNames(array($f['newName']))->needMembers(true)->needAncestorMembers(true)->executeOne();
  member_ui_check($created, 'Browser-created project missing.');
  $actual = $created->getDirectMemberPHIDs(); sort($actual);
  $expected = array($f['editor']['phid'], $f['reader']['phid'], $f['teamuser']['phid']); sort($expected);
  member_ui_check($actual === $expected, 'Initial member sources must expand and deduplicate without copying owner or roles.');
  member_ui_check(TeamProjectMembership::canManage($owner, $created), 'New creator must manage project.');
  member_ui_check(!TeamOrganizationProjectBoundary::newGuard($created), 'Creation must not set an extra team restriction.');
  foreach (array('view', 'edit', 'join') as $cap) {
    $policy = TeamProjectAccessService::getPolicy($owner, $created, $cap);
    $rules = $policy->getRules();
    member_ui_check(count($rules) === 1 && head($rules)['rule'] === TeamOrganizationDirectPolicyRule::class &&
      head($rules)['value'] === array($f['teams']['allowed']['phid']), 'Three direct team dropdown policies must persist.');
  }
  $target = member_ui_project($f['projects']['target']['phid']);
  $editor = member_ui_user($f['editor']['phid']);
  member_ui_check(TeamProjectMembership::getRole($target, $editor->getPHID()) === 'viewer', 'Editor downgrade must persist.');
  member_ui_check(!PhabricatorPolicyFilter::hasCapability($editor, $target, 'edit') &&
    PhabricatorPolicyFilter::hasCapability($editor, $target, 'view'), 'Read-only role must override broad edit policy while preserving view.');
  member_ui_check(!TeamProjectMembership::canManage($editor, $target), 'Editors/readers may not manage members.');
  member_ui_check(!in_array($f['outsider']['phid'], $target->getDirectMemberPHIDs()), 'Added outsider must be removed.');
  member_ui_check(TeamProjectMembership::canManage($owner, $target), 'Last administrator must remain.');
  member_ui_check(!TeamProjectProgress::canPublish($editor, $target), 'Downgraded member cannot publish.');
  echo json_encode(array('passed' => true, 'createdProjectID' => (int)$created->getID(), 'checks' => array(
    'three team policies persisted', 'no create boundary', 'initial mixed sources expanded once',
    'source roles not copied', 'creator retains management', 'read-only overrides broad edit grants',
    'ordinary editor cannot manage', 'member add/remove persisted', 'last administrator retained')))."\n";
  exit;
}
$suffix = Filesystem::readRandomCharacters(8); $users = array();
foreach (array('owner','editor','reader','teamuser','outsider','admin') as $key) {
  $user = id(new PhabricatorUser())->setUsername('memberui'.$key.$suffix)->setRealName('Member UI '.$key.' '.$suffix)
    ->setIsApproved(1)->setIsEmailVerified(1)->setIsAdmin($key === 'admin' ? 1 : 0)->save();
  id(new PhabricatorUserEmail())->setUserPHID($user->getPHID())->setAddress($user->getUsername().'@members.invalid')
    ->setIsPrimary(1)->setIsVerified(1)->save();
  $users[$key] = member_ui_user($user->getPHID());
}
$teams = array();
foreach (array('allowed'=>'users','hiddenRoster'=>'admin') as $key=>$roster) {
  $team = TeamOrganizationService::saveTeam($users['admin'], null, array('name'=>'Member UI Team '.$key.' '.$suffix,
    'viewPolicy'=>'users','membersPolicy'=>$roster));
  $team = TeamOrganizationService::setMembers($users['admin'], $team,
    array($users['teamuser']->getPHID(),$users['reader']->getPHID()), $team->getVersion());
  $teams[$key] = array('id'=>(int)$team->getID(),'phid'=>$team->getPHID(),'name'=>$team->getName());
}
$projects = array();
foreach (array('source','target','hidden') as $key) {
  $actor = $key === 'hidden' ? $users['admin'] : $users['owner'];
  $tx = array(array('type'=>'name','value'=>'Member UI '.$key.' '.$suffix),
    array('type'=>'view','value'=>$key === 'hidden' ? $actor->getPHID() : 'users'),
    array('type'=>'edit','value'=>$key === 'target' ? 'users' : $actor->getPHID()),
    array('type'=>'join','value'=>'no-one'));
  if ($key !== 'hidden') { $tx[] = array('type'=>'members.set','value'=>array($users['editor']->getPHID(),$users['reader']->getPHID())); }
  $r = id(new ConduitCall('project.edit',array('transactions'=>$tx)))->setUser($actor)->execute();
  $p = member_ui_project($r['object']['phid']);
  $projects[$key] = array('id'=>(int)$p->getID(),'phid'=>$p->getPHID(),'name'=>$p->getName());
}
$named = id(new PhorgeNamedPolicy())->setName('Member UI Named '.$suffix)
  ->setTargetObjectType('PROJ')->setEffectivePolicy(PhabricatorPolicies::POLICY_USER)->save();
$f = array('teams'=>$teams,'projects'=>$projects,'newName'=>'Member UI Created '.$suffix);
$f['namedPolicy'] = array('id'=>(int)$named->getID(),'phid'=>$named->getPHID(),'name'=>$named->getName());
foreach ($users as $key=>$user) {
  $f[$key] = array('username'=>$user->getUsername(),'phid'=>$user->getPHID(),
    'session'=>id(new PhabricatorAuthSessionEngine())->establishSession(PhabricatorAuthSession::TYPE_WEB,$user->getPHID(),false));
}
echo json_encode($f,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)."\n";
