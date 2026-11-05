<?php

// Synthetic browser fixtures. This script intentionally refuses production.
require_once '/opt/phorge/phorge/scripts/__init_script__.php';
if (getenv('TEAM_PROJECT_ISOLATED_UI') !== '1' ||
    PhabricatorEnv::getEnvConfig('storage.default-namespace') !== 'project_regression_base' ||
    !preg_match('/^team-project-regression-[a-f0-9]{8}-db$/D',
      PhabricatorEnv::getEnvConfig('mysql.host'))) {
  throw new Exception('Only the disposable project regression database is allowed.');
}

function ui_project($phid) {
  return id(new PhabricatorProjectQuery())
    ->setViewer(PhabricatorUser::getOmnipotentUser())
    ->withPHIDs(array($phid))->needMembers(true)->executeOne();
}
function ui_check($condition, $message) {
  if (!$condition) { throw new Exception($message); }
}

if (isset($argv[1]) && $argv[1] === '--verify') {
  $fixture = phutil_json_decode(file_get_contents('php://stdin'));
  $created = id(new PhabricatorProjectQuery())
    ->setViewer(PhabricatorUser::getOmnipotentUser())
    ->withNames(array($fixture['createdName']))->needMembers(true)->executeOne();
  ui_check($created !== null, 'Browser form did not persist a project.');
  ui_check($created->getParentProjectPHID() === $fixture['projects']['empty']['phid'],
    'Browser creation selected an unexpected parent.');
  ui_check($created->getViewPolicy() === $fixture['owner']['phid'] &&
    $created->getEditPolicy() === $fixture['owner']['phid'] &&
    $created->getJoinPolicy() === PhabricatorPolicies::POLICY_NOONE,
    'Browser-selected policies changed during creation.');
  ui_check(!in_array($fixture['member']['phid'], $created->getMemberPHIDs()),
    'The first child copied a parent member.');
  $parent = ui_project($fixture['projects']['empty']['phid']);
  ui_check(in_array($fixture['member']['phid'], $parent->getMemberPHIDs()),
    'Creating the child removed an existing parent member.');
  echo json_encode(array('passed' => true, 'createdProjectID' => (int)$created->getID(),
    'checks' => array('actual form preserved selected view/edit/join',
      'first child did not copy parent members', 'parent retained explicit members')))."\n";
  exit;
}

// A failed browser attempt may leave its synthetic projects in this disposable
// base schema. Delete only exact fixture names owned by the matching fixture
// user, deepest first, through the native destruction engine before retrying.
$prior = id(new PhabricatorProjectQuery())
  ->setViewer(PhabricatorUser::getOmnipotentUser())->execute();
$cleanup = array();
foreach ($prior as $project) {
  if (!preg_match('/^(?:10 Alpha Root|11 Alpha Child|12 Alpha Grandchild|'.
      '13 Confidential Child|20 Bravo Root|30 Creation Parent|UI First Created) '.
      '([a-z2-7]{8})$/D', $project->getName(), $matches)) {
    continue;
  }
  $author = id(new PhabricatorPeopleQuery())
    ->setViewer(PhabricatorUser::getOmnipotentUser())
    ->withPHIDs(array($project->getAuthorPHID()))->executeOne();
  ui_check($author && $author->getUsername() === 'projectuiowner'.$matches[1] &&
    !$author->getIsAdmin(), 'Unsafe old browser fixture cleanup target.');
  $cleanup[] = $project;
}
usort($cleanup, function($a, $b) {
  return $b->getProjectDepth() - $a->getProjectDepth();
});
foreach ($cleanup as $project) {
  $project = ui_project($project->getPHID());
  if ($project) { id(new PhabricatorDestructionEngine())->destroyObject($project); }
}

$token = Filesystem::readRandomCharacters(8);
$users = array();
foreach (array('owner', 'member') as $role) {
  $user = id(new PhabricatorUser())
    ->setUsername('projectui'.$role.$token)
    ->setRealName('Isolated Project UI '.$role)
    ->setIsApproved(1)->setIsEmailVerified(1)->save();
  id(new PhabricatorUserEmail())
    ->setUserPHID($user->getPHID())
    ->setAddress($user->getUsername().'@project-ui.invalid')
    ->setIsPrimary(1)->setIsVerified(1)->save();
  $users[$role] = id(new PhabricatorPeopleQuery())
    ->setViewer(PhabricatorUser::getOmnipotentUser())
    ->withPHIDs(array($user->getPHID()))->needUserSettings(true)->executeOne();
}
$owner = $users['owner'];
$member = $users['member'];
$projects = array();
$specs = array(
  'root' => array('10 Alpha Root', null, false),
  'child' => array('11 Alpha Child', 'root', false),
  'grandchild' => array('12 Alpha Grandchild', 'child', false),
  'private' => array('13 Confidential Child', 'root', true),
  'second' => array('20 Bravo Root', null, false),
  'empty' => array('30 Creation Parent', null, false),
);
foreach ($specs as $key => $spec) {
  list($name, $parent_key, $private) = $spec;
  $transactions = array(
    array('type' => 'name', 'value' => $name.' '.$token),
    array('type' => 'view', 'value' => $private
      ? $owner->getPHID() : PhabricatorPolicies::POLICY_USER),
    array('type' => 'edit', 'value' => $owner->getPHID()),
    array('type' => 'join', 'value' => PhabricatorPolicies::POLICY_NOONE),
  );
  if ($parent_key) {
    $transactions[] = array('type' => 'parent', 'value' => $projects[$parent_key]['phid']);
  } else {
    $transactions[] = array('type' => 'members.set', 'value' => array($member->getPHID()));
  }
  $result = id(new ConduitCall('project.edit', array('transactions' => $transactions)))
    ->setUser($owner)->execute();
  $project = ui_project($result['object']['phid']);
  $projects[$key] = array('id' => (int)$project->getID(),
    'phid' => $project->getPHID(), 'name' => $project->getName());
}
$fixture = array('scope' => 'Disposable project_regression_base synthetic objects only.',
  'projects' => $projects, 'createdName' => 'UI First Created '.$token);
foreach ($users as $role => $user) {
  $fixture[$role] = array('username' => $user->getUsername(), 'phid' => $user->getPHID(),
    'session' => id(new PhabricatorAuthSessionEngine())->establishSession(
      PhabricatorAuthSession::TYPE_WEB, $user->getPHID(), false));
}
// The parent runner captures this privately; session tokens must not be logged.
echo json_encode($fixture, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)."\n";
