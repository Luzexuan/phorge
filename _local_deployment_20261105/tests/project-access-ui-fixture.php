<?php

require_once '/opt/phorge/phorge/scripts/__init_script__.php';
if (getenv('TEAM_PROJECT_ISOLATED_UI') !== '1' ||
    PhabricatorEnv::getEnvConfig('storage.default-namespace') !== 'project_regression_base' ||
    !preg_match('/^team-project-regression-[a-f0-9]{8}-db$/D', PhabricatorEnv::getEnvConfig('mysql.host'))) {
  throw new Exception('Only the disposable project access regression database is allowed.');
}
function access_ui_check($test, $message) { if (!$test) { throw new Exception($message); } }
function access_ui_user($phid) {
  return id(new PhabricatorPeopleQuery())->setViewer(PhabricatorUser::getOmnipotentUser())
    ->withPHIDs(array($phid))->needUserSettings(true)->executeOne();
}
function access_ui_project($phid) {
  return id(new PhabricatorProjectQuery())->setViewer(PhabricatorUser::getOmnipotentUser())
    ->withPHIDs(array($phid))->needMembers(true)->needAncestorMembers(true)->executeOne();
}
function access_ui_policy(array $rules) {
  return id(new PhabricatorPolicy())->setRules($rules)
    ->setDefaultAction(PhabricatorPolicy::ACTION_DENY)->save()->getPHID();
}
function access_ui_allow($rule, array $value) {
  return array('action' => PhabricatorPolicy::ACTION_ALLOW, 'rule' => $rule, 'value' => $value);
}

if (isset($argv[1]) && $argv[1] === '--verify') {
  $f = phutil_json_decode(file_get_contents('php://stdin'));
  $manager = access_ui_user($f['manager']['phid']);
  $project = access_ui_project($f['projects']['main']['phid']);
  foreach (array('manager' => true, 'parent' => true, 'child' => false, 'outsider' => true, 'member' => true) as $role => $allowed) {
    $viewer = access_ui_user($f[$role]['phid']);
    $visible = id(new PhabricatorProjectQuery())->setViewer($viewer)
      ->withPHIDs(array($project->getPHID()))->execute();
    access_ui_check((bool)$visible === $allowed, 'Unexpected final view permission: '.$role);
  }
  access_ui_check(!TeamProjectAccessService::canManage(access_ui_user($f['outsider']['phid']), $project),
    'Revoked edit grant must remove management access while retaining view.');
  access_ui_check(TeamProjectAccessService::canManage($manager, $project) && !$manager->getIsAdmin(),
    'Project permissions are managed by a project editor without site admin.');
  access_ui_check(in_array($f['member']['phid'], $project->getMemberPHIDs()),
    'Replacing view rules must not silently remove existing project membership.');
  $parent = access_ui_user($f['parent']['phid']);
  access_ui_check(PhabricatorPolicyFilter::hasCapability($parent, $project, PhabricatorPolicyCapability::CAN_JOIN),
    'Independent team join grant must persist.');
  $strict = access_ui_project($f['projects']['strict']['phid']);
  access_ui_check(!TeamOrganizationProjectBoundary::newGuard($strict),
    'Explicit boundary clear must persist.');
  $parent_team = id(new TeamOrganizationTeamQuery())->setViewer(access_ui_user($f['admin']['phid']))
    ->withPHIDs(array($f['teams']['parent']['phid']))->executeOne();
  $team_members = TeamOrganizationService::getMemberPHIDs($parent_team); sort($team_members);
  $expected_members = array($f['manager']['phid'], $f['parent']['phid']); sort($expected_members);
  access_ui_check($team_members === $expected_members, 'Project grant removal must not change global team memberships.');
  $hidden = access_ui_project($f['projects']['hidden']['phid']);
  foreach (TeamProjectAccessService::getPolicy($manager, $hidden, 'view')->getRules() as $rule) {
    access_ui_check(!in_array($f['teams']['hidden']['phid'], (array)idx($rule, 'value')),
      'Hidden team allow rule must be removable without disclosing its identity.');
  }
  $presets = access_ui_project($f['projects']['presets']['phid']);
  foreach (array('manager' => true, 'member' => true, 'parent' => false, 'child' => false,
    'outsider' => false, 'blocked' => false) as $role => $allowed) {
    access_ui_check(PhabricatorPolicyFilter::hasCapability(access_ui_user($f[$role]['phid']),
      $presets, PhabricatorPolicyCapability::CAN_VIEW) === $allowed,
      'Cleared explicit grants must retain only native visibility sources: '.$role);
  }
  access_ui_check($presets->getEditPolicy() === $manager->getPHID() &&
    $presets->getJoinPolicy() === PhabricatorPolicies::POLICY_NOONE,
    'View presets must leave edit and join policies unchanged.');
  $boundary = access_ui_project($f['projects']['boundary']['phid']);
  access_ui_check(!TeamOrganizationProjectBoundary::newGuard($boundary) &&
    $boundary->getViewPolicy() === PhabricatorPolicies::POLICY_USER &&
    $boundary->getEditPolicy() === $manager->getPHID() &&
    $boundary->getJoinPolicy() === PhabricatorPolicies::POLICY_NOONE,
    'Project-wide boundary choices must not rewrite any explicit capability policy.');
  $mixed = access_ui_project($f['projects']['mixed']['phid']);
  foreach (array('parent', 'child', 'outsider', 'member', 'blocked') as $role) {
    access_ui_check(!PhabricatorPolicyFilter::hasCapability(access_ui_user($f[$role]['phid']),
      $mixed, PhabricatorPolicyCapability::CAN_VIEW),
      'Both independent mixed-scope team sources must be removable: '.$role);
  }
  access_ui_check(TeamProjectAccessService::canManage($manager, $mixed),
    'Removing both team sources must retain the independently authorized manager.');
  $named = id(new PhorgeNamedPolicy())->load($f['namedPolicy']['id']);
  access_ui_check($named && $named->getEffectivePolicy() === PhabricatorPolicies::POLICY_USER,
    'Explicitly replacing a project policy must not rewrite the named policy object.');
  $named_project = access_ui_project($f['projects']['named']['phid']);
  access_ui_check($named_project->getViewPolicy() !== $named->getPHID() &&
    !PhabricatorPolicyFilter::hasCapability(access_ui_user($f['blocked']['phid']),
      $named_project, PhabricatorPolicyCapability::CAN_VIEW),
    'Explicit named-policy replacement must persist on the project only.');
  echo json_encode(array('passed' => true, 'checks' => array(
    'user and team grants combine without site admin', 'replace only changes selected explicit rules',
    'existing membership retained', 'revoked edit loses management but keeps other view grant',
    'team join grant remains independent', 'strict boundary cleared only by explicit choice',
    'hidden team rule removed without membership changes', 'global team memberships unchanged',
    'explicit view presets preserve automatic membership and other capabilities',
    'project-wide boundary changes preserve explicit policies',
    'mixed team scopes independently revoked', 'named policy object unchanged after explicit replacement')))."\n";
  exit;
}

$token = Filesystem::readRandomCharacters(8);
$users = array();
foreach (array('admin', 'manager', 'parent', 'child', 'outsider', 'member', 'blocked') as $role) {
  $user = id(new PhabricatorUser())->setUsername('accessui'.$role.$token)
    ->setRealName('Access UI '.$role.' '.$token)->setIsApproved(1)
    ->setIsEmailVerified(1)->setIsAdmin($role === 'admin' ? 1 : 0)->save();
  id(new PhabricatorUserEmail())->setUserPHID($user->getPHID())
    ->setAddress($user->getUsername().'@access.invalid')->setIsPrimary(1)->setIsVerified(1)->save();
  $users[$role] = access_ui_user($user->getPHID());
}
$admin = $users['admin']; $manager = $users['manager']; $teams = array();
foreach (array('parent' => array(null, array('manager', 'parent'), 'users'),
  'child' => array('parent', array('child'), 'users'),
  'other' => array(null, array('outsider', 'member'), 'users'),
  'hidden' => array(null, array('parent'), 'admin')) as $key => $spec) {
  $team = TeamOrganizationService::saveTeam($admin, null, array('name' => 'Access Team UI '.$key.' '.$token,
    'description' => 'Permission browser fixture '.$key, 'parentPHID' => $spec[0] ? $teams[$spec[0]]['phid'] : null,
    'viewPolicy' => $spec[2], 'membersPolicy' => 'admin', 'isArchived' => false));
  $members = array(); foreach ($spec[1] as $role) { $members[] = $users[$role]->getPHID(); }
  $team = TeamOrganizationService::setMembers($admin, $team, $members, $team->getVersion());
  $teams[$key] = array('id' => (int)$team->getID(), 'phid' => $team->getPHID(), 'name' => $team->getName());
}
$named = id(new PhorgeNamedPolicy())->setName('Access Named UI '.$token)
  ->setTargetObjectType('PROJ')->setEffectivePolicy(PhabricatorPolicies::POLICY_USER)->save();
$projects = array();
foreach (array('main', 'strict', 'hidden', 'deny', 'global', 'parent', 'child', 'milestone',
  'mixed', 'presets', 'boundary', 'named') as $key) {
  $transactions = array(array('type' => 'name', 'value' => 'Access UI '.$key.' '.$token),
    array('type' => 'view', 'value' => $manager->getPHID()),
    array('type' => 'edit', 'value' => $manager->getPHID()),
    array('type' => 'join', 'value' => PhabricatorPolicies::POLICY_NOONE));
  if (in_array($key, array('main', 'strict', 'presets', 'boundary'), true)) {
    $transactions[] = array('type' => 'members.set', 'value' => array($manager->getPHID(), $users['member']->getPHID()));
  }
  if ($key === 'strict') {
    $transactions[] = array('type' => 'organization.teams', 'value' => array($teams['parent']['phid']));
    $transactions[] = array('type' => 'organization.scope', 'value' => 'direct');
  }
  if ($key === 'global' || $key === 'boundary') { $transactions[1]['value'] = PhabricatorPolicies::POLICY_USER; }
  if ($key === 'named') { $transactions[1]['value'] = $named->getPHID(); }
  if ($key === 'hidden') {
    $transactions[1]['value'] = access_ui_policy(array(
      access_ui_allow(PhabricatorUsersPolicyRule::class, array($manager->getPHID())),
      access_ui_allow(TeamOrganizationDirectPolicyRule::class, array($teams['hidden']['phid']))));
  }
  if ($key === 'deny') {
    $deny = access_ui_allow(PhabricatorUsersPolicyRule::class, array($users['blocked']->getPHID()));
    $deny['action'] = PhabricatorPolicy::ACTION_DENY;
    $transactions[1]['value'] = access_ui_policy(array($deny,
      access_ui_allow(PhabricatorUsersPolicyRule::class, array($manager->getPHID()))));
  }
  if ($key === 'child' || $key === 'milestone') {
    $transactions[] = array('type' => ($key === 'milestone' ? 'milestone' : 'parent'), 'value' => $projects['parent']['phid']);
    if ($key === 'milestone') { $transactions = array($transactions[0], last($transactions)); }
  }
  $result = id(new ConduitCall('project.edit', array('transactions' => $transactions)))
    ->setUser($manager)->execute();
  // Keep the original access suite as legacy-policy regression coverage.
  access_ui_project($result['object']['phid'])->setProperty(TeamProjectMembership::ROLES_PROPERTY, null)->save();
  $projects[$key] = array('id' => (int)$result['object']['id'], 'phid' => $result['object']['phid'],
    'name' => 'Access UI '.$key.' '.$token);
}
$fixture = array('teams' => $teams, 'projects' => $projects,
  'namedPolicy' => array('id' => (int)$named->getID(), 'phid' => $named->getPHID(), 'name' => $named->getName()));
foreach ($users as $role => $user) {
  $fixture[$role] = array('username' => $user->getUsername(), 'phid' => $user->getPHID(),
    'session' => id(new PhabricatorAuthSessionEngine())->establishSession(
      PhabricatorAuthSession::TYPE_WEB, $user->getPHID(), false));
}
echo json_encode($fixture, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)."\n";
