<?php

require_once '/opt/phorge/phorge/scripts/__init_script__.php';
if (getenv('TEAM_PROJECT_ISOLATED_UI') !== '1' ||
    PhabricatorEnv::getEnvConfig('storage.default-namespace') !== 'project_regression_base' ||
    !preg_match('/^team-project-regression-[a-f0-9]{8}-db$/D', PhabricatorEnv::getEnvConfig('mysql.host'))) {
  throw new Exception('Only the disposable organization regression database is allowed.');
}
function org_ui_check($test, $message) { if (!$test) { throw new Exception($message); } }
function org_ui_user($phid) {
  return id(new PhabricatorPeopleQuery())->setViewer(PhabricatorUser::getOmnipotentUser())
    ->withPHIDs(array($phid))->needUserSettings(true)->executeOne();
}

if (isset($argv[1]) && $argv[1] === '--verify') {
  $f = phutil_json_decode(file_get_contents('php://stdin'));
  $admin = org_ui_user($f['admin']['phid']);
  $teams = id(new TeamOrganizationTeamQuery())->setViewer($admin)->execute();
  $created = array();
  foreach ($teams as $team) {
    if ($team->getName() === $f['renamedTeam']) { $created[] = $team; }
  }
  org_ui_check(count($created) === 1, 'The browser must create and rename exactly one team.');
  $team = head($created);
  org_ui_check((bool)$team->getIsArchived() &&
    $team->getParentPHID() === $f['teams']['visibleChild']['phid'] &&
    $team->getViewPolicy() === PhabricatorPolicies::POLICY_USER &&
    $team->getMembersPolicy() === PhabricatorPolicies::POLICY_ADMIN &&
    TeamOrganizationService::getMemberPHIDs($team) === array(),
    'Team edits, independent policies, archive and membership removal must persist.');
  $child = org_ui_user($f['child']['phid']);
  $child_teams = TeamOrganizationService::getUserTeams($admin, $child);
  org_ui_check(!isset($child_teams[$team->getPHID()]) &&
    isset($child_teams[$f['teams']['policyChild']['phid']]),
    'User assignment and team membership edits must agree and preserve unrelated teams.');
  org_ui_check(count(TeamOrganizationService::loadAudit($admin, $team)) >= 5,
    'Real browser changes must leave administrator audit records.');
  $roots = array();
  foreach ($teams as $candidate) {
    org_ui_check($candidate->getName() !== $f['invalidParentTeam'],
      'An invalid nonempty parent PHID must not create a team.');
    if ($candidate->getName() === $f['rootTeam']) { $roots[] = $candidate; }
  }
  org_ui_check(count($roots) === 1, 'The empty-parent browser flow must create exactly one root team.');
  $root_team = head($roots);
  org_ui_check($root_team->getParentPHID() === null &&
    $root_team->getDescription() === 'Root edit without choosing a parent.' &&
    !$root_team->getIsArchived() &&
    $root_team->getViewPolicy() === PhabricatorPolicies::POLICY_USER &&
    $root_team->getMembersPolicy() === PhabricatorPolicies::POLICY_ADMIN &&
    TeamOrganizationService::getMemberPHIDs($root_team) === array($f['child']['phid']),
    'Creating, editing and detaching a root must preserve its privacy settings and members.');
  org_ui_check(count(TeamOrganizationService::loadAudit($admin, $root_team)) >= 5,
    'Root create/edit, membership assignment, parent assignment and parent clearing must be audited.');
  $project = id(new PhabricatorProjectQuery())->setViewer($admin)
    ->withPHIDs(array($f['project']['phid']))->needMembers(true)->executeOne();
  org_ui_check(in_array($f['outsider']['phid'], $project->getMemberPHIDs()),
    'The outside project member must remain a member; the boundary controls access.');
  org_ui_check($project->getProperty(TeamOrganizationProjectBoundary::TEAMS_PROPERTY) ===
    array($f['teams']['policyParent']['phid']) &&
    $project->getProperty(TeamOrganizationProjectBoundary::SCOPE_PROPERTY) === 'descendants',
    'The native project form must persist its team boundary and descendant scope.');
  foreach (array('parent' => true, 'child' => true, 'outsider' => false) as $role => $allowed) {
    $viewer = org_ui_user($f[$role]['phid']);
    $visible = id(new PhabricatorProjectQuery())->setViewer($viewer)
      ->withPHIDs(array($project->getPHID()))->execute();
    org_ui_check((bool)$visible === $allowed, 'Unexpected final project access for '.$role);
  }
  echo json_encode(array('passed' => true, 'createdTeamID' => (int)$team->getID(),
    'checks' => array('native team create/edit persisted', 'independent team and roster policies',
      'empty-parent create/edit/detach persisted', 'detaching preserves privacy and members',
      'invalid nonempty parent rejected without creating a team',
      'user and team membership entry points agree', 'archive only removed memberships',
      'audit retained', 'native project boundary stored', 'existing project member denied outside boundary')))."\n";
  exit;
}

$token = Filesystem::readRandomCharacters(8);
$users = array();
foreach (array('admin', 'parent', 'child', 'outsider', 'secret') as $role) {
  $user = id(new PhabricatorUser())->setUsername('orgui'.$role.$token)
    ->setRealName('Organization UI '.$role.' '.$token)->setIsApproved(1)
    ->setIsEmailVerified(1)->setIsAdmin($role === 'admin' ? 1 : 0)->save();
  id(new PhabricatorUserEmail())->setUserPHID($user->getPHID())
    ->setAddress($user->getUsername().'@organization.invalid')->setIsPrimary(1)->setIsVerified(1)->save();
  $users[$role] = org_ui_user($user->getPHID());
}
$admin = $users['admin'];
$teams = array();
$specs = array(
  'policyParent' => array(null, 'users', 'users', array('admin', 'parent')),
  'policyChild' => array('policyParent', 'users', 'users', array('child')),
  'hiddenParent' => array(null, 'admin', 'admin', array()),
  'visibleChild' => array('hiddenParent', 'users', 'admin', array('child')),
  'grandchild' => array('visibleChild', 'users', 'admin', array()),
  'hiddenChild' => array('policyParent', 'admin', 'admin', array('child', 'secret')),
  'rosterPrivate' => array(null, 'users', 'admin', array('child')),
  'privateLocal' => array(null, TeamOrganizationTeam::DEFAULT_MEMBERS_POLICY, 'admin', array('child')),
);
foreach ($specs as $key => $spec) {
  $team = TeamOrganizationService::saveTeam($admin, null, array(
    'name' => 'Org UI '.$key.' '.$token, 'description' => 'Organization detail '.$key.' '.$token,
    'parentPHID' => $spec[0] ? $teams[$spec[0]]['phid'] : null,
    'viewPolicy' => $spec[1], 'membersPolicy' => $spec[2], 'isArchived' => false));
  $members = array();
  foreach ($spec[3] as $role) { $members[] = $users[$role]->getPHID(); }
  if ($members) { $team = TeamOrganizationService::setMembers($admin, $team, $members, $team->getVersion()); }
  $teams[$key] = array('id' => (int)$team->getID(), 'phid' => $team->getPHID(),
    'name' => $team->getName(), 'description' => $team->getDescription());
}
$project = id(new ConduitCall('project.edit', array('transactions' => array(
  array('type' => 'name', 'value' => 'Organization UI project '.$token),
  array('type' => 'view', 'value' => PhabricatorPolicies::POLICY_USER),
  array('type' => 'edit', 'value' => $admin->getPHID()),
  array('type' => 'join', 'value' => PhabricatorPolicies::POLICY_NOONE),
  array('type' => 'members.set', 'value' => array($users['outsider']->getPHID())),
))))->setUser($admin)->execute();
$fixture = array('teams' => $teams,
  'createdTeam' => 'Org UI created '.$token, 'renamedTeam' => 'Org UI renamed '.$token,
  'rootTeam' => 'Org UI root '.$token, 'invalidParentTeam' => 'Org UI invalid parent '.$token,
  'project' => array('id' => (int)$project['object']['id'], 'phid' => $project['object']['phid'],
    'name' => 'Organization UI project '.$token));
foreach (array('explainParent', 'explainChild') as $key) {
  $name = 'Organization UI '.$key.' '.$token;
  $transactions = array(
    array('type' => 'name', 'value' => $name),
    array('type' => 'view', 'value' => PhabricatorPolicies::POLICY_USER),
    array('type' => 'edit', 'value' => $admin->getPHID()),
    array('type' => 'join', 'value' => PhabricatorPolicies::POLICY_NOONE));
  if ($key === 'explainChild') {
    $transactions[] = array('type' => 'parent', 'value' => $fixture['explainParent']['phid']);
    $transactions[] = array('type' => 'organization.teams', 'value' => array($teams['policyParent']['phid']));
    $transactions[] = array('type' => 'organization.scope', 'value' => 'descendants');
  }
  $result = id(new ConduitCall('project.edit', array('transactions' => $transactions)))
    ->setUser($admin)->execute();
  $fixture[$key] = array('id' => (int)$result['object']['id'],
    'phid' => $result['object']['phid'], 'name' => $name);
}
foreach ($users as $role => $user) {
  $fixture[$role] = array('username' => $user->getUsername(), 'phid' => $user->getPHID(),
    'session' => id(new PhabricatorAuthSessionEngine())->establishSession(
      PhabricatorAuthSession::TYPE_WEB, $user->getPHID(), false));
}
echo json_encode($fixture, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)."\n";
