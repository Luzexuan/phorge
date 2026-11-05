<?php
// Run only against the dedicated acceptance deployment, after browser signup.
// Uses actual registered users and normal application transaction/API paths.
require_once '/opt/phorge/phorge/scripts/__init_script__.php';

$report = array('verifiedAt' => gmdate('c'), 'scope' => 'registered-user Phorge CLI Conduit API, object policy, hierarchy, mentions and workboard acceptance; file checks cover file.search/file.download APIs, not HTTP bearer download links', 'checks' => array());
$users = array();
$projects = array();
$tasks = array();
$columns = array();
$documents = array();
$files = array();
$site_admin = null;

function acc_check($name, $condition, $detail = null) {
  global $report;
  $report['checks'][] = array('name' => $name, 'passed' => (bool)$condition, 'detail' => $detail);
}

function acc_api($user, $method, array $params) {
  return id(new ConduitCall($method, $params))->setUser($user)->execute();
}

function acc_policy(array $names, array $project_objects = array()) {
  global $users, $site_admin;
  $rules = array();
  if ($names) {
    $allowed_phids = array_map(function ($name) use ($users) { return $users[$name]->getPHID(); }, $names);
    if (in_array('test_admin', $names) && $site_admin) { $allowed_phids[] = $site_admin->getPHID(); }
    $rules[] = array('action' => 'allow', 'rule' => 'PhabricatorUsersPolicyRule', 'value' => $allowed_phids);
  }
  if ($project_objects) {
    $rules[] = array('action' => 'allow', 'rule' => 'PhabricatorProjectsPolicyRule',
      'value' => array_values(mpull($project_objects, 'getPHID')));
  }
  return id(new PhabricatorPolicy())->setRules($rules)->setDefaultAction('deny')->save()->getPHID();
}

function acc_project($key, $name, $view, $edit, array $member_names, $parent = null) {
  global $users, $projects;
  $actor = $users['test_admin'];
  $object = id(new PhabricatorProjectQuery())->setViewer($actor)->withNames(array($name))->needMembers(true)->executeOne();
  if (!$object) {
    $tx = array(
      array('type' => 'name', 'value' => $name),
      array('type' => 'view', 'value' => $view),
      array('type' => 'edit', 'value' => $edit),
      array('type' => 'join', 'value' => $users['test_admin']->getPHID()),
      array('type' => 'members.add', 'value' => array_map(function ($n) use ($users) { return $users[$n]->getPHID(); }, $member_names)),
    );
    if ($parent) {
      $tx[] = array('type' => 'parent', 'value' => $parent->getPHID());
    }
    $result = acc_api($actor, 'project.edit', array('transactions' => $tx));
    $object = id(new PhabricatorProjectQuery())->setViewer($actor)->withPHIDs(array($result['object']['phid']))->needMembers(true)->executeOne();
  }
  if (!$object) { throw new Exception('Project not found after creation: '.$name); }
  $projects[$key] = $object;
  return $object;
}

function acc_task($key, $title, $marker, $view, $edit, $project, $actor_name = 'test_admin') {
  global $users, $tasks;
  // Exact fixture title lookup is only for rerun discovery. All acceptance reads
  // below use policy-aware queries and Conduit with real non-omnipotent users.
  $existing = id(new ManiphestTask())->loadOneWhere('title = %s', $title);
  if (!$existing) {
    $result = acc_api($users[$actor_name], 'maniphest.edit', array('transactions' => array(
      array('type' => 'title', 'value' => $title),
      array('type' => 'description', 'value' => 'Synthetic acceptance fixture. Confidential marker: '.$marker),
      array('type' => 'view', 'value' => $view),
      array('type' => 'edit', 'value' => $edit),
      array('type' => 'projects.add', 'value' => array($project->getPHID())),
    )));
    $existing = id(new ManiphestTask())->load($result['object']['id']);
  }
  if (!$existing) { throw new Exception('Task not found after creation: '.$title); }
  $tasks[$key] = $existing;
  return $existing;
}

function acc_can_project($user, $project, $capability = null) {
  $query = id(new PhabricatorProjectQuery())->setViewer($user)->setRaisePolicyExceptions(false)->withPHIDs(array($project->getPHID()))->needMembers(true);
  if ($capability) { $query->requireCapabilities(array($capability)); }
  return (bool)$query->execute();
}

function acc_can_task($user, $task, $capability = null) {
  $query = id(new ManiphestTaskQuery())->setViewer($user)->setRaisePolicyExceptions(false)->withPHIDs(array($task->getPHID()));
  if ($capability) { $query->requireCapabilities(array($capability)); }
  return (bool)$query->execute();
}

function acc_column($key, $project, $name, $sequence, $default = false) {
  global $users, $columns;
  $actor = $users['test_admin'];
  $existing = id(new PhabricatorProjectColumn())->loadOneWhere('projectPHID = %s AND name = %s', $project->getPHID(), $name);
  if (!$existing) {
    $project = id(new PhabricatorProjectQuery())->setViewer($actor)->withPHIDs(array($project->getPHID()))->executeOne();
    if (!$project->getHasWorkboard()) {
      id(new PhabricatorProjectTransactionEditor())->setActor($actor)
        ->setContentSource(PhabricatorContentSource::newForSource('console', array()))
        ->setContinueOnNoEffect(true)->applyTransactions($project, array(
          id(new PhabricatorProjectTransaction())->setTransactionType(PhabricatorProjectWorkboardTransaction::TRANSACTIONTYPE)->setNewValue(1),
        ));
    }
    $column = PhabricatorProjectColumn::initializeNewColumn($actor)
      ->setProjectPHID($project->getPHID())->setSequence($sequence)
      ->setProperty('isDefault', $default)->attachProject($project);
    id(new PhabricatorProjectColumnTransactionEditor())->setActor($actor)
      ->setContentSource(PhabricatorContentSource::newForSource('console', array()))
      ->setContinueOnNoEffect(true)->applyTransactions($column, array(
        id(new PhabricatorProjectColumnTransaction())->setTransactionType(PhabricatorProjectColumnNameTransaction::TRANSACTIONTYPE)->setNewValue($name),
      ));
    $existing = $column;
  }
  $columns[$key] = $existing;
  return $existing;
}

function acc_must_reject($name, $callback) {
  try {
    $callback();
    acc_check($name, false, 'Unauthorized operation unexpectedly succeeded');
  } catch (Exception $error) {
    $policy_rejection = $error instanceof PhabricatorPolicyException ||
      preg_match('/^No object exists with PHID "PHID-[A-Z]+-[a-z0-9]+"\\.$/', $error->getMessage());
    acc_check($name, $policy_rejection, get_class($error).': '.$error->getMessage());
  }
}

try {
  $site_admin = id(new PhabricatorPeopleQuery())->setViewer(PhabricatorUser::getOmnipotentUser())->withUsernames(array('siteadmin'))->needUserSettings(true)->executeOne();
  if (!$site_admin || !$site_admin->getIsAdmin()) { throw new Exception('Real siteadmin must exist with site administrator permission'); }
  foreach (array('test_admin', 'a_lead', 'a_member', 'b_lead', 'b_member', 'guest') as $name) {
    $user = id(new PhabricatorPeopleQuery())->setViewer(PhabricatorUser::getOmnipotentUser())->withUsernames(array($name))->needUserSettings(true)->executeOne();
    if (!$user) { throw new Exception('Register this user through Stargate/Phorge before fixture creation: '.$name); }
    if ($user->getIsDisabled()) { throw new Exception('Acceptance user is disabled: '.$name); }
    $users[$name] = $user;
  }
  if (!$users['test_admin']->getIsAdmin()) { throw new Exception('test_admin must be an actual site administrator before acceptance'); }
  foreach ($users as $name => $user) {
    acc_check('persona/'.$name.'/privilege', !$user->isOmnipotent() && ($name === 'test_admin' ? (bool)$user->getIsAdmin() : !$user->getIsAdmin()));
  }

  $admin = $users['test_admin'];
  $a_names = array('test_admin', 'a_lead', 'a_member');
  $b_names = array('test_admin', 'b_lead', 'b_member');
  $lead_names = array('test_admin', 'a_lead');
  $p_admin = acc_policy(array('test_admin'));
  $p_a_users = acc_policy($a_names);
  $p_b_users = acc_policy($b_names);
  $p_a_lead = acc_policy($lead_names);
  $team_a = acc_project('team_a', 'ACC26 Team A', $p_a_users, $p_a_lead, $a_names);
  $team_b = acc_project('team_b', 'ACC26 Team B', $p_b_users, acc_policy(array('test_admin', 'b_lead')), $b_names);
  $p_a = acc_policy(array('test_admin'), array($team_a));
  $p_b = acc_policy(array('test_admin'), array($team_b));
  $p_invite = acc_policy(array('test_admin', 'guest'), array($team_a));
  $main_a = acc_project('a_main', 'ACC26 A Main', $p_a, $p_a_lead, array());
  $shared_a = acc_project('a_shared', 'ACC26 A Shared Subproject', $p_a, $p_a_lead, $a_names, $main_a);
  $secret_a = acc_project('a_secret', 'ACC26 A Secret Subproject', $p_a_lead, $p_a_lead, $lead_names, $main_a);
  $main_b = acc_project('b_main', 'ACC26 B Main', $p_b, acc_policy(array('test_admin', 'b_lead')), $b_names);
  $invite = acc_project('a_invited', 'ACC26 A Confidential Invitation', $p_invite, $p_a_lead, array('test_admin', 'a_lead', 'guest'));

  $shared_task = acc_task('a_shared', 'ACC26 A shared ACC26SHAREDA', 'ACC26SHAREDA', $p_a, $p_a, $shared_a);
  $secret_task = acc_task('a_secret', 'ACC26 A secret ACC26SECRETACORE', 'ACC26SECRETACORE', $p_a_lead, $p_a_lead, $secret_a);
  acc_api($admin, 'maniphest.edit', array('objectIdentifier' => $secret_task->getPHID(), 'transactions' => array(array('type' => 'projects.add', 'value' => array($shared_a->getPHID())))));
  $b_task = acc_task('b_private', 'ACC26 B private ACC26SECRETB', 'ACC26SECRETB', $p_b, $p_b, $main_b);
  $invite_task = acc_task('a_invited', 'ACC26 guest invited ACC26INVITED', 'ACC26INVITED', $p_invite, $p_a, $invite);
  $todo = acc_column('a_todo', $shared_a, '待办', 0, true);
  $doing = acc_column('a_doing', $shared_a, '进行中', 1);
  $done = acc_column('a_done', $shared_a, '完成', 2);
  acc_column('a_secret_todo', $secret_a, '私密待办', 0, true);
  acc_column('b_todo', $main_b, '团队B待办', 0, true);
  acc_column('invite_todo', $invite, '受邀成员待办', 0, true);

  // A private project label is NOT a task's view policy. Demonstrate, then fix.
  $control = acc_task('tag_control', 'ACC26 tag control ACC26TAGCONTROL', 'ACC26TAGCONTROL', $p_a, $p_a, $shared_a);
  acc_api($admin, 'maniphest.edit', array('objectIdentifier' => $control->getPHID(), 'transactions' => array(array('type' => 'view', 'value' => PhabricatorPolicies::POLICY_USER))));
  try {
    acc_check('configuration-risk/private-tag-does-not-hide-task', !acc_can_project($users['b_member'], $shared_a) && acc_can_task($users['b_member'], $control), 'Expected stock behavior: task ACL is independent of project tag');
  } finally {
    acc_api($admin, 'maniphest.edit', array('objectIdentifier' => $control->getPHID(), 'transactions' => array(array('type' => 'view', 'value' => $p_a))));
  }
  acc_check('configuration-risk/private-tag-control-remediated', !acc_can_task($users['b_member'], $control));

  // Stock task edit permission includes sharing permission, not only card
  // movement or body edits. Record this boundary using synthetic data.
  acc_api($users['a_member'], 'maniphest.edit', array('objectIdentifier' => $control->getPHID(), 'transactions' => array(array('type' => 'view', 'value' => PhabricatorPolicies::POLICY_USER))));
  try {
    acc_check('configuration-risk/task-editor-can-broaden-visibility', acc_can_task($users['b_member'], $control), 'Task edit permission also permits changing task ACL; it is not a no-sharing role');
  } finally {
    acc_api($admin, 'maniphest.edit', array('objectIdentifier' => $control->getPHID(), 'transactions' => array(array('type' => 'view', 'value' => $p_a))));
  }
  acc_check('configuration-risk/editor-sharing-control-remediated', !acc_can_task($users['b_member'], $control));

  // Site admins manage the installation, but are not omnipotent object viewers.
  $admin_control = acc_task('admin_control', 'ACC26 admin scope ACC26ADMINSCOPE', 'ACC26ADMINSCOPE', $p_a_lead, $p_a_lead, $secret_a, 'a_lead');
  acc_api($users['a_lead'], 'maniphest.edit', array('objectIdentifier' => $admin_control->getPHID(), 'transactions' => array(array('type' => 'view', 'value' => $users['a_lead']->getPHID()))));
  acc_check('administrator/no-implicit-private-object-bypass', !acc_can_task($admin, $admin_control), 'Site administrator is not the internal omnipotent viewer');
  acc_api($users['a_lead'], 'maniphest.edit', array('objectIdentifier' => $admin_control->getPHID(), 'transactions' => array(array('type' => 'view', 'value' => $p_a_lead))));
  acc_check('administrator/explicit-policy-restores-access', acc_can_task($admin, $admin_control));

  // Child membership propagates upward. Do not use it to invite a guest while
  // promising to hide the parent. This demonstration is undone immediately.
  $risk_parent = acc_project('risk_parent', 'ACC26 Invitation Hierarchy Control', $p_a, $p_admin, array());
  $risk_child = acc_project('risk_child', 'ACC26 Invitation Child Control', $p_a, $p_admin, array('test_admin', 'a_lead'), $risk_parent);
  acc_check('hierarchy/guest-initially-cannot-see-parent', !acc_can_project($users['guest'], $risk_parent));
  acc_api($admin, 'project.edit', array('objectIdentifier' => $risk_child->getPHID(), 'transactions' => array(array('type' => 'members.add', 'value' => array($users['guest']->getPHID())))));
  try {
    acc_check('configuration-risk/child-membership-reveals-parent', acc_can_project($users['guest'], $risk_parent) && acc_can_project($users['guest'], $risk_child), 'Expected membership inheritance; not a separate-team tenant boundary');
  } finally {
    acc_api($admin, 'project.edit', array('objectIdentifier' => $risk_child->getPHID(), 'transactions' => array(array('type' => 'members.remove', 'value' => array($users['guest']->getPHID())))));
  }
  acc_check('configuration-risk/child-membership-control-remediated', !acc_can_project($users['guest'], $risk_parent));

  // Membership alone exposes the project, not its tasks. Test a complete
  // confidential invitation and retain the explicit, scoped final policies.
  acc_api($admin, 'project.edit', array('objectIdentifier' => $invite->getPHID(), 'transactions' => array(
    array('type' => 'members.remove', 'value' => array($users['guest']->getPHID())),
    array('type' => 'view', 'value' => $p_a), array('type' => 'edit', 'value' => $p_a_lead),
  )));
  acc_api($admin, 'maniphest.edit', array('objectIdentifier' => $invite_task->getPHID(), 'transactions' => array(
    array('type' => 'view', 'value' => $p_a), array('type' => 'edit', 'value' => $p_a),
  )));
  acc_check('invitation/before-invite-guest-denied', !acc_can_project($users['guest'], $invite) && !acc_can_task($users['guest'], $invite_task));
  acc_api($admin, 'project.edit', array('objectIdentifier' => $invite->getPHID(), 'transactions' => array(
    array('type' => 'members.add', 'value' => array($users['guest']->getPHID())),
  )));
  acc_check('invitation/project-membership-does-not-grant-task-acl', acc_can_project($users['guest'], $invite) && !acc_can_task($users['guest'], $invite_task));
  acc_api($admin, 'project.edit', array('objectIdentifier' => $invite->getPHID(), 'transactions' => array(
    array('type' => 'view', 'value' => $p_invite), array('type' => 'edit', 'value' => $p_a_lead),
  )));
  acc_api($admin, 'maniphest.edit', array('objectIdentifier' => $invite_task->getPHID(), 'transactions' => array(
    array('type' => 'view', 'value' => $p_invite), array('type' => 'edit', 'value' => $p_a),
  )));
  acc_check('invitation/explicit-project-and-task-policy-grants-access', acc_can_project($users['guest'], $invite) && acc_can_task($users['guest'], $invite_task));

  // Mention syntax is @username for people and #project-slug for teams/projects.
  // A mention does not add visibility. Only already-authorized people subscribe.
  $mention = 'Acceptance mention test '.gmdate('c').' @a_member @b_member @guest #'.$team_b->getPrimarySlug();
  acc_api($admin, 'maniphest.edit', array('objectIdentifier' => $shared_task->getPHID(), 'transactions' => array(array('type' => 'comment', 'value' => $mention))));
  acc_api($admin, 'project.edit', array('objectIdentifier' => $secret_a->getPHID(), 'transactions' => array(array('type' => 'description', 'value' => $mention))));
  $subscribers = PhabricatorSubscribersQuery::loadSubscribersForPHID($shared_task->getPHID());
  acc_check('mentions/visible-person-subscribed', in_array($users['a_member']->getPHID(), $subscribers));
  acc_check('mentions/hidden-person-not-subscribed', !in_array($users['b_member']->getPHID(), $subscribers) && !in_array($users['guest']->getPHID(), $subscribers));
  acc_check('mentions/team-reference-does-not-grant-task-access', !acc_can_task($users['b_member'], $shared_task));
  acc_check('mentions/project-description-does-not-grant-access', !acc_can_project($users['a_member'], $secret_a) && !acc_can_project($users['b_member'], $secret_a) && !acc_can_project($users['guest'], $secret_a));

  // Explicit subscription also does not grant view permission.
  acc_api($admin, 'maniphest.edit', array('objectIdentifier' => $secret_task->getPHID(), 'transactions' => array(array('type' => 'subscribers.add', 'value' => array($users['b_member']->getPHID())))));
  acc_check('subscriptions/no-permission-elevation', !acc_can_task($users['b_member'], $secret_task));
  acc_api($admin, 'maniphest.edit', array('objectIdentifier' => $secret_task->getPHID(), 'transactions' => array(array('type' => 'subscribers.remove', 'value' => array($users['b_member']->getPHID())))));

  // An assignee IS a special access grant. Demonstrate and remove it.
  acc_api($admin, 'maniphest.edit', array('objectIdentifier' => $secret_task->getPHID(), 'transactions' => array(array('type' => 'owner', 'value' => $users['b_member']->getPHID()))));
  try {
    acc_check('configuration-risk/assignee-automatically-sees-secret-task', acc_can_task($users['b_member'], $secret_task, PhabricatorPolicyCapability::CAN_EDIT));
  } finally {
    acc_api($admin, 'maniphest.edit', array('objectIdentifier' => $secret_task->getPHID(), 'transactions' => array(array('type' => 'owner', 'value' => null))));
  }
  acc_check('configuration-risk/assignee-control-remediated', !acc_can_task($users['b_member'], $secret_task));

  $project_expected = array('team_a' => $a_names, 'team_b' => $b_names, 'a_main' => $a_names,
    'a_shared' => $a_names, 'a_secret' => $lead_names, 'b_main' => $b_names,
    'a_invited' => array('test_admin', 'a_lead', 'a_member', 'guest'),
    'risk_parent' => $a_names, 'risk_child' => $a_names);
  $task_expected = array('a_shared' => $a_names, 'a_secret' => $lead_names, 'b_private' => $b_names,
    'a_invited' => array('test_admin', 'a_lead', 'a_member', 'guest'), 'tag_control' => $a_names, 'admin_control' => $lead_names);
  foreach ($users as $username => $user) {
    foreach ($project_expected as $key => $allowed) {
      $expected = in_array($username, $allowed);
      $visible = acc_can_project($user, $projects[$key]);
      $api = acc_api($user, 'project.search', array('constraints' => array('ids' => array((int)$projects[$key]->getID()))));
      acc_check('project/'.$key.'/'.$username, $visible === $expected && ((bool)$api['data']) === $expected, array('expected' => $expected, 'query' => $visible, 'api' => (bool)$api['data']));
    }
    foreach ($task_expected as $key => $allowed) {
      $expected = in_array($username, $allowed);
      $visible = acc_can_task($user, $tasks[$key]);
      $api = acc_api($user, 'maniphest.search', array('constraints' => array('ids' => array((int)$tasks[$key]->getID()))));
      acc_check('task/'.$key.'/'.$username, $visible === $expected && ((bool)$api['data']) === $expected, array('expected' => $expected, 'query' => $visible, 'api' => (bool)$api['data']));
    }
  }
  foreach ($projects as $key => $object) {
    acc_check('administrator/real-admin-project/'.$key, acc_can_project($site_admin, $object, PhabricatorPolicyCapability::CAN_EDIT));
  }
  foreach ($tasks as $key => $object) {
    acc_check('administrator/real-admin-task/'.$key, acc_can_task($site_admin, $object, PhabricatorPolicyCapability::CAN_EDIT));
  }

  foreach (array('test_admin' => true, 'a_lead' => true, 'a_member' => false) as $name => $expected) {
    $board_tasks = acc_api($users[$name], 'maniphest.search', array('constraints' => array('projects' => array($shared_a->getPHID()))));
    $board_phids = array_column($board_tasks['data'], 'phid');
    acc_check('board/mixed-visible-project-private-card/'.$name, in_array($shared_task->getPHID(), $board_phids) && in_array($secret_task->getPHID(), $board_phids) === $expected);
  }

  // G04: private wiki content and a file whose only non-author access comes
  // from its restricted parent task. These use ordinary application editors.
  $wiki_root = id(new PhrictionDocumentQuery())->setViewer($admin)->withSlugs(array('/'))->executeOne();
  if (!$wiki_root) {
    acc_api($admin, 'phriction.create', array('slug' => '/', 'title' => 'Wiki', 'content' => 'Team documentation index.'));
  }
  $document = id(new PhrictionDocumentQuery())->setViewer($admin)->withSlugs(array('acc26_secret/'))->needContent(true)->executeOne();
  if (!$document) {
    $document = PhrictionDocument::initializeNewDocument($admin, 'acc26_secret/');
    id(new PhrictionTransactionEditor())->setActor($admin)
      ->setContentSource(PhabricatorContentSource::newForSource('console', array()))
      ->setContinueOnNoEffect(true)->applyTransactions($document, array(
        id(new PhrictionTransaction())->setTransactionType(PhrictionDocumentTitleTransaction::TRANSACTIONTYPE)->setNewValue('ACC26 Private Wiki ACC26DOCSECRET'),
        id(new PhrictionTransaction())->setTransactionType(PhrictionDocumentContentTransaction::TRANSACTIONTYPE)->setNewValue('Synthetic private wiki content ACC26DOCSECRET.'),
        id(new PhrictionTransaction())->setTransactionType(PhabricatorTransactions::TYPE_VIEW_POLICY)->setNewValue($p_a_lead),
        id(new PhrictionTransaction())->setTransactionType(PhabricatorTransactions::TYPE_EDIT_POLICY)->setNewValue($p_a_lead),
      ));
  }
  $documents['a_secret'] = $document;
  $file_bytes = "ACC26FILESECRET: synthetic confidential attachment.\n";
  $file = id(new PhabricatorFileQuery())->setViewer($admin)->withNames(array('ACC26-private-attachment.txt'))->executeOne();
  if (!$file) {
    $file_phid = acc_api($admin, 'file.upload', array('data_base64' => base64_encode($file_bytes), 'name' => 'ACC26-private-attachment.txt', 'viewPolicy' => PhabricatorPolicies::POLICY_NOONE, 'canCDN' => false));
    $file = id(new PhabricatorFileQuery())->setViewer($admin)->withPHIDs(array($file_phid))->executeOne();
    acc_check('file/before-attachment-leader-cannot-see', !id(new PhabricatorFileQuery())->setViewer($users['a_lead'])->withPHIDs(array($file_phid))->execute());
  }
  acc_api($admin, 'maniphest.edit', array('objectIdentifier' => $secret_task->getPHID(), 'transactions' => array(array('type' => 'comment', 'value' => 'Synthetic restricted attachment {F'.$file->getID().'}'))));
  // A remarkup reference alone does not grant file access. Apply the same
  // formal attachment transaction used by the UI's "Grant Permission" action.
  $attachment_task = id(new ManiphestTaskQuery())->setViewer($admin)->withPHIDs(array($secret_task->getPHID()))->executeOne();
  id(new ManiphestTransactionEditor())->setActor($admin)
    ->setContentSource(PhabricatorContentSource::newForSource('console', array()))
    ->setContinueOnNoEffect(true)->setContinueOnMissingFields(true)
    ->applyTransactions($attachment_task, array(
      id(new ManiphestTransaction())->setTransactionType(PhabricatorTransactions::TYPE_FILE)
        ->setNewValue(array($file->getPHID() => PhabricatorFileAttachment::MODE_ATTACH)),
    ));
  $files['a_secret'] = $file;
  acc_check('file/explicit-policy-denies-general-access', $file->getViewPolicy() === PhabricatorPolicies::POLICY_NOONE);
  foreach ($users as $name => $user) {
    $expected = in_array($name, $lead_names);
    $docs = acc_api($user, 'phriction.document.search', array('constraints' => array('ids' => array((int)$document->getID()))));
    acc_check('document/private-wiki/'.$name, (bool)$docs['data'] === $expected);
    $file_query = id(new PhabricatorFileQuery())->setViewer($user)->withPHIDs(array($file->getPHID()))->execute();
    $file_api = acc_api($user, 'file.search', array('constraints' => array('ids' => array((int)$file->getID()))));
    acc_check('file/private-task-inherited-policy/'.$name, (bool)$file_query === $expected && (bool)$file_api['data'] === $expected);
    if ($expected) {
      $download = acc_api($user, 'file.download', array('phid' => $file->getPHID()));
      acc_check('file/authorized-download-exact-bytes/'.$name, base64_decode($download) === $file_bytes);
    } else {
      acc_must_reject('file/unauthorized-download-rejected/'.$name, function () use ($user, $file) {
        acc_api($user, 'file.download', array('phid' => $file->getPHID()));
      });
    }
  }

  acc_api($users['a_member'], 'maniphest.edit', array('objectIdentifier' => $shared_task->getPHID(), 'transactions' => array(array('type' => 'column', 'value' => array($doing->getPHID())))));
  $layout = id(new PhabricatorBoardLayoutEngine())->setViewer($users['a_member'])->setBoardPHIDs(array($shared_a->getPHID()))->setObjectPHIDs(array($shared_task->getPHID()))->executeLayout();
  acc_check('board/authorized-member-moves-card', in_array($doing->getPHID(), array_values(mpull($layout->getObjectColumns($shared_a->getPHID(), $shared_task->getPHID()), 'getPHID'))));
  acc_must_reject('board/cross-team-move-rejected', function () use ($users, $shared_task, $done) {
    acc_api($users['b_member'], 'maniphest.edit', array('objectIdentifier' => $shared_task->getPHID(), 'transactions' => array(array('type' => 'column', 'value' => array($done->getPHID())))));
  });
  acc_must_reject('edit/guest-cannot-edit-uninvited-project-task', function () use ($users, $secret_task) {
    acc_api($users['guest'], 'maniphest.edit', array('objectIdentifier' => $secret_task->getPHID(), 'transactions' => array(array('type' => 'comment', 'value' => 'This unauthorized comment must not persist'))));
  });
  acc_api($users['guest'], 'maniphest.edit', array('objectIdentifier' => $invite_task->getPHID(), 'transactions' => array(array('type' => 'comment', 'value' => 'Invited guest can collaborate only in this confidential project.'))));
  acc_check('invitation/guest-can-collaborate-without-team-membership', acc_can_task($users['guest'], $invite_task) && !acc_can_project($users['guest'], $team_a) && !acc_can_project($users['guest'], $main_a));
  acc_must_reject('membership/ordinary-member-cannot-invite-other-team', function () use ($users, $shared_a) {
    acc_api($users['a_member'], 'project.edit', array('objectIdentifier' => $shared_a->getPHID(), 'transactions' => array(array('type' => 'members.add', 'value' => array($users['b_member']->getPHID())))));
  });
  acc_must_reject('policy/guest-cannot-open-confidential-project', function () use ($users, $invite) {
    acc_api($users['guest'], 'project.edit', array('objectIdentifier' => $invite->getPHID(), 'transactions' => array(array('type' => 'view', 'value' => PhabricatorPolicies::POLICY_USER))));
  });
  acc_must_reject('policy/guest-cannot-open-confidential-task', function () use ($users, $invite_task) {
    acc_api($users['guest'], 'maniphest.edit', array('objectIdentifier' => $invite_task->getPHID(), 'transactions' => array(array('type' => 'view', 'value' => PhabricatorPolicies::POLICY_USER))));
  });
  acc_must_reject('membership/guest-cannot-self-join-team', function () use ($users, $team_a) {
    acc_api($users['guest'], 'project.edit', array('objectIdentifier' => $team_a->getPHID(), 'transactions' => array(array('type' => 'members.add', 'value' => array($users['guest']->getPHID())))));
  });

  $found = array();
  for ($attempt = 0; $attempt < 20; $attempt++) {
    $found = acc_api($admin, 'maniphest.search', array('constraints' => array('query' => 'ACC26SECRETACORE')));
    if ($found['data']) { break; }
    usleep(500000);
  }
  acc_check('search/authorized-positive-control-indexed', (bool)$found['data']);
  foreach (array('a_member', 'b_lead', 'b_member', 'guest') as $name) {
    $result = acc_api($users[$name], 'maniphest.search', array('constraints' => array('query' => 'ACC26SECRETACORE')));
    acc_check('search/secret-not-discoverable/'.$name, !$result['data']);
    $feed = acc_api($users[$name], 'feed.query', array('filterPHIDs' => array($secret_task->getPHID()), 'limit' => 100, 'view' => 'data'));
    acc_check('feed/secret-not-discoverable/'.$name, !$feed);
  }
  $admin_feed = acc_api($admin, 'feed.query', array('filterPHIDs' => array($secret_task->getPHID()), 'limit' => 100, 'view' => 'data'));
  acc_check('feed/authorized-positive-control', (bool)$admin_feed);

  $report['realSiteAdministrator'] = array('username' => $site_admin->getUsername(), 'phid' => $site_admin->getPHID(), 'explicitFixtureAccess' => true);
  $report['fixtures'] = array('users' => array(), 'projects' => array(), 'tasks' => array(), 'columns' => array());
  foreach ($users as $key => $object) { $report['fixtures']['users'][$key] = array('phid' => $object->getPHID(), 'username' => $object->getUsername(), 'isAdmin' => (bool)$object->getIsAdmin()); }
  foreach ($projects as $key => $object) { $report['fixtures']['projects'][$key] = array('id' => (int)$object->getID(), 'phid' => $object->getPHID(), 'name' => $object->getName(), 'slug' => $object->getPrimarySlug(), 'url' => '/project/profile/'.$object->getID().'/', 'boardUrl' => '/project/board/'.$object->getID().'/', 'visibleTo' => $project_expected[$key]); }
  foreach ($tasks as $key => $object) { $report['fixtures']['tasks'][$key] = array('id' => (int)$object->getID(), 'phid' => $object->getPHID(), 'title' => $object->getTitle(), 'url' => '/T'.$object->getID(), 'visibleTo' => $task_expected[$key]); }
  foreach ($columns as $key => $object) { $report['fixtures']['columns'][$key] = array('id' => (int)$object->getID(), 'phid' => $object->getPHID(), 'name' => $object->getName()); }
  foreach ($documents as $key => $object) { $report['fixtures']['documents'][$key] = array('id' => (int)$object->getID(), 'phid' => $object->getPHID(), 'url' => $object->getURI(), 'marker' => 'ACC26DOCSECRET', 'visibleTo' => $lead_names); }
  foreach ($files as $key => $object) { $report['fixtures']['files'][$key] = array('id' => (int)$object->getID(), 'phid' => $object->getPHID(), 'url' => '/F'.$object->getID(), 'downloadUrl' => (string)$object->getDownloadURI(), 'marker' => 'ACC26FILESECRET', 'sha256' => hash('sha256', $file_bytes), 'bytes' => strlen($file_bytes), 'visibleTo' => $lead_names); }
} catch (Throwable $error) {
  $report['fatal'] = get_class($error).': '.$error->getMessage();
  $report['trace'] = $error->getTraceAsString();
}
if (!isset($report['fixtures'])) {
  // Preserve navigable fixture identifiers even when a later assertion aborts.
  $report['fixtures'] = array('projects' => array(), 'tasks' => array(), 'columns' => array());
  foreach ($projects as $key => $object) { $report['fixtures']['projects'][$key] = array('id' => (int)$object->getID(), 'phid' => $object->getPHID(), 'name' => $object->getName(), 'url' => '/project/profile/'.$object->getID().'/', 'boardUrl' => '/project/board/'.$object->getID().'/'); }
  foreach ($tasks as $key => $object) { $report['fixtures']['tasks'][$key] = array('id' => (int)$object->getID(), 'phid' => $object->getPHID(), 'title' => $object->getTitle(), 'url' => '/T'.$object->getID()); }
  foreach ($columns as $key => $object) { $report['fixtures']['columns'][$key] = array('id' => (int)$object->getID(), 'phid' => $object->getPHID(), 'name' => $object->getName()); }
}
$report['passed'] = empty($report['fatal']) && !array_filter($report['checks'], function ($check) { return !$check['passed']; });
echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)."\n";
exit($report['passed'] ? 0 : 1);
