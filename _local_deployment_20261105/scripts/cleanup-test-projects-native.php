<?php

/** Exact, evidence-backed historical fixture cleanup. CLI only; dry by default. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit(1); }
ini_set('display_errors', '0');
try {
  $plan = json_decode(base64_decode(isset($argv[1]) ? $argv[1] : '', true), true);
  if (!is_array($plan) || ($plan['operation'] ?? null) !== 'purge-reviewed-acceptance-projects' ||
      !is_array($plan['projects'] ?? null) || count($plan['projects']) !== 9 ||
      !is_array($plan['formerTestUserPHIDs'] ?? null)) {
    throw new RuntimeException('Invalid cleanup plan.');
  }
  require '/opt/phorge/phorge/scripts/__init_script__.php';
  $viewer = PhabricatorUser::getOmnipotentUser();
  $test_users = array_fuse($plan['formerTestUserPHIDs']);
  $targets = array();
  foreach ($plan['projects'] as $spec) {
    if (!is_int(idx($spec, 'id')) || $spec['id'] < 1 || $spec['id'] > 9 ||
        !preg_match('/^PHID-PROJ-[a-z0-9]{20}$/D', idx($spec, 'phid', '')) ||
        strpos(idx($spec, 'name', ''), 'ACC26 ') !== 0 ||
        !isset($test_users[idx($spec, 'authorPHID', '')]) || isset($targets[$spec['phid']])) {
      throw new RuntimeException('Unsafe cleanup target.');
    }
    $targets[$spec['phid']] = $spec;
  }
  $projects = id(new PhabricatorProject())->loadAllWhere('1 = 1');
  $users = id(new PhabricatorUser())->loadAllWhere('1 = 1');
  $live_users = mpull($users, null, 'getPHID');
  $siteadmin = null;
  foreach ($users as $user) {
    if (isset($test_users[$user->getPHID()])) {
      throw new RuntimeException('A historical test user remains; use account cleanup first.');
    }
    if ($user->getUsername() === 'siteadmin') { $siteadmin = $user; }
  }
  if (!$siteadmin || !$siteadmin->getIsAdmin() || !$siteadmin->getIsApproved() ||
      $siteadmin->getIsDisabled()) { throw new RuntimeException('Protected administrator unavailable.'); }

  $present = array();
  foreach ($projects as $project) {
    $phid = $project->getPHID();
    $parent = $project->getParentProjectPHID();
    if ($parent && isset($targets[$parent]) && !isset($targets[$phid])) {
      throw new RuntimeException('A target has a non-test child; cleanup refused.');
    }
    if (!isset($targets[$phid])) { continue; }
    $spec = $targets[$phid];
    if ((int)$project->getID() !== $spec['id'] || $project->getName() !== $spec['name'] ||
        $project->getAuthorPHID() !== $spec['authorPHID'] ||
        $parent !== $spec['parentPHID'] || $project->isMilestone()) {
      throw new RuntimeException('A target no longer matches its reviewed identity.');
    }
    $loaded = id(new PhabricatorProjectQuery())->setViewer($viewer)
      ->withPHIDs(array($phid))->needMembers(true)->needWatchers(true)->executeOne();
    if (!$loaded) { throw new RuntimeException('Target project graph is not readable.'); }
    foreach (array_merge($loaded->getMemberPHIDs(), $loaded->getWatcherPHIDs()) as $person) {
      if (isset($live_users[$person])) {
        throw new RuntimeException('A target has a current real member or watcher.');
      }
    }
    $xaction_dao = new PhabricatorProjectTransaction();
    $xactions = queryfx_all($xaction_dao->establishConnection('r'),
      'SELECT id, objectPHID, authorPHID, transactionType, oldValue, newValue, dateCreated '.
      'FROM %T WHERE objectPHID = %s', $xaction_dao->getTableName(), $phid);
    $reviewed_status = ipull(idx($plan, 'reviewedStatusTransactions', array()), null, 'id');
    foreach ($xactions as $xaction) {
      if (isset($live_users[$xaction['authorPHID']])) {
        // A precisely reviewed administrator archive action does not turn
        // an original test fixture into a real business project.
        $reviewed = idx($reviewed_status, $xaction['id']);
        if (!$reviewed || $reviewed !== $xaction ||
            $xaction['authorPHID'] !== $siteadmin->getPHID() ||
            $xaction['transactionType'] !== 'project:status' ||
            json_decode($xaction['newValue'], true) !== 100) {
          throw new RuntimeException('A real user has modified this test project; review required.');
        }
      }
    }
    $present[$phid] = $loaded;
  }

  function cleanup_project_snapshot(array $target_phids) {
    $p = new PhabricatorProject();
    $protected = queryfx_all($p->establishConnection('r'),
      'SELECT * FROM %T WHERE phid NOT IN (%Ls) ORDER BY id', $p->getTableName(), $target_phids);
    $protected_phids = ipull($protected, 'phid');
    $edges = $protected_phids ? queryfx_all($p->establishConnection('r'),
      'SELECT * FROM %T WHERE src IN (%Ls) ORDER BY src, type, dst',
      PhabricatorEdgeConfig::TABLE_NAME_EDGE, $protected_phids) : array();
    $u = new PhabricatorUser(); $t = new ManiphestTask();
    $users = queryfx_all($u->establishConnection('r'), 'SELECT * FROM %T ORDER BY id', $u->getTableName());
    $tasks = queryfx_all($t->establishConnection('r'), 'SELECT * FROM %T ORDER BY id', $t->getTableName());
    return array(
      'protectedProjects' => count($protected), 'protectedUsers' => count($users),
      'preservedTasks' => count($tasks),
      'protectedProjectDigest' => hash('sha256', json_encode(array($protected, $edges))),
      'protectedUserDigest' => hash('sha256', json_encode($users)),
      'taskContentAndPolicyDigest' => hash('sha256', json_encode($tasks)),
    );
  }
  $before = cleanup_project_snapshot(array_keys($targets));
  $summary = array('validated' => true, 'plannedProjects' => count($targets),
    'presentProjects' => count($present), 'alreadyAbsent' => count($targets) - count($present),
    'remainingTestUsers' => 0, 'protectedState' => $before);
  if (idx($plan, 'apply') !== true) {
    echo json_encode($summary, JSON_PRETTY_PRINT)."\n";
    exit;
  }
  // Refuse a changed real-object snapshot between the wrapper's review and apply.
  if (idx($plan, 'protectedState') !== $before) {
    throw new RuntimeException('Protected data changed after preflight.');
  }
  uasort($present, function ($a, $b) {
    return $b->getProjectDepth() <=> $a->getProjectDepth();
  });
  $scope = PhabricatorEnv::beginScopedEnv();
  $scope->overrideEnvConfig('phabricator.silent', true);
  $unguarded = AphrontWriteGuard::beginScopedUnguardedWrites();
  $deleted = array();
  foreach ($present as $phid => $project) {
    // Reload after each deletion so ancestor/materialized membership reflects
    // the current graph, while retaining the exact reviewed target identity.
    $project = id(new PhabricatorProjectQuery())->setViewer($viewer)
      ->withPHIDs(array($phid))->needMembers(true)->executeOne();
    if (!$project) { throw new RuntimeException('Target disappeared during cleanup.'); }
    $deleted_id = (int)$project->getID();
    id(new PhabricatorDestructionEngine())->destroyObject($project);
    $deleted[] = array('id' => $deleted_id, 'phid' => $phid);
  }
  unset($unguarded);
  if (id(new PhabricatorProject())->loadAllWhere('phid IN (%Ls)', array_keys($targets))) {
    throw new RuntimeException('A cleanup target remains.');
  }
  $after = cleanup_project_snapshot(array_keys($targets));
  if ($after !== $before) { throw new RuntimeException('Protected objects changed during cleanup.'); }
  echo json_encode($summary + array('passed' => true, 'deletedProjects' => $deleted,
    'deletedUsers' => 0, 'protectedProjectsUnchanged' => true,
    'protectedUsersUnchanged' => true, 'taskContentsAndPoliciesUnchanged' => true,
    'note' => 'Native destruction removes project tags and board columns; task objects and their policies are retained.'),
    JSON_PRETTY_PRINT)."\n";
} catch (Throwable $error) {
  $detail = $error instanceof RuntimeException ? $error->getMessage() : get_class($error).' at '.basename($error->getFile()).':'.$error->getLine();
  fwrite(STDERR, 'Reviewed project cleanup rejected: '.$detail."\n");
  exit(1);
}
