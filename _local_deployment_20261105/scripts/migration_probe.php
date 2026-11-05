<?php

/**
 * Read-only migration evidence. Run on the stopped source and on the restored
 * database before starting application writers. No identifiers, names, row
 * values, passwords, or file contents are included in this report.
 *
 * stdin invocation: compose run --rm --no-deps -T --entrypoint php phorge < FILE
 * Optional TEAM_MIGRATION_FILES=1 checks complete file bytes after file storage
 * is running. It does not generate image transforms or write files.
 */
if (PHP_SAPI !== 'cli') {
  http_response_code(404);
  exit(1);
}
require_once '/opt/phorge/phorge/scripts/__init_script__.php';

// Native policy/settings queries may fill derived caches on a cold install.
// Keep those writes inside this PHP process so source snapshots and restored
// snapshots remain comparisons of the imported data, not cache warm-up timing.
foreach (array('getImmutableCache', 'getMutableCache', 'getMutableStructureCache',
    'getRepositoryGraphL1Cache', 'getRepositoryGraphL2Cache', 'getServerStateCache')
  as $cache_method) {
  PhabricatorCaches::$cache_method()->setCaches(
    array(new PhutilInRequestKeyValueCache()));
}

function migration_probe_digest($value) {
  return hash('sha256', serialize($value));
}

function migration_probe_table($conn, $database, $table) {
  $columns = queryfx_all($conn,
    'SELECT COLUMN_NAME, ORDINAL_POSITION, COLUMN_TYPE, IS_NULLABLE, '.
    'COLUMN_DEFAULT, CHARACTER_SET_NAME, COLLATION_NAME, EXTRA, '.
    'GENERATION_EXPRESSION FROM information_schema.COLUMNS '.
    'WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION',
    $database, $table);
  $indexes = queryfx_all($conn,
    'SELECT INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME, COLLATION, '.
    'SUB_PART, INDEX_TYPE FROM information_schema.STATISTICS '.
    'WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s ORDER BY INDEX_NAME, SEQ_IN_INDEX',
    $database, $table);
  $primary = array();
  foreach ($indexes as $index) {
    if ($index['INDEX_NAME'] === 'PRIMARY') {
      $primary[] = $index['COLUMN_NAME'];
    }
  }

  // Sorted row hashes preserve NULL, binary, and exact JSON values. Paging by
  // the primary key bounds row memory while the transaction fixes the view.
  // Tables without a primary key are read once to avoid unstable page ties.
  $hashes = array();
  $offset = 0;
  do {
    if ($primary) {
      $rows = queryfx_all($conn,
        'SELECT * FROM %T.%T ORDER BY %LC LIMIT %d, %d',
        $database, $table, $primary, $offset, 1000);
    } else {
      $rows = queryfx_all($conn, 'SELECT * FROM %T.%T', $database, $table);
    }
    foreach ($rows as $row) {
      ksort($row, SORT_STRING);
      $hashes[] = migration_probe_digest($row);
    }
    $offset += count($rows);
  } while ($primary && count($rows) === 1000);
  sort($hashes, SORT_STRING);
  $digest = hash_init('sha256');
  foreach ($hashes as $hash) {
    hash_update($digest, $hash."\n");
  }
  return array(
    'rows' => count($hashes),
    'dataSHA256' => hash_final($digest),
    'schemaSHA256' => migration_probe_digest(array($columns, $indexes)),
  );
}

function migration_probe_capability($viewer, $object, $capability) {
  try {
    return (bool)PhabricatorPolicyFilter::hasCapability(
      $viewer, $object, $capability);
  } catch (PhabricatorPolicyException $ex) {
    return false;
  }
}

function migration_probe_authorization() {
  $omnipotent = PhabricatorUser::getOmnipotentUser();
  $users = id(new PhabricatorPeopleQuery())->setViewer($omnipotent)
    ->setLimit(null)->needUserSettings(true)->execute();
  $projects = id(new PhabricatorProjectQuery())->setViewer($omnipotent)
    ->setLimit(null)->needMembers(true)->needAncestorMembers(true)->execute();
  $tasks = id(new ManiphestTaskQuery())->setViewer($omnipotent)
    ->setLimit(null)->execute();
  $teams = id(new TeamOrganizationTeamQuery())->setViewer($omnipotent)
    ->setLimit(null)->execute();
  $matrix = array();
  $task_matrix = array();
  $team_matrix = array();
  $active = 0;
  $totals = array('view' => 0, 'edit' => 0, 'join' => 0,
    'publish' => 0, 'manage' => 0);
  foreach ($users as $viewer) {
    if (!$viewer->isUserActivated() || $viewer->getIsSystemAgent() ||
        $viewer->getIsMailingList()) {
      continue;
    }
    $active++;
    foreach ($projects as $project) {
      $caps = array();
      foreach (array('view', 'edit', 'join') as $capability) {
        $caps[$capability] = migration_probe_capability(
          $viewer, $project, $capability);
      }
      $caps['publish'] = TeamProjectProgress::canPublish($viewer, $project);
      try {
        $caps['manage'] = TeamProjectAccessService::canManage($viewer, $project);
      } catch (PhabricatorPolicyException $ex) {
        $caps['manage'] = false;
      }
      foreach ($totals as $capability => $total) {
        $totals[$capability] += (int)$caps[$capability];
      }
      $matrix[$viewer->getPHID().':'.$project->getPHID()] = $caps;
    }
    foreach ($tasks as $task) {
      $task_matrix[$viewer->getPHID().':'.$task->getPHID()] = array(
        'view' => migration_probe_capability($viewer, $task, 'view'),
        'edit' => migration_probe_capability($viewer, $task, 'edit'));
    }
    foreach ($teams as $team) {
      $team_matrix[$viewer->getPHID().':'.$team->getPHID()] = array(
        'view' => migration_probe_capability($viewer, $team, 'view'),
        'members' => TeamOrganizationService::canViewMembers($viewer, $team));
    }
  }
  ksort($matrix, SORT_STRING);
  ksort($task_matrix, SORT_STRING);
  ksort($team_matrix, SORT_STRING);
  return array('activePeople' => $active, 'projects' => count($projects),
    'projectCombinations' => count($matrix), 'projectAllowedCounts' => $totals,
    'projectSHA256' => migration_probe_digest($matrix),
    'taskCombinations' => count($task_matrix),
    'taskSHA256' => migration_probe_digest($task_matrix),
    'teamCombinations' => count($team_matrix),
    'teamSHA256' => migration_probe_digest($team_matrix));
}

function migration_probe_files() {
  $files = id(new PhabricatorFileQuery())
    ->setViewer(PhabricatorUser::getOmnipotentUser())
    ->withIsDeleted(false)->setLimit(null)->execute();
  $digests = array();
  $engines = array();
  $complete = 0;
  $partial = 0;
  $total_bytes = 0;
  foreach ($files as $file) {
    if ($file->getIsPartial()) {
      $partial++;
      continue;
    }
    $engine = $file->getStorageEngine();
    $engines[$engine] = idx($engines, $engine, 0) + 1;
    $hash = hash_init('sha256');
    $bytes = 0;
    foreach ($file->getFileDataIterator() as $chunk) {
      hash_update($hash, $chunk);
      $bytes += strlen($chunk);
    }
    $actual = hash_final($hash);
    // Some historical resumable-upload contentHash values identify an upload
    // and end in "-C"; they are not hashes of its bytes. Gorge stores the
    // verified complete-upload SHA256 separately in file metadata.
    $expected = rtrim((string)$file->getContentHash(), "\0");
    if (!preg_match('/\A[0-9a-f]{64}\z/', $expected)) {
      $expected = idx($file->getMetadata(), 'gorge.upload.sha256');
    }
    if ($bytes !== (int)$file->getByteSize() ||
        ($expected && !hash_equals($expected, $actual))) {
      throw new Exception('Complete attachment bytes do not match metadata.');
    }
    $digests[$file->getPHID()] = array('bytes' => $bytes, 'sha256' => $actual);
    $complete++;
    $total_bytes += $bytes;
  }
  ksort($digests, SORT_STRING);
  ksort($engines, SORT_STRING);
  return array('passed' => true, 'completeFiles' => $complete,
    'partialFilesSkipped' => $partial, 'bytesRead' => $total_bytes,
    'storageEngines' => $engines,
    'contentSHA256' => migration_probe_digest($digests));
}

$stage = 'initialization';
$conn = null;
$in_transaction = false;
try {
  $namespace = PhabricatorLiskDAO::getStorageNamespace();
  if (!preg_match('/\A[A-Za-z0-9_]{1,44}\z/', $namespace)) {
    throw new Exception('Invalid storage namespace.');
  }
  $conn = id(new PhabricatorUser())->establishConnection('w');
  queryfx($conn, 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
  queryfx($conn, 'START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
  $in_transaction = true;
  $prefix = $namespace.'_';
  $found = queryfx_all($conn,
    'SELECT TABLE_SCHEMA, TABLE_NAME, ENGINE, TABLE_TYPE '.
    'FROM information_schema.TABLES WHERE LEFT(TABLE_SCHEMA, %d) = %s '.
    'OR TABLE_SCHEMA = %s ORDER BY TABLE_SCHEMA, TABLE_NAME',
    strlen($prefix), $prefix, 'phorge');
  if (!$found) {
    throw new Exception('No application tables found.');
  }
  $tables = array();
  $business = array();
  $schema = array();
  $non_transactional = array();
  $stage = 'table-snapshot';
  foreach ($found as $row) {
    $database = $row['TABLE_SCHEMA'];
    $table = $row['TABLE_NAME'];
    $application = $database === 'phorge' ? 'bootstrap' :
      substr($database, strlen($prefix));
    $key = $application.'.'.$table;
    $snapshot = migration_probe_table($conn, $database, $table);
    $snapshot['engine'] = $row['ENGINE'];
    $snapshot['type'] = $row['TABLE_TYPE'];
    $tables[$key] = $snapshot;
    $schema[$key] = array($snapshot['schemaSHA256'], $row['ENGINE'], $row['TABLE_TYPE']);
    if ($row['TABLE_TYPE'] === 'BASE TABLE' && $row['ENGINE'] !== 'InnoDB') {
      $non_transactional[] = $key;
    }
    // Post-start comparison is deliberately narrower than full restoration.
    // The complete digest above includes sessions, caches and pending queues.
    if (in_array($application, array('project', 'maniphest', 'policy', 'phriction'), true) ||
        ($application === 'user' &&
         (in_array($table, array('user', 'user_email', 'user_profile',
            'user_configuredcustomfieldstorage', 'edge', 'edgedata'), true) ||
          strpos($table, 'user_organization') === 0))) {
      $business[$key] = $snapshot;
    }
  }
  ksort($tables, SORT_STRING);
  ksort($business, SORT_STRING);
  ksort($schema, SORT_STRING);
  $count = function($key) use ($tables) {
    return isset($tables[$key]) ? $tables[$key]['rows'] : null;
  };
  $node_counts = queryfx_all($conn,
    'SELECT transactionType, COUNT(*) n FROM %T.%T '.
    'WHERE transactionType IN (%Ls) GROUP BY transactionType ORDER BY transactionType',
    $namespace.'_project', 'project_transaction',
    array_values(TeamProjectProgress::getTransactionTypes()));
  $nodes = array_fill_keys(array_values(TeamProjectProgress::getTransactionTypes()), 0);
  foreach ($node_counts as $row) {
    $nodes[$row['transactionType']] = (int)$row['n'];
  }
  ksort($nodes, SORT_STRING);
  $stage = 'authorization';
  $authorization = migration_probe_authorization();
  queryfx($conn, 'COMMIT');
  $in_transaction = false;
  $result = array('formatVersion' => 1, 'passed' => true, 'readOnly' => true,
    'capturedAt' => gmdate('c'), 'databaseNamespace' => $namespace,
    'digestAlgorithm' => 'sha256(sorted sha256(serialize(sorted row columns)))',
    'tableCount' => count($tables), 'tables' => $tables,
    'fullDigest' => migration_probe_digest($tables),
    'schemaDigest' => migration_probe_digest($schema),
    'businessTables' => array_keys($business),
    'businessDigest' => migration_probe_digest($business),
    'nonTransactionalTables' => $non_transactional,
    'counts' => array('users' => $count('user.user'),
      'projects' => $count('project.project'), 'tasks' => $count('maniphest.maniphest_task'),
      'teams' => $count('user.user_organizationteam'),
      'teamMemberships' => $count('user.user_organizationmember'),
      'organizationAudit' => $count('user.user_organizationaudit'),
      'policies' => $count('policy.policy'), 'files' => $count('file.file'),
      'nodeTransactions' => $nodes),
    'authorization' => $authorization);
  if (getenv('TEAM_MIGRATION_FILES') === '1') {
    $stage = 'attachment-bytes';
    $result['files'] = migration_probe_files();
  }
  echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n";
} catch (Throwable $ex) {
  if ($conn && $in_transaction) {
    try { queryfx($conn, 'ROLLBACK'); } catch (Throwable $ignored) {}
  }
  // Exceptions from database or storage clients can contain private identities,
  // query text, handles or URLs. Only emit the stage and exception class.
  echo json_encode(array('formatVersion' => 1, 'passed' => false,
    'readOnly' => true, 'failedStage' => $stage,
    'errorType' => get_class($ex)), JSON_PRETTY_PRINT)."\n";
  exit(1);
}
