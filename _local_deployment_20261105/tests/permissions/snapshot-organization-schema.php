<?php

/** Read-only schema/data evidence for repeating the additive organization patch. */
$root = getenv('TEAM_PHORGE_ROOT') ?: '/opt/phorge/phorge';
require_once $root.'/scripts/__init_script__.php';

$account = queryfx_one(id(new TeamOrganizationTeam())->establishConnection('r'),
  'SELECT CURRENT_USER() AS account');
$snapshot = array('readOnly' => true, 'databaseUser' => $account['account'],
  'tables' => array());
foreach (array(
  new TeamOrganizationTeam(),
  new TeamOrganizationMember(),
  new TeamOrganizationAudit(),
  new TeamOrganizationLock(),
) as $object) {
  $connection = $object->establishConnection('r');
  $table = $object->getTableName();
  $schema = queryfx_one($connection, 'SHOW CREATE TABLE %T', $table);
  $rows = queryfx_all($connection, 'SELECT * FROM %T ORDER BY id', $table);
  $snapshot['tables'][$table] = array(
    'rowCount' => count($rows),
    'schemaDigest' => hash('sha256', json_encode($schema)),
    'dataDigest' => hash('sha256', json_encode($rows)),
  );
}
echo json_encode($snapshot, JSON_PRETTY_PRINT)."\n";
