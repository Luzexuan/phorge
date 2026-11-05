<?php

// Read-only release check. Compare before/after digests without exposing names,
// policies, member identities or any credentials in the report.
$root = getenv('TEAM_PHORGE_ROOT') ?: '/opt/phorge/phorge';
require_once $root.'/scripts/__init_script__.php';
$project = new PhabricatorProject();
$conn = $project->establishConnection('r');
$projects = queryfx_all(
  $conn,
  'SELECT id, phid, parentProjectPHID, viewPolicy, editPolicy, joinPolicy, '.
  'hasSubprojects, milestoneNumber FROM %T ORDER BY id',
  $project->getTableName());
$phids = ipull($projects, 'phid');
$members = array();
if ($phids) {
  $members = queryfx_all(
    $conn,
    'SELECT src, type, dst FROM %T WHERE src IN (%Ls) AND type IN (%Ld) '.
    'ORDER BY src, type, dst',
    PhabricatorEdgeConfig::TABLE_NAME_EDGE,
    $phids,
    array(
      PhabricatorProjectProjectHasMemberEdgeType::EDGECONST,
      PhabricatorProjectMaterializedMemberEdgeType::EDGECONST,
    ));
}
echo json_encode(array(
  'checkedAt' => gmdate('c'),
  'readOnly' => true,
  'projectCount' => count($projects),
  'membershipEdgeCount' => count($members),
  'projectPolicyDigest' => hash('sha256', json_encode($projects)),
  'membershipDigest' => hash('sha256', json_encode($members)),
), JSON_PRETTY_PRINT)."\n";
