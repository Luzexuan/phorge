<?php

/**
 * Read-only deployment preflight; emits no names or credentials.
 * Run against the existing installation BEFORE enabling the project overrides:
 *   php tests/permissions/audit-legacy-parent-members.php
 * Exit 2 means a historical dormant direct-member edge needs review before
 * the new index can safely include direct members on parent projects.
 */
function team_project_membership_audit() {
  $viewer = PhabricatorUser::getOmnipotentUser();
  $parents = id(new PhabricatorProjectQuery())
    ->setViewer($viewer)
    ->withHasSubprojects(true)
    ->withIsMilestone(false)
    ->execute();
  $direct_type = PhabricatorProjectProjectHasMemberEdgeType::EDGECONST;
  $effective_type = PhabricatorProjectMaterializedMemberEdgeType::EDGECONST;
  $findings = array();
  if ($parents) {
    $edges = id(new PhabricatorEdgeQuery())
      ->withSourcePHIDs(mpull($parents, 'getPHID'))
      ->withEdgeTypes(array($direct_type, $effective_type));
    $edges->execute();
    foreach ($parents as $parent) {
      $source = array($parent->getPHID());
      $direct = $edges->getDestinationPHIDs($source, array($direct_type));
      $effective = $edges->getDestinationPHIDs($source, array($effective_type));
      $dormant = array_values(array_diff($direct, $effective));
      if ($dormant) {
        sort($dormant);
        $findings[] = array(
          'projectID' => (int)$parent->getID(),
          'projectPHID' => $parent->getPHID(),
          'dormantDirectMemberPHIDs' => $dormant,
        );
      }
    }
  }
  return array(
    'checkedAt' => gmdate('c'),
    'readOnly' => true,
    'passed' => !$findings,
    'parentProjectsChecked' => count($parents),
    'findings' => $findings,
    'existingChildMembers' => 'Historical automatic copies can not be reliably '.
      'distinguished from deliberate invitations and are not changed.',
  );
}

// The native storage-fixture regression suite reuses the read-only audit.
if (defined('TEAM_PROJECT_MEMBERSHIP_AUDIT_LIBRARY')) {
  return;
}
$root = getenv('TEAM_PHORGE_ROOT') ?: '/opt/phorge/phorge';
require_once $root.'/scripts/__init_script__.php';
$report = team_project_membership_audit();
echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)."\n";
exit($report['passed'] ? 0 : 2);
