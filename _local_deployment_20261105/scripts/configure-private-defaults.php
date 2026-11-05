<?php
// Deployment configuration only. Dry run by default; set
// TEAM_PRIVATE_DEFAULTS_APPLY=1 explicitly after taking a current backup.
// Updates application defaults through the same native editor as the web UI.
// Never changes an existing project/task/document/file, user, credential or session.
require_once '/opt/phorge/phorge/scripts/__init_script__.php';

$apply = getenv('TEAM_PRIVATE_DEFAULTS_APPLY') === '1';
$omnipotent = PhabricatorUser::getOmnipotentUser();
$actor = id(new PhabricatorPeopleQuery())
  ->setViewer($omnipotent)->withUsernames(array('siteadmin'))
  ->needUserSettings(true)->executeOne();
if (!$actor || !$actor->getIsAdmin() || !$actor->getIsApproved() ||
    $actor->getIsDisabled() || $actor->getIsSystemAgent() ||
    $actor->getIsMailingList()) {
  throw new Exception('An enabled, approved siteadmin is required.');
}
if (PhabricatorEnv::getEnvConfig('policy.allow-public')) {
  throw new Exception('Anonymous public policies must remain disabled.');
}

$plan = array(
  'PhabricatorProjectApplication' => array(
    ProjectDefaultViewCapability::CAPABILITY => TeamPrivateProjectPolicyRule::POLICY,
    ProjectDefaultEditCapability::CAPABILITY => TeamPrivateProjectPolicyRule::POLICY,
    ProjectDefaultJoinCapability::CAPABILITY => PhabricatorPolicies::POLICY_NOONE,
  ),
  'PhabricatorManiphestApplication' => array(
    ManiphestDefaultViewCapability::CAPABILITY => TeamPrivateTaskPolicyRule::POLICY,
    ManiphestDefaultEditCapability::CAPABILITY => TeamPrivateTaskPolicyRule::POLICY,
  ),
  'PhabricatorFilesApplication' => array(
    FilesDefaultViewCapability::CAPABILITY => PhabricatorPolicies::POLICY_NOONE,
  ),
);
$apps = id(new PhabricatorApplicationQuery())->setViewer($actor)
  ->withClasses(array_keys($plan))->execute();
$mapped = array();
foreach ($apps as $application) { $mapped[get_class($application)] = $application; }
if (count($mapped) !== count($plan)) {
  throw new Exception('Required applications are unavailable.');
}
$report = array('verifiedAt' => gmdate('c'), 'mode' => $apply ? 'apply' : 'dry-run',
  'changes' => array(), 'existingObjectsChanged' => false);
$source = PhabricatorContentSource::newForSource('console', array());
foreach ($plan as $class => $policies) {
  $application = $mapped[$class];
  $xactions = array();
  foreach ($policies as $capability => $policy) {
    $old = $application->getPolicy($capability);
    $report['changes'][] = array('application' => $class,
      'capability' => $capability, 'before' => $old, 'after' => $policy);
    if ($old === $policy) { continue; }
    $xactions[] = id($application->getApplicationTransactionTemplate())
      ->setTransactionType(PhabricatorApplicationPolicyChangeTransaction::TRANSACTIONTYPE)
      ->setMetadataValue(PhabricatorApplicationPolicyChangeTransaction::METADATA_ATTRIBUTE,
        $capability)
      ->setNewValue($policy);
  }
  if ($apply && $xactions) {
    id(new PhabricatorApplicationEditor())->setActor($actor)
      ->setContentSource($source)->setContinueOnNoEffect(true)
      ->setContinueOnMissingFields(true)->applyTransactions($application, $xactions);
  }
}
if ($apply) {
  $stored = PhabricatorConfigEntry::loadConfigEntry('phabricator.application-settings')->getValue();
  foreach ($plan as $class => $policies) {
    $phid = $mapped[$class]->getPHID();
    foreach ($policies as $capability => $policy) {
      if (idx(idx(idx($stored, $phid, array()), 'policy', array()), $capability) !== $policy) {
        throw new Exception('A default policy was not persisted.');
      }
    }
  }
}
$report['passed'] = true;
echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)."\n";
