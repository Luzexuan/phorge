<?php

/** Private read-only fixture description for the isolated migration browser. */
if (PHP_SAPI !== 'cli' || getenv('TEAM_MIGRATION_REHEARSAL') !== '1' ||
    !preg_match('/\Atm-migrate-test-[a-f0-9]+\z/',
      (string)getenv('TEAM_MIGRATION_PROJECT'))) {
  throw new Exception('Only the isolated migration rehearsal is allowed.');
}
require '/opt/phorge/phorge/scripts/__init_script__.php';
$omnipotent = PhabricatorUser::getOmnipotentUser();
if (isset($migration_browser_verify)) {
  $spec = $migration_browser_verify;
  $actor = id(new PhabricatorPeopleQuery())->setViewer($omnipotent)
    ->withPHIDs(array($spec['actorPHID']))->executeOne();
  $project = id(new PhabricatorProjectQuery())->setViewer($actor)
    ->withIDs(array($spec['projectID']))->needMembers(true)->executeOne();
  $record = TeamProjectProgress::newQuery($actor, $project)
    ->withIDs(array($spec['entryID']))->executeOne();
  $value = $record ? $record->getNewValue() : null;
  $matches = 0;
  $denied = 0;
  $rows = id(new PhabricatorProjectTransactionQuery())->setViewer($omnipotent)
    ->withTransactionTypes(array_values(TeamProjectProgress::getTransactionTypes()))
    ->setLimit(null)->execute();
  foreach ($rows as $row) {
    $entry = $row->getNewValue();
    if (idx($entry, 'title') === $spec['title']) { $matches++; }
    if (in_array(idx($entry, 'title'), $spec['deniedTitles'], true)) { $denied++; }
  }
  $passed = $record && $record->getAuthorPHID() === $actor->getPHID() &&
    $record->getTransactionType() === TeamProjectProgressCommentTransaction::TRANSACTIONTYPE &&
    idx($value, 'kind') === 'comment' && idx($value, 'title') === $spec['title'] &&
    idx($value, 'body') === $spec['body'] && $matches === 1 && $denied === 0;
  echo json_encode(array('passed' => (bool)$passed,
    'persistedComments' => $matches, 'deniedWritesPersisted' => $denied,
    'authorMatches' => $record && $record->getAuthorPHID() === $actor->getPHID()))."\n";
  exit($passed ? 0 : 1);
}
$users = id(new PhabricatorPeopleQuery())->setViewer($omnipotent)
  ->setLimit(null)->needUserSettings(true)->execute();
$provider = id(new PhabricatorAuthProviderConfigQuery())->setViewer($omnipotent)
  ->withProviderClasses(array('PhabricatorTraefikAuthProvider'))
  ->withIsEnabled(true)->executeOne();
if (!$provider || !$provider->getShouldAllowLogin()) {
  throw new Exception('Restored native identity provider is not usable.');
}
$projects = id(new PhabricatorProjectQuery())->setViewer($omnipotent)
  ->setLimit(null)->needMembers(true)->needAncestorMembers(true)->execute();
$tasks = id(new ManiphestTaskQuery())->setViewer($omnipotent)
  ->setLimit(null)->execute();
$teams = id(new TeamOrganizationTeamQuery())->setViewer($omnipotent)
  ->setLimit(null)->execute();
$files = id(new PhabricatorFileQuery())->setViewer($omnipotent)
  ->withIsDeleted(false)->withIsPartial(false)->setLimit(null)->execute();
$actors = array();
foreach ($users as $viewer) {
  if (!$viewer->isUserActivated() || $viewer->getIsSystemAgent() ||
      $viewer->getIsMailingList()) {
    continue;
  }
  $accounts = id(new PhabricatorExternalAccountQuery())->setViewer($omnipotent)
    ->withProviderConfigPHIDs(array($provider->getPHID()))
    ->withUserPHIDs(array($viewer->getPHID()))
    ->needAccountIdentifiers(true)->execute();
  if (count($accounts) !== 1) {
    continue;
  }
  $account = head($accounts);
  $identifiers = $account->getAccountIdentifiers();
  if (count($identifiers) !== 1 || !$account->getEmail()) {
    continue;
  }
  $actor = array('username' => $viewer->getUsername(), 'phid' => $viewer->getPHID(),
    'principal' => head($identifiers)->getIdentifierRaw(),
    'email' => $account->getEmail(), 'admin' => (bool)$viewer->getIsAdmin(),
    'projects' => array(), 'tasks' => array(), 'teams' => array(), 'files' => array());
  foreach ($projects as $project) {
    $view = PhabricatorPolicyFilter::hasCapability($viewer, $project, 'view');
    $node = null;
    if ($view) {
      $node = TeamProjectProgress::newQuery($viewer, $project, 'node')
        ->setLimit(1)->executeOne();
    }
    $actor['projects'][] = array('id' => (int)$project->getID(),
      'name' => $project->getName(), 'view' => $view,
      'edit' => $view && PhabricatorPolicyFilter::hasCapability($viewer, $project, 'edit'),
      'nodeID' => $node ? (int)$node->getID() : null);
  }
  foreach ($tasks as $task) {
    $actor['tasks'][] = array('id' => (int)$task->getID(),
      'name' => $task->getTitle(),
      'view' => PhabricatorPolicyFilter::hasCapability($viewer, $task, 'view'));
  }
  foreach ($teams as $team) {
    $actor['teams'][] = array('id' => (int)$team->getID(),
      'name' => $team->getName(),
      'view' => PhabricatorPolicyFilter::hasCapability($viewer, $team, 'view'));
  }
  $visible_files = id(new PhabricatorFileQuery())->setViewer($viewer)
    ->withIsDeleted(false)->withIsPartial(false)->setLimit(null)->execute();
  $visible_files = mpull($visible_files, null, 'getPHID');
  $samples = array();
  foreach ($files as $file) {
    if ($file->isBuiltin() || $file->getByteSize() > 16 * 1024 * 1024) {
      continue;
    }
    $allowed = isset($visible_files[$file->getPHID()]);
    $sample_key = $allowed ? 'allowed' : 'denied';
    if (isset($samples[$sample_key])) {
      continue;
    }
    $hash = hash_init('sha256');
    foreach ($file->getFileDataIterator() as $chunk) {
      hash_update($hash, $chunk);
    }
    $samples[$sample_key] = array('uri' => (string)$file->getViewURI(),
      'view' => $allowed, 'bytes' => (int)$file->getByteSize(),
      'sha256' => hash_final($hash));
  }
  $actor['files'] = array_values($samples);
  $actors[] = $actor;
}
echo json_encode(array('private' => true, 'actors' => $actors,
  'existingUsersOnly' => true), JSON_UNESCAPED_SLASHES)."\n";
