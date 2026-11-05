<?php
/** Private maintenance CLI bridge. Never exposed as a web route. */
ini_set('display_errors', '0');
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
try {
  $raw = file_get_contents('php://stdin', false, null, 0, 65537);
  if (strlen($raw) > 65536) { throw new Exception('input'); }
  $input = json_decode($raw, true);
  if (!is_array($input) || !isset($input['action'])) { throw new Exception('input'); }
  require_once '/opt/phorge/phorge/scripts/__init_script__.php';
  $viewer = PhabricatorUser::getOmnipotentUser();
  $provider = id(new PhabricatorAuthProviderConfigQuery())->setViewer($viewer)
    ->withProviderClasses(array('PhabricatorTraefikAuthProvider'))
    ->withIsEnabled(true)->executeOne();
  if (!$provider || !$provider->getShouldAllowLogin() ||
      $provider->getShouldTrustEmails() || $provider->getShouldAllowLink() ||
      $provider->getShouldAllowUnlink()) { throw new Exception('provider'); }
  $users = id(new PhabricatorPeopleQuery())->setViewer($viewer)->setLimit(10001)->execute();
  if (count($users) > 10000) { throw new Exception('capacity'); }
  $records = array();
  $objects = array();
  foreach ($users as $user) {
    $accounts = id(new PhabricatorExternalAccountQuery())->setViewer($viewer)
      ->withProviderConfigPHIDs(array($provider->getPHID()))
      ->withUserPHIDs(array($user->getPHID()))->needAccountIdentifiers(true)->execute();
    $email = id(new PhabricatorUserEmail())->loadOneWhere(
      'userPHID = %s AND isPrimary = 1', $user->getPHID());
    $principal = null;
    $binding = false;
    if (count($accounts) === 1 && $email) {
      $account = head($accounts);
      $identifiers = $account->getAccountIdentifiers();
      if (count($identifiers) === 1) {
        $principal = head($identifiers)->getIdentifierRaw();
        $binding = is_string($principal) && strlen($principal) > 0 &&
          strlen($principal) <= 255 &&
          strcasecmp($email->getAddress(), $account->getEmail()) === 0;
      }
    }
    $records[$user->getPHID()] = array(
      'phorge_phid'=>$user->getPHID(), 'username'=>$user->getUsername(),
      'name'=>$user->getRealName(), 'mail'=>$email ? $email->getAddress() : '',
      'user_id'=>$principal, 'binding_valid'=>$binding,
      'is_admin'=>(bool)$user->getIsAdmin(),
      'is_approved'=>(bool)$user->getIsApproved(),
      'is_disabled'=>(bool)$user->getIsDisabled(),
      'is_system_agent'=>(bool)$user->getIsSystemAgent(),
      'is_mailing_list'=>(bool)$user->getIsMailingList());
    $objects[$user->getPHID()] = $user;
  }
  $actor_phid = idx($input, 'actor_phid');
  $actor_principal = idx($input, 'actor_principal');
  $record = idx($records, $actor_phid);
  if (!$record || !$record['is_admin'] || !$record['is_approved'] ||
      $record['is_disabled'] || $record['is_system_agent'] ||
      $record['is_mailing_list'] || !$record['binding_valid'] ||
      !is_string($actor_principal) || !hash_equals($record['user_id'], $actor_principal)) {
    throw new Exception('actor');
  }
  $actor = $objects[$actor_phid];
  if ($input['action'] === 'snapshot') {
    echo json_encode(array('actor'=>$record, 'users'=>array_values($records)))."\n";
  } else if ($input['action'] === 'provision') {
    $registration = idx($input, 'registration');
    if (!is_array($registration) || idx($registration, 'approved_by') !== $actor->getUsername()) {
      throw new Exception('actor');
    }
    require dirname(__DIR__, 2).'/scripts/provision-registered-user.php';
  } else if ($input['action'] === 'set_disabled') {
    $target = idx($records, idx($input, 'phorge_phid'));
    if (!$target || !$target['binding_valid'] ||
        $target['user_id'] !== idx($input, 'user_id') ||
        !$target['is_approved'] || $target['is_system_agent'] || $target['is_mailing_list'] ||
        !is_bool(idx($input, 'disabled')) || $target['phorge_phid'] === $actor_phid) {
      throw new Exception('target');
    }
    $disabled = $input['disabled'];
    if ($disabled && $target['is_admin']) {
      $count = 0;
      foreach ($records as $other) {
        if ($other['is_admin'] && $other['is_approved'] && !$other['is_disabled'] &&
            $other['binding_valid'] && !$other['is_system_agent'] && !$other['is_mailing_list']) {
          $count++;
        }
      }
      if ($count <= 1) { throw new Exception('last-admin'); }
    }
    $user = $objects[$target['phorge_phid']];
    $unguarded = AphrontWriteGuard::beginScopedUnguardedWrites();
    if ((bool)$user->getIsDisabled() !== $disabled) {
      $transaction = id(new PhabricatorUserTransaction())
        ->setTransactionType(PhabricatorUserDisableTransaction::TRANSACTIONTYPE)
        ->setNewValue($disabled);
      id(new PhabricatorUserTransactionEditor())->setActor($actor)
        ->setActingAsPHID($actor_phid)
        ->setContentSource(PhabricatorContentSource::newForSource(PhabricatorWebContentSource::SOURCECONST))
        ->setContinueOnMissingFields(true)->setContinueOnNoEffect(true)
        ->applyTransactions($user, array($transaction));
    }
    if ($disabled) {
      // Permanently remove native browser sessions in addition to the directory
      // denial. API/session credentials are not returned to the caller.
      $sessions = id(new PhabricatorAuthSessionQuery())->setViewer($viewer)
        ->withIdentityPHIDs(array($user->getPHID()))
        ->withSessionTypes(array(PhabricatorAuthSession::TYPE_WEB))->execute();
      foreach ($sessions as $session) { $session->delete(); }
    }
    unset($unguarded);
    echo json_encode(array('user_id'=>$target['user_id'],
      'phorge_phid'=>$target['phorge_phid'], 'is_disabled'=>(bool)$user->getIsDisabled()))."\n";
  } else { throw new Exception('action'); }
} catch (Throwable $error) {
  // Exceptions may include SQL or user fields. Emit only a fixed category.
  fwrite(STDERR, "Native maintenance operation rejected.\n");
  if ($error->getMessage() === 'actor') {
    echo '{"native_error":"actor"}'."\n";
  }
  exit(1);
}
