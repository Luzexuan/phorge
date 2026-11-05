<?php
/** Narrow one-time fixture destruction; argv[1] is reviewed base64 JSON. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit(1); }
ini_set('display_errors', '0');
try {
  $input = json_decode(base64_decode(isset($argv[1]) ? $argv[1] : '', true), true);
  if (!is_array($input) || ($input['operation'] ?? null) !== 'purge-reviewed-acceptance-users' ||
      !is_array($input['users'] ?? null) || !count($input['users']) || count($input['users']) > 50) {
    throw new Exception('Invalid cleanup operation.');
  }
  require '/opt/phorge/phorge/scripts/__init_script__.php';
  $viewer = PhabricatorUser::getOmnipotentUser();
  $all = id(new PhabricatorPeopleQuery())->setViewer($viewer)->setLimit(10001)->execute();
  $by_phid = mpull($all, null, 'getPHID');
  $targets = array();
  $absent = 0;
  foreach ($input['users'] as $spec) {
    $phid = idx($spec, 'phid');
    if (!is_string($phid) || !preg_match('/^PHID-USER-[a-zA-Z0-9]{20}$/D', $phid) ||
        array_key_exists($phid, $targets) || !is_string(idx($spec, 'username')) ||
        in_array($spec['username'], array('siteadmin','admin','root')) ||
        !is_string(idx($spec, 'principal')) || $spec['principal']==='linkerbot-site-admin' ||
        !is_array(idx($spec, 'emails')) || !count($spec['emails'])) {
      throw new Exception('Unsafe cleanup target.');
    }
    foreach ($spec['emails'] as $address) {
      if (!is_string($address) || !preg_match('/^[^@]+@acceptance\.test$/D', $address)) {
        throw new Exception('Non-test email target.');
      }
    }
    $targets[$phid] = null;
    $user = idx($by_phid, $phid);
    if (!$user) { $absent++; continue; }
    if ($user->getUsername() !== $spec['username'] || $user->getIsSystemAgent() || $user->getIsMailingList()) {
      throw new Exception('Changed cleanup identity.');
    }
    $emails = mpull(id(new PhabricatorUserEmail())->loadAllWhere('userPHID = %s', $phid), 'getAddress');
    $expected_emails = $spec['emails']; sort($emails); sort($expected_emails);
    if ($emails !== $expected_emails) { throw new Exception('Changed cleanup emails.'); }
    $accounts = id(new PhabricatorExternalAccountQuery())->setViewer($viewer)
      ->withUserPHIDs(array($phid))->needAccountIdentifiers(true)->execute();
    if (count($accounts)!==1) { throw new Exception('Ambiguous cleanup binding.'); }
    $identifiers = head($accounts)->getAccountIdentifiers();
    if (count($identifiers)!==1 || head($identifiers)->getIdentifierRaw()!==$spec['principal']) {
      throw new Exception('Changed cleanup principal.');
    }
    $targets[$phid] = $user;
  }
  $siteadmin = id(new PhabricatorPeopleQuery())->setViewer($viewer)->withUsernames(array('siteadmin'))->executeOne();
  if (!$siteadmin || !$siteadmin->getIsAdmin() || !$siteadmin->getIsApproved() || $siteadmin->getIsDisabled() ||
      array_key_exists($siteadmin->getPHID(), $targets)) { throw new Exception('Protected administrator unavailable.'); }
  function protected_state($users, $targets) {
    $result = array();
    foreach ($users as $user) {
      if (array_key_exists($user->getPHID(), $targets)) { continue; }
      $sessions = id(new PhabricatorAuthSession())->loadAllWhere('userPHID = %s', $user->getPHID());
      $session_ids = array_values(mpull($sessions, 'getID')); sort($session_ids);
      $result[$user->getPHID()] = array($user->getUsername(), $user->getIsAdmin(),
        $user->getIsApproved(), $user->getIsDisabled(), $session_ids);
    }
    ksort($result); return $result;
  }
  function retained_objects($viewer) {
    $projects = mpull(id(new PhabricatorProjectQuery())->setViewer($viewer)->setLimit(10001)->execute(), 'getPHID');
    $tasks = mpull(id(new ManiphestTaskQuery())->setViewer($viewer)->setLimit(10001)->execute(), 'getPHID');
    sort($projects); sort($tasks); return array($projects, $tasks);
  }
  $protected_before = protected_state($all, $targets);
  $objects_before = retained_objects($viewer);
  if (idx($input, 'apply') !== true) {
    echo json_encode(array('validated'=>true, 'targets'=>count($targets), 'alreadyAbsent'=>$absent,
      'protectedUsers'=>count($protected_before), 'projects'=>count($objects_before[0]), 'tasks'=>count($objects_before[1])))."\n";
    exit;
  }
  $unguarded = AphrontWriteGuard::beginScopedUnguardedWrites();
  $deleted = 0; $tokens = 0; $bindings = 0;
  foreach ($targets as $phid=>$user) {
    // These two stores have no native user-destruction hook in this version.
    foreach (id(new PhabricatorConduitToken())->loadAllWhere('objectPHID = %s', $phid) as $token) {
      $token->delete(); $tokens++;
    }
    foreach (id(new TeamEntrySessionBinding())->loadAllWhere('userPHID = %s', $phid) as $binding) {
      $binding->delete(); $bindings++;
    }
    if ($user) {
      id(new PhabricatorDestructionEngine())->destroyObject($user);
      $deleted++;
    }
  }
  unset($unguarded);
  $remaining = id(new PhabricatorPeopleQuery())->setViewer($viewer)->setLimit(10001)->execute();
  foreach ($remaining as $user) {
    if (array_key_exists($user->getPHID(), $targets)) { throw new Exception('Target remains.'); }
  }
  if (protected_state($remaining, $targets)!==$protected_before || retained_objects($viewer)!==$objects_before) {
    throw new Exception('Protected state changed.');
  }
  echo json_encode(array('passed'=>true, 'deletedUsers'=>$deleted, 'alreadyAbsent'=>$absent,
    'deletedConduitTokens'=>$tokens, 'deletedEntryBindings'=>$bindings,
    'protectedUsersUnchanged'=>true, 'protectedNativeSessionsUnchanged'=>true,
    'projectsPreserved'=>count($objects_before[0]), 'tasksPreserved'=>count($objects_before[1])))."\n";
} catch (Throwable $error) {
  // Do not emit SQL, user fields, tokens, or credentials from exception text.
  fwrite(STDERR, 'Fixture cleanup rejected: '.get_class($error).' at '.basename($error->getFile()).':'.$error->getLine()."\n");
  exit(1);
}
