<?php

// Only the disposable regression database may contain these auth fixtures.
require_once '/opt/phorge/phorge/scripts/__init_script__.php';
if (getenv('TEAM_ENTRY_SESSION_ISOLATED') !== '1' ||
    PhabricatorEnv::getEnvConfig('storage.default-namespace') !== 'project_regression_base' ||
    !preg_match('/^team-project-regression-[a-f0-9]{8}-db$/D',
      PhabricatorEnv::getEnvConfig('mysql.host'))) {
  throw new Exception('Only the disposable regression database is allowed.');
}

function session_fixture_check($condition, $message) {
  if (!$condition) { throw new Exception($message); }
}

if (isset($argv[1]) && $argv[1] === '--verify') {
  $input = phutil_json_decode(file_get_contents('php://stdin'));
  $checks = array();
  $checks['rejected application sessions were revoked'] = true;
  $checks['rejected application bindings were removed'] = true;
  foreach ($input['revokedTokens'] as $token) {
    $digest = PhabricatorAuthSession::newSessionDigest(new PhutilOpaqueEnvelope($token));
    $checks['rejected application sessions were revoked'] =
      $checks['rejected application sessions were revoked'] &&
      !id(new PhabricatorAuthSession())->loadOneWhere('sessionKey = %s', $digest);
    $checks['rejected application bindings were removed'] =
      $checks['rejected application bindings were removed'] &&
      !id(new TeamEntrySessionBinding())->loadOneWhere('sessionKey = %s', $digest);
  }
  $checks['rejected form submissions created no work cards'] =
    count(id(new ManiphestTask())->loadAllWhere('1 = 1')) === $input['initialTaskCount'];
  foreach ($input['users'] as $spec) {
    $user = id(new PhabricatorUser())->loadOneWhere('phid = %s', $spec['phid']);
    session_fixture_check($user &&
      strncmp($user->getUsername(), 'sessionrecovery', 15) === 0,
      'Unexpected session fixture user.');
    $checks['fixture user '.$spec['role'].' unchanged'] =
      $user->getRealName() === $spec['realName'] && !$user->getIsAdmin();
  }
  session_fixture_check(!in_array(false, $checks, true), 'Session verification failed.');
  echo json_encode(array('passed' => true, 'checks' => $checks), JSON_PRETTY_PRINT)."\n";
  exit;
}

$dao = new TeamEntrySessionBinding();
$unguarded = AphrontWriteGuard::beginScopedUnguardedWrites();
queryfx($dao->establishConnection('w'),
  'CREATE TABLE IF NOT EXISTS %T ('.
  'id INT UNSIGNED NOT NULL AUTO_INCREMENT, '.
  'sessionKey VARBINARY(64) NOT NULL, userPHID VARBINARY(64) NOT NULL, '.
  'principalHash VARBINARY(64) NOT NULL, entryHash VARBINARY(64) NOT NULL, '.
  'sessionExpires INT UNSIGNED NOT NULL, PRIMARY KEY (id), '.
  'UNIQUE KEY key_session (sessionKey), KEY key_expires (sessionExpires)'.
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin', $dao->getTableName());
PhabricatorHash::digestWithNamedKey('initialize', 'team.entry.principal');
PhabricatorHash::digestWithNamedKey('initialize', 'team.entry.session');

$omni = PhabricatorUser::getOmnipotentUser();
$provider = new PhabricatorTraefikAuthProvider();
$config = id(new PhabricatorAuthProviderConfigQuery())->setViewer($omni)
  ->withProviderClasses(array(get_class($provider)))->executeOne();
if ($config) {
  session_fixture_check($config->getIsEnabled() && $config->getShouldAllowLogin() &&
    !$config->getShouldAllowRegistration(), 'Unexpected isolated identity configuration.');
  $accounts = id(new PhabricatorExternalAccountQuery())->setViewer($omni)
    ->withProviderConfigPHIDs(array($config->getPHID()))->execute();
  foreach ($accounts as $account) {
    session_fixture_check(strncmp($account->getUsername(), 'sessionrecovery', 15) === 0,
      'An unrelated isolated identity already uses the provider.');
  }
} else {
  $config = $provider->getDefaultProviderConfig()
    ->setProviderType($provider->getProviderType())
    ->setProviderDomain($provider->getProviderDomain())
    ->setIsEnabled(1)->setShouldAllowLogin(1)->setShouldAllowRegistration(0)
    ->setShouldAllowLink(0)->setShouldAllowUnlink(0)
    ->setShouldTrustEmails(0)->setShouldAutoLogin(0)->save();
}
$token = Filesystem::readRandomCharacters(8);
$fixture = array('users' => array(),
  'initialTaskCount' => count(id(new ManiphestTask())->loadAllWhere('1 = 1')));
foreach (array('a', 'b') as $role) {
  $username = 'sessionrecovery'.$role.$token;
  $user = id(new PhabricatorUser())->setUsername($username)
    ->setRealName('Session Recovery '.$role.' '.$token)
    ->setIsAdmin(0)->setIsApproved(1)->setIsEmailVerified(1)->save();
  $address = $username.'@session-recovery.invalid';
  id(new PhabricatorUserEmail())->setUserPHID($user->getPHID())
    ->setAddress($address)->setIsPrimary(1)->setIsVerified(1)->save();
  $principal = 'session-recovery-'.$role.'-'.$token;
  $config->getProvider()->newDefaultExternalAccount()
    ->setUserPHID($user->getPHID())->setUsername($username)
    ->setRealName($user->getRealName())->setEmail($address)->setEmailVerified(1)
    ->attachAccountIdentifiers(array(id(new PhabricatorExternalAccountIdentifier())
      ->setIdentifierRaw($principal)))->save();
  $fixture['users'][$role] = array('role' => $role, 'username' => $username,
    'phid' => $user->getPHID(), 'realName' => $user->getRealName(),
    'principal' => $principal, 'email' => $address);
}
unset($unguarded);
echo json_encode($fixture, JSON_PRETTY_PRINT)."\n";
