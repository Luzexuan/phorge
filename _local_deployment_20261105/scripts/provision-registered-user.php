<?php
// Invoked only by the root operator approval CLI. The CLI supplies $registration
// as a JSON-decoded value in the same PHP stdin stream; no web route exists.
require_once '/opt/phorge/phorge/scripts/__init_script__.php';

if (PHP_SAPI !== 'cli' || !isset($registration) || !is_array($registration)) {
  throw new Exception('Use the local registration approval CLI.');
}
foreach (array('registration_id', 'user_id', 'phone', 'email', 'name', 'username',
  'approved_by', 'confirmed_phone') as $key) {
  if (!isset($registration[$key]) || !is_string($registration[$key]) ||
      $registration[$key] === '') {
    throw new Exception('Registration input is incomplete.');
  }
}
$id = $registration['registration_id'];
$principal = $registration['user_id'];
$phone = $registration['phone'];
$address = $registration['email'];
$username = $registration['username'];
$name = $registration['name'];
if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D', $id) ||
    $principal !== 'reg-'.$id || !preg_match('/^1[3-9][0-9]{9}$/D', $phone) ||
    $registration['confirmed_phone'] !== $phone ||
    $address !== strtolower($address) || !PhabricatorUserEmail::isAllowedAddress($address) ||
    !PhabricatorUser::validateUsername($username) ||
    $name !== trim($name) || phutil_utf8_strlen($name) > 80 ||
    preg_match('/[\x00-\x1f\x7f]/', $name)) {
  throw new Exception('Registration input is invalid or unsupported.');
}
if (in_array(strtolower($username), array('admin', 'administrator', 'root',
    'siteadmin', 'system', 'phabricator', 'phorge', 'test_admin'))) {
  throw new Exception('This username is reserved.');
}
foreach (array('org_unit_id', 'manager_user_id', 'position') as $key) {
  if (idx($registration, $key) !== null) {
    throw new Exception('Organization fields must remain empty during initial registration.');
  }
}

$viewer = PhabricatorUser::getOmnipotentUser();
$actor = id(new PhabricatorPeopleQuery())->setViewer($viewer)
  ->withUsernames(array($registration['approved_by']))->executeOne();
if (!$actor || !$actor->getIsAdmin() || $actor->getIsDisabled()) {
  throw new Exception('Approval attribution must name an enabled site administrator.');
}
$config = id(new PhabricatorAuthProviderConfigQuery())->setViewer($viewer)
  ->withProviderClasses(array('PhabricatorTraefikAuthProvider'))
  ->withIsEnabled(true)->executeOne();
if (!$config || !$config->getShouldAllowLogin() || $config->getShouldTrustEmails() ||
    $config->getShouldAllowLink() || $config->getShouldAllowUnlink()) {
  throw new Exception('Traefik provider must allow login, distrust claimed emails, and disable account linking.');
}
$accounts = id(new PhabricatorExternalAccountQuery())->setViewer($viewer)
  ->withProviderConfigPHIDs(array($config->getPHID()))
  ->withRawAccountIdentifiers(array($principal))->needAccountIdentifiers(true)->execute();
$account = $accounts ? head($accounts) : null;
if (count($accounts) > 1) { throw new Exception('Ambiguous external identity.'); }
if ($account) {
  $exact = false;
  foreach ($account->getAccountIdentifiers() as $identifier) {
    $exact = $exact || hash_equals($principal, $identifier->getIdentifierRaw());
  }
  if (!$exact || $account->getProperty('registration.id') !== $id ||
      $account->getProperty('registration.phone') !== $phone ||
      $account->getEmail() !== $address) {
    throw new Exception('Existing identity does not belong to this registration.');
  }
  $user = id(new PhabricatorPeopleQuery())->setViewer($viewer)
    ->withPHIDs(array($account->getUserPHID()))->executeOne();
  $email = $user ? id(new PhabricatorUserEmail())->loadOneWhere(
    'userPHID = %s AND isPrimary = 1', $user->getPHID()) : null;
  if (!$user || !$email || $email->getAddress() !== $address ||
      $user->getUsername() !== $username || $user->getRealName() !== $name ||
      $user->getIsAdmin() || $user->getIsSystemAgent() || $user->getIsMailingList() ||
      $user->getIsDisabled() || !$user->getIsApproved()) {
    throw new Exception('Previously provisioned account changed; refusing reassignment.');
  }
  $created = false;
} else {
  if (idx($registration, 'phorge_phid')) {
    throw new Exception('Previously recorded external identity is missing; refusing to create a replacement account.');
  }
  // Never adopt an existing user by matching their self-claimed email/name.
  $collision = id(new PhabricatorPeopleQuery())->setViewer($viewer)
    ->withUsernames(array($username))->execute();
  $email_collision = id(new PhabricatorUserEmail())->loadOneWhere(
    'LOWER(address) = %s', $address);
  if ($collision || $email_collision) {
    throw new Exception('Username or email is already reserved by a Phorge account.');
  }
  $all_accounts = id(new PhabricatorExternalAccountQuery())->setViewer($viewer)
    ->withProviderConfigPHIDs(array($config->getPHID()))->execute();
  foreach ($all_accounts as $other) {
    if ($other->getProperty('registration.phone') === $phone ||
        strtolower((string)$other->getEmail()) === $address) {
      throw new Exception('Phone or email is already reserved by another external identity.');
    }
  }
  $user = id(new PhabricatorUser())->setUsername($username)->setRealName($name)
    ->setIsAdmin(0)->setIsSystemAgent(0)->setIsMailingList(0)->setIsDisabled(0)
    ->setIsApproved(1)->setIsEmailVerified(0);
  $email = id(new PhabricatorUserEmail())->setAddress($address)->setIsVerified(0);
  $unguarded = AphrontWriteGuard::beginScopedUnguardedWrites();
  // All three objects use the existing user database. An outer transaction
  // makes user+email+principal mapping commit or roll back together.
  $user->openTransaction();
  try {
    id(new PhabricatorUserEditor())->setActor($actor)->createNewUser($user, $email);
    $account = $config->getProvider()->newDefaultExternalAccount()
      ->setUserPHID($user->getPHID())->setUsername($username)->setRealName($name)
      ->setEmail($address)->setEmailVerified(0)
      ->setProperty('registration.id', $id)
      ->setProperty('registration.phone', $phone)
      ->setProperty('registration.approved-by', $actor->getPHID())
      ->setProperty('registration.phone-confirmation',
        idx($registration, 'password_approval') ? 'operator-reviewed-registration' :
          (idx($registration, 'acceptance_only') ? 'acceptance-only' : 'operator-confirmed-dingtalk'))
      ->attachAccountIdentifiers(array(id(new PhabricatorExternalAccountIdentifier())
        ->setIdentifierRaw($principal)));
    $account->save();
    $user->saveTransaction();
  } catch (Throwable $ex) {
    $user->killTransaction();
    throw $ex;
  }
  unset($unguarded);
  $created = true;
}
echo json_encode(array('user_id'=>$principal, 'registration_id'=>$id,
  'username'=>$user->getUsername(), 'phorge_phid'=>$user->getPHID(),
  'created'=>$created, 'is_admin'=>(bool)$user->getIsAdmin(),
  'email_verified'=>(bool)$email->getIsVerified(),
  'external_email_verified'=>(bool)$account->getEmailVerified()))."\n";
