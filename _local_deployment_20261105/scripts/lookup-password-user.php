<?php
// Read-only lookup used solely by the local root password-management command.
require_once '/opt/phorge/phorge/scripts/__init_script__.php';
if (PHP_SAPI !== 'cli' || !isset($password_username) ||
    !is_string($password_username) || !PhabricatorUser::validateUsername($password_username)) {
  throw new Exception('Use the local password-management command.');
}
$viewer = PhabricatorUser::getOmnipotentUser();
$user = id(new PhabricatorPeopleQuery())->setViewer($viewer)
  ->withUsernames(array($password_username))->executeOne();
if (!$user || $user->getUsername() !== $password_username || !$user->getIsApproved() ||
    $user->getIsDisabled() || $user->getIsSystemAgent() || $user->getIsMailingList()) {
  throw new Exception('Password management requires an approved, enabled person.');
}
$config = id(new PhabricatorAuthProviderConfigQuery())->setViewer($viewer)
  ->withProviderClasses(array('PhabricatorTraefikAuthProvider'))
  ->withIsEnabled(true)->executeOne();
if (!$config || !$config->getShouldAllowLogin()) {
  throw new Exception('The entry identity provider is not available.');
}
$accounts = id(new PhabricatorExternalAccountQuery())->setViewer($viewer)
  ->withProviderConfigPHIDs(array($config->getPHID()))
  ->withUserPHIDs(array($user->getPHID()))->needAccountIdentifiers(true)->execute();
if (count($accounts) !== 1) {
  throw new Exception('An unambiguous existing entry identity is required.');
}
$account = head($accounts);
$identifiers = $account->getAccountIdentifiers();
if (count($identifiers) !== 1) {
  throw new Exception('An unambiguous stable principal is required.');
}
$principal = head($identifiers)->getIdentifierRaw();
$email = id(new PhabricatorUserEmail())->loadOneWhere(
  'userPHID = %s AND isPrimary = 1', $user->getPHID());
if (!$principal || !$email || strcasecmp($email->getAddress(), $account->getEmail()) !== 0) {
  throw new Exception('The existing identity email binding differs.');
}
echo json_encode(array('username'=>$user->getUsername(),
  'user_id'=>$principal, 'phorge_phid'=>$user->getPHID(),
  'email'=>$email->getAddress(), 'is_approved'=>(bool)$user->getIsApproved(),
  'is_disabled'=>(bool)$user->getIsDisabled(),
  'is_system_agent'=>(bool)$user->getIsSystemAgent(),
  'is_mailing_list'=>(bool)$user->getIsMailingList()))."\n";
