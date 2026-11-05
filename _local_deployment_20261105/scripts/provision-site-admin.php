<?php
require_once '/opt/phorge/phorge/scripts/__init_script__.php';
$viewer = PhabricatorUser::getOmnipotentUser();
$username = 'siteadmin';
$address = '177000177@qq.com';
$principal = 'linkerbot-site-admin';
$user = id(new PhabricatorPeopleQuery())->setViewer($viewer)
  ->withUsernames(array($username))->executeOne();
if (!$user) {
  $user = id(new PhabricatorUser())->setUsername($username)
    ->setRealName('Site Administrator')->setIsApproved(1);
  $email = id(new PhabricatorUserEmail())->setAddress($address)->setIsVerified(1);
  id(new PhabricatorUserEditor())->setActor($viewer)->createNewUser($user, $email);
}
$email = id(new PhabricatorUserEmail())->loadOneWhere(
  'userPHID = %s AND isPrimary = 1', $user->getPHID());
if (!$email || $email->getAddress() !== $address) {
  throw new Exception('Existing administrator email differs; refusing to reassign identity.');
}
$config = id(new PhabricatorAuthProviderConfigQuery())->setViewer($viewer)
  ->withProviderClasses(array('PhabricatorTraefikAuthProvider'))->executeOne();
if (!$config) { throw new Exception('Traefik identity provider is missing.'); }
$existing = id(new PhabricatorExternalAccountQuery())->setViewer($viewer)
  ->withProviderConfigPHIDs(array($config->getPHID()))
  ->withRawAccountIdentifiers(array($principal))->executeOne();
if ($existing && $existing->getUserPHID() !== $user->getPHID()) {
  throw new Exception('Entry identity is already bound to another user.');
}
if (!$existing) {
  $account = $config->getProvider()->newDefaultExternalAccount()
    ->setUserPHID($user->getPHID())->setUsername($username)
    ->setRealName($user->getRealName())->setEmail($address)->setEmailVerified(1)
    ->attachAccountIdentifiers(array(id(new PhabricatorExternalAccountIdentifier())
      ->setIdentifierRaw($principal)));
  $account->save();
}
if (!$user->getIsAdmin()) {
  // Bootstrap the first real administrator from the authorized operator CLI.
  // The omnipotent CLI viewer has no user PHID and cannot author transactions.
  $user->setIsAdmin(1)->setIsApproved(1)->save();
}
echo json_encode(array('username'=>$username, 'email'=>$address,
  'isAdmin'=>(bool)$user->getIsAdmin(), 'entryPrincipal'=>$principal,
  'provisioning'=>'operator-provisioned; actual email/DingTalk delivery not verified'),
  JSON_PRETTY_PRINT)."\n";
