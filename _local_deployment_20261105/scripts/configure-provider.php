<?php
require_once '/opt/phorge/phorge/scripts/__init_script__.php';
$viewer = PhabricatorUser::getOmnipotentUser();
$provider = new PhabricatorTraefikAuthProvider();
$existing = id(new PhabricatorAuthProviderConfigQuery())
  ->setViewer($viewer)
  ->withProviderClasses(array(get_class($provider)))
  ->executeOne();
if ($existing) {
  echo "Traefik personal identity provider already exists; preserved.\n";
  exit(0);
}
$config = $provider->getDefaultProviderConfig()
  ->setProviderType($provider->getProviderType())
  ->setProviderDomain($provider->getProviderDomain())
  ->setShouldAllowLogin(1)
  ->setShouldAllowRegistration(1)
  ->setShouldAllowLink(0)
  ->setShouldAllowUnlink(0)
  // Directory phone/DingTalk login does not prove ownership of a submitted email.
  ->setShouldTrustEmails(0)
  ->setShouldAutoLogin(0);
$config->save();
echo "Traefik personal identity provider initialized; no user created.\n";
