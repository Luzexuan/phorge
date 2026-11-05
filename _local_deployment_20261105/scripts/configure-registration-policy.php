<?php
// A directory-approved phone identifies the user. Self-entered registration
// email is a contact/login alias, not proof of control of that mailbox.
require_once '/opt/phorge/phorge/scripts/__init_script__.php';
$config = id(new PhabricatorAuthProviderConfigQuery())
  ->setViewer(PhabricatorUser::getOmnipotentUser())
  ->withProviderClasses(array('PhabricatorTraefikAuthProvider'))
  ->executeOne();
if (!$config) {
  throw new Exception('The personal identity provider must already exist.');
}
$config->setShouldTrustEmails(0)->setShouldAllowLink(0)->setShouldAllowUnlink(0)->save();
if (PhabricatorEnv::getEnvConfig('auth.require-email-verification')) {
  throw new Exception('Email verification is required; phone-only code delivery cannot satisfy that configuration.');
}
echo "Future provider emails are unverified; existing email verification flags were preserved.\n";
