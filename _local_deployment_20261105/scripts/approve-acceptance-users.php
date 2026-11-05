<?php
require_once '/opt/phorge/phorge/scripts/__init_script__.php';
$viewer = PhabricatorUser::getOmnipotentUser();
$admin = id(new PhabricatorPeopleQuery())->setViewer($viewer)
  ->withUsernames(array('siteadmin'))->executeOne();
if (!$admin || !$admin->getIsAdmin()) { throw new Exception('Provision siteadmin first.'); }
foreach (array('test_admin','a_lead','a_member','b_lead','b_member','guest') as $username) {
  $user = id(new PhabricatorPeopleQuery())->setViewer($viewer)
    ->withUsernames(array($username))->executeOne();
  if (!$user) { echo "$username: not registered yet\n"; continue; }
  // Authorized operator provisioning for synthetic acceptance identities.
  // This is explicitly not a claim that the browser approval/MFA flow passed.
  $user->setIsApproved(1);
  if ($username === 'test_admin') { $user->setIsAdmin(1); }
  $user->save();
  echo "$username: approved, admin=".($user->getIsAdmin()?'yes':'no')."\n";
}
