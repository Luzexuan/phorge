<?php
require_once '/opt/phorge/phorge/scripts/__init_script__.php';
if (!class_exists('TeamEntrySessionBinding')) {
  throw new Exception('Mount the TeamEntrySessionGuard runtime extension first.');
}
$dao = new TeamEntrySessionBinding();
$conn = $dao->establishConnection('w');
$unguarded = AphrontWriteGuard::beginScopedUnguardedWrites();
queryfx($conn,
  'CREATE TABLE IF NOT EXISTS %T ('.
  'id INT UNSIGNED NOT NULL AUTO_INCREMENT, '.
  'sessionKey VARBINARY(64) NOT NULL, userPHID VARBINARY(64) NOT NULL, '.
  'principalHash VARBINARY(64) NOT NULL, entryHash VARBINARY(64) NOT NULL, '.
  'sessionExpires INT UNSIGNED NOT NULL, PRIMARY KEY (id), '.
  'UNIQUE KEY key_session (sessionKey), KEY key_expires (sessionExpires)'.
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin',
  $dao->getTableName());
unset($unguarded);
// Seed persisted HMAC keys before concurrent first browser requests arrive.
PhabricatorHash::digestWithNamedKey('initialize', 'team.entry.principal');
PhabricatorHash::digestWithNamedKey('initialize', 'team.entry.session');
echo "Entry-session binding schema initialized. Cookie values are never stored.\n";
