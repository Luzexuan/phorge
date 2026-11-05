<?php
// Native route and real database-policy regression. No bearer URLs are printed.
require_once '/opt/phorge/phorge/scripts/__init_script__.php';
$checks = array();
function file_guard_check($name, $condition) {
  global $checks;
  $checks[] = array('name' => $name, 'passed' => (bool)$condition);
  if (!$condition) { throw new Exception('File guard check failed: '.$name); }
}
function file_guard_allows($user, $path) {
  try {
    id(new TeamEntrySessionGuard())->enforceFilePolicy($user, $path);
    return true;
  } catch (TeamEntryFilePolicyException $ex) {
    return false;
  }
}
$omni = PhabricatorUser::getOmnipotentUser();
$file = id(new PhabricatorFileQuery())->setViewer($omni)
  ->withNames(array('ACC26-private-attachment.txt'))->executeOne();
if (!$file) { throw new Exception('Run acceptance-phorge.php first.'); }
$phid = $file->getPHID();
$paths = array(
  'data' => '/file/data/test-key/'.$phid.'/attachment.txt',
  'download' => '/file/download/test-key/'.$phid.'/attachment.txt',
  'data-instance' => '/file/data/@example/test-key/'.$phid.'/attachment.txt',
  'download-instance' => '/file/download/@example/test-key/'.$phid.'/attachment.txt',
  'xform' => '/file/xform/thumb-60x45/'.$phid.'/test-key/',
  'xform-instance' => '/file/xform/@example/thumb-60x45/'.$phid.'/test-key/',
);
foreach ($paths as $name => $path) {
  file_guard_check('native route '.$name,
    TeamEntrySessionGuard::getProtectedFilePHID($path) === $phid);
}
foreach (array('/auth/login/', '/res/example', '/file/upload/', '/F21') as $index => $path) {
  file_guard_check('unrelated route '.$index,
    TeamEntrySessionGuard::getProtectedFilePHID($path) === null);
}
$users = id(new PhabricatorPeopleQuery())->setViewer($omni)
  ->withUsernames(array('test_admin', 'a_lead', 'a_member', 'b_lead', 'b_member', 'guest'))
  ->execute();
$users = mpull($users, null, 'getUsername');
file_guard_check('all six registered fixtures exist', count($users) === 6);
$users['anonymous'] = new PhabricatorUser();
foreach ($users as $name => $user) {
  foreach ($paths as $kind => $path) {
    file_guard_check('private attachment '.$name.' '.$kind,
      file_guard_allows($user, $path) === in_array($name, array('test_admin', 'a_lead')));
  }
}
$partial = clone $users['a_lead'];
$partial->attachSession(id(new PhabricatorAuthSession())->setIsPartial(1));
file_guard_check('partial authentication cannot fetch private file',
  !file_guard_allows($partial, $paths['data']));
$unapproved = clone $users['a_lead'];
$unapproved->setIsApproved(0);
file_guard_check('unapproved account cannot fetch private file',
  !file_guard_allows($unapproved, $paths['data']));

// Intentionally use a public-profile derivative: native FileQuery skips its
// ancestry, so this fixture verifies the deployment's additional restriction.
$unguarded = AphrontWriteGuard::beginScopedUnguardedWrites();
$derived = id(new PhabricatorFileQuery())->setViewer($omni)
  ->withNames(array('ACC26-G04-derived-policy.txt'))->executeOne();
if (!$derived) {
  $derived = PhabricatorFile::newFromFileData("G04 synthetic profile derivative.\n", array(
    'name' => 'ACC26-G04-derived-policy.txt', 'profile' => true,
    'authorPHID' => $users['test_admin']->getPHID(),
    'viewPolicy' => PhabricatorPolicies::POLICY_USER, 'canCDN' => false));
  id(new PhabricatorTransformedFile())->setOriginalPHID($phid)
    ->setTransformedPHID($derived->getPHID())->setTransform('g04-policy-regression')->save();
}
unset($unguarded);
$derived_path = '/file/data/test-key/'.$derived->getPHID().'/derived.txt';
foreach ($users as $name => $user) {
  file_guard_check('profile derivative preserves original policy '.$name,
    file_guard_allows($user, $derived_path) === in_array($name, array('test_admin', 'a_lead')));
  $native = id(new PhabricatorFileQuery())->setViewer($user)
    ->withPHIDs(array($derived->getPHID()))->execute();
  file_guard_check('native query preserves profile source visibility '.$name,
    (bool)$native === in_array($name, array('test_admin', 'a_lead')));
}
$unguarded = AphrontWriteGuard::beginScopedUnguardedWrites();
$avatar = id(new PhabricatorFileQuery())->setViewer($omni)
  ->withNames(array('ACC26-G04-standalone-avatar.png'))->executeOne();
if (!$avatar) {
  $avatar = PhabricatorFile::newFromFileData(
    Filesystem::readFile('/opt/phorge/phorge/resources/builtin/image-100x100.png'), array(
      'name' => 'ACC26-G04-standalone-avatar.png', 'profile' => true,
      'authorPHID' => $users['test_admin']->getPHID(),
      'viewPolicy' => PhabricatorPolicies::POLICY_USER, 'canCDN' => false));
}
unset($unguarded);
foreach ($users as $name => $user) {
  if ($name === 'anonymous') { continue; }
  $native = id(new PhabricatorFileQuery())->setViewer($user)
    ->withPHIDs(array($avatar->getPHID()))->execute();
  file_guard_check('standalone public avatar remains visible '.$name, (bool)$native);
}
$builtin = id(new PhabricatorFileQuery())->setViewer($omni)
  ->withIsBuiltin(true)->withIsDeleted(false)->setLimit(1)->executeOne();
file_guard_check('anonymous builtin login resource remains available',
  $builtin && file_guard_allows(new PhabricatorUser(),
    '/file/data/test-key/'.$builtin->getPHID().'/builtin.png'));
file_guard_check('nonexistent resource rejected', !file_guard_allows($users['test_admin'],
  '/file/data/test-key/PHID-FILE-doesnotexist/unknown.txt'));
$response = id(new TeamEntrySessionMismatchHandler())->handleRequestThrowable(
  new AphrontRequest('45.77.36.106', '/'), new TeamEntryFilePolicyException());
file_guard_check('generic 404 contains no file identity or contents',
  $response->getHTTPResponseCode() === 404 && $response->buildResponseString() === "Not Found\n");
echo json_encode(array('passed' => true, 'checks' => $checks), JSON_PRETTY_PRINT)."\n";
