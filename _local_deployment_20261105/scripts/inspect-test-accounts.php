<?php
/** Read-only test-account inventory. Never emit credentials or real-user PII. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit(1); }
ini_set('display_errors', '0');
try {
  require '/opt/phorge/phorge/scripts/__init_script__.php';
  $viewer = PhabricatorUser::getOmnipotentUser();
  $users = id(new PhabricatorPeopleQuery())->setViewer($viewer)->setLimit(10001)->execute();
  if (count($users) > 10000) { throw new Exception('capacity'); }
  $rows = array();
  foreach ($users as $user) {
    $emails = id(new PhabricatorUserEmail())->loadAllWhere('userPHID = %s', $user->getPHID());
    $addresses = array();
    foreach ($emails as $email) { $addresses[] = $email->getAddress(); }
    $synthetic = count($addresses) > 0;
    foreach ($addresses as $address) {
      if (!preg_match('/^[^@]+@acceptance\.test$/D', $address)) { $synthetic = false; }
    }
    $accounts = id(new PhabricatorExternalAccountQuery())->setViewer($viewer)
      ->withUserPHIDs(array($user->getPHID()))->needAccountIdentifiers(true)->execute();
    $bindings = array();
    foreach ($accounts as $account) {
      $identifiers = array();
      foreach ($account->getAccountIdentifiers() as $identifier) {
        $identifiers[] = $identifier->getIdentifierRaw();
      }
      $bindings[] = array('accountPHID'=>$account->getPHID(),
        'providerConfigPHID'=>$account->getProviderConfigPHID(),
        'identifiers'=>$identifiers);
    }
    $counts = array();
    foreach (array('nativeSessions'=>array(new PhabricatorAuthSession(), 'userPHID'),
      'conduitTokens'=>array(new PhabricatorConduitToken(), 'objectPHID'),
      'entryBindings'=>array(new TeamEntrySessionBinding(), 'userPHID')) as $key=>$spec) {
      $result = queryfx_one($spec[0]->establishConnection('r'), 'SELECT COUNT(*) AS n FROM %T WHERE %C = %s',
        $spec[0]->getTableName(), $spec[1], $user->getPHID());
      $counts[$key] = (int)$result['n'];
    }
    $rows[] = array('phid'=>$user->getPHID(), 'username'=>$synthetic ? $user->getUsername() : null,
      'syntheticEmailDomain'=>$synthetic, 'emails'=>$synthetic ? $addresses : array(),
      'isAdmin'=>(bool)$user->getIsAdmin(), 'isApproved'=>(bool)$user->getIsApproved(),
      'isDisabled'=>(bool)$user->getIsDisabled(), 'isSystemAgent'=>(bool)$user->getIsSystemAgent(),
      'isMailingList'=>(bool)$user->getIsMailingList(), 'bindings'=>$bindings, 'counts'=>$counts,
      'protectedSiteAdmin'=>$user->getUsername()==='siteadmin');
  }
  $projects = id(new PhabricatorProjectQuery())->setViewer($viewer)->needMembers(true)->setLimit(10001)->execute();
  $project_rows = array();
  foreach ($projects as $project) {
    $project_rows[] = array('phid'=>$project->getPHID(), 'id'=>(int)$project->getID(),
      'authorPHID'=>$project->getAuthorPHID(), 'memberPHIDs'=>$project->getMemberPHIDs());
  }
  $tasks = id(new ManiphestTaskQuery())->setViewer($viewer)->setLimit(10001)->execute();
  $task_rows = array();
  foreach ($tasks as $task) {
    $task_rows[] = array('phid'=>$task->getPHID(), 'id'=>(int)$task->getID(),
      'authorPHID'=>$task->getAuthorPHID(), 'ownerPHID'=>$task->getOwnerPHID());
  }
  echo json_encode(array('users'=>$rows, 'projects'=>$project_rows, 'tasks'=>$task_rows), JSON_UNESCAPED_UNICODE)."\n";
} catch (Throwable $error) {
  fwrite(STDERR, 'Read-only inventory error '.get_class($error).' at '.basename($error->getFile()).':'.$error->getLine()."\n"); exit(1);
}
