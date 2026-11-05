<?php
// Deployment acceptance: exact existing synthetic identities, three registered
// temporary objects, native Conduit creation/edit, and exact-object cleanup.
require_once '/opt/phorge/phorge/scripts/__init_script__.php';
$run = getenv('TEAM_PRIVATE_DEFAULTS_TEST_RUN');
if (!is_string($run) || !preg_match('/^[a-z0-9]{8,32}$/D', $run)) {
  throw new Exception('An explicit unique acceptance run token is required.');
}
$prefix = 'PRIVATEDEFAULTS-'.$run;
$report = array('verifiedAt' => gmdate('c'), 'checks' => array(),
  'scope' => 'Native Conduit creation/edit with existing synthetic users; no credentials or user state changed.',
  'objects' => array(), 'cleanup' => array());
$objects = array();
$users = array();
function pd_check($name, $condition) {
  global $report;
  $report['checks'][] = array('name' => $name, 'passed' => (bool)$condition);
  if (!$condition) { throw new Exception('Acceptance assertion failed.'); }
}
function pd_api($user, $method, array $params) {
  return id(new ConduitCall($method, $params))->setUser($user)->execute();
}
function pd_can($user, $object, $capability) {
  return PhabricatorPolicyFilter::hasCapability($user, $object, $capability);
}
function pd_project($phid) {
  return id(new PhabricatorProjectQuery())
    ->setViewer(PhabricatorUser::getOmnipotentUser())
    ->withPHIDs(array($phid))->needMembers(true)->executeOne();
}
function pd_task($phid) {
  return id(new ManiphestTask())->loadOneWhere('phid = %s', $phid);
}
function pd_file($user,$phid) {
  try {
    return id(new PhabricatorFileQuery())->setViewer($user)
      ->setRaisePolicyExceptions(false)->withPHIDs(array($phid))->executeOne();
  } catch (PhabricatorPolicyException $denied) {
    return null;
  }
}
function pd_denied($user, $method, array $params) {
  try { pd_api($user, $method, $params); return false; }
  catch (Exception $ex) {
    return $ex instanceof PhabricatorPolicyException ||
      (bool)preg_match('/^No object exists with PHID "PHID-[A-Z]+-[a-z0-9]+"\\.$/D',
        $ex->getMessage());
  }
}
function pd_existing_snapshot() {
  $data = array();
  foreach (array(new PhabricatorProject(), new ManiphestTask(), new PhrictionDocument()) as $dao) {
    $rows = queryfx_all($dao->establishConnection('r'),
      'SELECT phid, viewPolicy, editPolicy FROM %T ORDER BY phid', $dao->getTableName());
    foreach ($rows as $row) { $data[$row['phid']] = $row; }
  }
  $dao = new PhabricatorFile();
  foreach (queryfx_all($dao->establishConnection('r'),
    'SELECT phid, viewPolicy FROM %T ORDER BY phid',$dao->getTableName()) as $row) {
    $data[$row['phid']] = $row;
  }
  return $data;
}
try {
  $viewer = PhabricatorUser::getOmnipotentUser();
  foreach (array('a_lead', 'a_member', 'b_member', 'siteadmin') as $name) {
    $user = id(new PhabricatorPeopleQuery())->setViewer($viewer)
      ->withUsernames(array($name))->needUserSettings(true)->executeOne();
    if (!$user || !$user->getIsApproved() || $user->getIsDisabled()) {
      throw new Exception('Required approved acceptance identity is unavailable.');
    }
    if ($name !== 'siteadmin') {
      $email = id(new PhabricatorUserEmail())->loadOneWhere(
        'userPHID = %s AND isPrimary = 1', $user->getPHID());
      if (!$email || $email->getAddress() !== $name.'@acceptance.test' || $user->getIsAdmin()) {
        throw new Exception('Unsafe synthetic identity.');
      }
    } else if (!$user->getIsAdmin()) {
      throw new Exception('Real siteadmin is not an administrator.');
    }
    $users[$name] = $user;
  }
  $owner = $users['a_lead']; $member = $users['a_member'];
  $outsider = $users['b_member']; $admin = $users['siteadmin'];
  $before = pd_existing_snapshot();
  $v = PhabricatorPolicyCapability::CAN_VIEW;
  $e = PhabricatorPolicyCapability::CAN_EDIT;
  $j = PhabricatorPolicyCapability::CAN_JOIN;

  $new_project = PhabricatorProject::initializeNewProject($owner);
  $new_task = ManiphestTask::initializeNewTask($owner);
  pd_check('new project defaults are creator/admin with no open joining',
    $new_project->getViewPolicy() === TeamPrivateProjectPolicyRule::POLICY &&
    $new_project->getEditPolicy() === TeamPrivateProjectPolicyRule::POLICY &&
    $new_project->getJoinPolicy() === PhabricatorPolicies::POLICY_NOONE);
  pd_check('new task defaults are creator/admin',
    $new_task->getViewPolicy() === TeamPrivateTaskPolicyRule::POLICY &&
    $new_task->getEditPolicy() === TeamPrivateTaskPolicyRule::POLICY);
  foreach (array($new_project, $new_task) as $template) {
    $choices = id(new PhabricatorPolicyQuery())->setViewer($owner)
      ->setObject($template)->execute();
    $policy = idx($choices, $template->getViewPolicy());
    pd_check('custom default is selectable and has a readable name: '.get_class($template),
      $policy && $policy->isValidPolicyForEdit() && strlen($policy->getName()) > 0);
  }

  $result = pd_api($owner, 'project.edit', array('transactions' => array(
    array('type' => 'name', 'value' => $prefix.' project'),
  )));
  $project_phid = $result['object']['phid'];
  $objects[] = array('type' => 'project', 'phid' => $project_phid, 'author' => $owner->getPHID(), 'name' => $prefix.' project');
  $report['objects'] = $objects;
  $project = pd_project($project_phid);
  pd_check('ordinary creator can create and manage a project without supplying a policy or members',
    $project && pd_can($owner,$project,$v) && pd_can($owner,$project,$e));
  pd_check('new persisted project keeps the default policies',
    $project->getViewPolicy() === TeamPrivateProjectPolicyRule::POLICY &&
    $project->getEditPolicy() === TeamPrivateProjectPolicyRule::POLICY &&
    $project->getJoinPolicy() === PhabricatorPolicies::POLICY_NOONE);
  pd_check('administrator retains access to the new private project',pd_can($admin,$project,$v)&&pd_can($admin,$project,$e));
  pd_check('uninvited users cannot view edit or join the new project',
    !pd_can($member,$project,$v) && !pd_can($outsider,$project,$v) &&
    !pd_can($outsider,$project,$e) && !pd_can($outsider,$project,$j));
  pd_api($owner,'project.edit',array('objectIdentifier'=>$project_phid,'transactions'=>array(
    array('type'=>'members.add','value'=>array($member->getPHID())),
    array('type'=>'description','value'=>'Synthetic default-policy invitation check.'),
  )));
  $project = pd_project($project_phid);
  pd_check('explicitly invited member can view but cannot manage project or invites',
    pd_can($member,$project,$v) && !pd_can($member,$project,$e));
  pd_check('invited member cannot grant outsider membership through Conduit',pd_denied($member,
    'project.edit',array('objectIdentifier'=>$project_phid,'transactions'=>array(
      array('type'=>'members.add','value'=>array($outsider->getPHID())),
    ))));
  $project = pd_project($project_phid);
  pd_check('denied invitation leaves outsider absent and private',
    !in_array($outsider->getPHID(),$project->getMemberPHIDs()) && !pd_can($outsider,$project,$v));

  $result = pd_api($owner,'maniphest.edit',array('transactions'=>array(
    array('type'=>'title','value'=>$prefix.' task'),
    array('type'=>'projects.add','value'=>array($project_phid)),
  )));
  $task_phid = $result['object']['phid'];
  $objects[] = array('type'=>'task','phid'=>$task_phid,'author'=>$owner->getPHID(),'name'=>$prefix.' task');
  $report['objects'] = $objects;
  $task = pd_task($task_phid);
  pd_check('ordinary creator can create and edit a task with no explicit ACL',
    $task && pd_can($owner,$task,$v) && pd_can($owner,$task,$e));
  pd_check('persisted task retains creator/admin defaults',
    $task->getViewPolicy()===TeamPrivateTaskPolicyRule::POLICY &&
    $task->getEditPolicy()===TeamPrivateTaskPolicyRule::POLICY);
  pd_check('project label does not reveal a private task to project members or outsiders',
    !pd_can($member,$task,$v) && !pd_can($outsider,$task,$v));
  pd_check('administrator can inspect and manage the default-private task',pd_can($admin,$task,$v)&&pd_can($admin,$task,$e));
  pd_check('outsider cannot widen the task view policy',pd_denied($outsider,
    'maniphest.edit',array('objectIdentifier'=>$task_phid,'transactions'=>array(
      array('type'=>'view','value'=>'users'),
    ))));
  $file_bytes = $prefix." synthetic private file.\n";
  $file_phid = pd_api($owner,'file.upload',array(
    'data_base64'=>base64_encode($file_bytes),'name'=>$prefix.'-file.txt','canCDN'=>false));
  $objects[] = array('type'=>'file','phid'=>$file_phid,'author'=>$owner->getPHID(),'name'=>$prefix.'-file.txt');
  $report['objects'] = $objects;
  $file = pd_file($owner,$file_phid);
  pd_check('standalone file upload defaults to no-one while uploader can read it',
    $file && $file->getViewPolicy()===PhabricatorPolicies::POLICY_NOONE &&
    base64_decode(pd_api($owner,'file.download',array('phid'=>$file_phid)))===$file_bytes);
  pd_check('unrelated member outsider and administrator cannot read an isolated private file',
    !pd_file($member,$file_phid) && !pd_file($outsider,$file_phid) && !pd_file($admin,$file_phid));
  id(new ManiphestTransactionEditor())->setActor($owner)
    ->setContentSource(PhabricatorContentSource::newForSource('console',array()))
    ->setContinueOnNoEffect(true)->setContinueOnMissingFields(true)
    ->applyTransactions($task,array(id(new ManiphestTransaction())
      ->setTransactionType(PhabricatorTransactions::TYPE_FILE)
      ->setNewValue(array($file_phid=>PhabricatorFileAttachment::MODE_ATTACH))));
  pd_check('formal attachment grants access through the authorized private task',
    pd_file($admin,$file_phid) && !pd_file($member,$file_phid) && !pd_file($outsider,$file_phid));
  pd_api($owner,'maniphest.edit',array('objectIdentifier'=>$task_phid,'transactions'=>array(
    array('type'=>'owner','value'=>$member->getPHID()),
  )));
  $task = pd_task($task_phid);
  pd_check('explicit task assignee retains native view/edit rights',pd_can($member,$task,$v)&&pd_can($member,$task,$e));
  pd_check('authorized project member can download attachment through task assignment',
    pd_file($member,$file_phid) && !pd_file($outsider,$file_phid) &&
    base64_decode(pd_api($member,'file.download',array('phid'=>$file_phid)))===$file_bytes);
  pd_api($owner,'maniphest.edit',array('objectIdentifier'=>$task_phid,'transactions'=>array(
    array('type'=>'owner','value'=>null),
  )));
  $task = pd_task($task_phid);
  pd_check('removing assignment revokes the prior assignee automatic rights',!pd_can($member,$task,$v)&&!pd_can($member,$task,$e));
  pd_check('revoking task access also revokes attachment access',!pd_file($member,$file_phid));
  pd_api($admin,'maniphest.edit',array('objectIdentifier'=>$task_phid,'transactions'=>array(
    array('type'=>'description','value'=>'Synthetic administrator inspection check.'),
  )));
  $task = pd_task($task_phid);
  pd_check('later administrative editing does not replace the original task creator',
    $task->getAuthorPHID()===$owner->getPHID() && pd_can($owner,$task,$v) && pd_can($owner,$task,$e));
  $after = pd_existing_snapshot();
  pd_check('all pre-existing project task document and file ACLs are unchanged',
    array_intersect_key($after,$before)===$before);
} catch (Throwable $error) {
  $report['error'] = array('type'=>get_class($error));
} finally {
  foreach (array_reverse($objects) as $spec) {
    try {
      $object = $spec['type']==='task' ? pd_task($spec['phid']) :
        ($spec['type']==='file' ? pd_file(PhabricatorUser::getOmnipotentUser(),$spec['phid']) : pd_project($spec['phid']));
      $name = $object ? ($spec['type']==='task' ? $object->getTitle() : $object->getName()) : null;
      if (!$object || $object->getAuthorPHID()!==$spec['author'] ||
          $name!==$spec['name'] || strpos($name,$prefix)!==0) {
        throw new Exception('Unsafe temporary object cleanup target.');
      }
      id(new PhabricatorDestructionEngine())->destroyObject($object);
      $gone = $spec['type']==='task' ? !pd_task($spec['phid']) :
        ($spec['type']==='file' ? !pd_file(PhabricatorUser::getOmnipotentUser(),$spec['phid']) : !pd_project($spec['phid']));
      $report['cleanup'][] = array('phid'=>$spec['phid'],'passed'=>$gone);
    } catch (Throwable $error) {
      $report['cleanup'][] = array('phid'=>$spec['phid'],'passed'=>false,'type'=>get_class($error));
    }
  }
  $report['passed'] = !isset($report['error']) && count($report['checks'])>0 &&
    !in_array(false,array_column($report['checks'],'passed'),true) &&
    !in_array(false,array_column($report['cleanup'],'passed'),true);
  $report['completedAt']=gmdate('c');
  echo json_encode($report,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)."\n";
  exit($report['passed']?0:1);
}
