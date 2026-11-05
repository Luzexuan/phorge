<?php

// Isolated navigation regression test. Run with: php tests/project-navigation.php
// These small view/model doubles keep the production controller logic testable
// without opening a database connection or creating any application objects.
function id($value) { return $value; }
function pht($pattern, ...$args) { return vsprintf($pattern, $args); }
function nonempty(...$values) {
  foreach ($values as $value) {
    if ($value) { return $value; }
  }
  return null;
}

class PhabricatorPolicyCapability {
  const CAN_VIEW = 'view';
  const CAN_EDIT = 'edit';
}
class PhabricatorPolicyException extends Exception {}
class TeamProjectProgress {
  public static function canPublish($viewer, $project) { return false; }
}
class Aphront404Response {}
class AphrontRequest {
  private $data;
  public function __construct(array $data) { $this->data = $data; }
  public function getURIData($key) {
    return isset($this->data[$key]) ? $this->data[$key] : null;
  }
}
class PhabricatorPolicyFilter {
  public static function hasCapability($viewer, $project, $capability) {
    return $project->visible;
  }
}
class PHUIListItemView {
  public $properties = array();
  public function __call($name, $args) {
    $this->properties[$name] = $args[0];
    return $this;
  }
}
class NavigationTestCrumbs {
  public $actions = array();
  public $crumbs = array();
  public function addAction($action) {
    $this->actions[] = $action;
    return $this;
  }
  public function addTextCrumb($name, $uri = null, $archived = false) {
    $this->crumbs[] = array($name, $uri, $archived);
    return $this;
  }
}
class PhabricatorController {
  private $request;
  public function setRequest($request) { $this->request = $request; return $this; }
  public function getRequest() { return $this->request; }
  public function getViewer() { return new stdClass(); }
  public function getApplicationURI($path) { return '/project/'.$path; }
  protected function buildApplicationCrumbs() {
    return id(new NavigationTestCrumbs())->addTextCrumb('Projects', '/project/');
  }
}
class PhabricatorProject {
  private $id;
  private $parent;
  public $visible = true;
  public $hasWorkboard = false;
  public function __construct($id, $parent = null) {
    $this->id = $id;
    $this->parent = $parent;
  }
  public function getID() { return $this->id; }
  public function getPHID() { return 'PHID-PROJ-'.$this->id; }
  public function getName() { return 'Project '.$this->id; }
  public function getParentProject() { return $this->parent; }
  public function getPrimarySlug() { return null; }
  public function getProfileURI() { return '/project/profile/'.$this->id.'/'; }
  public function getWorkboardURI() { return '/project/board/'.$this->id.'/'; }
  public function getHasWorkboard() { return $this->hasWorkboard; }
  public function isArchived() { return false; }
  public function getAncestorProjects() {
    $ancestors = array();
    for ($parent = $this->parent; $parent; $parent = $parent->parent) {
      $ancestors[] = $parent;
    }
    return $ancestors;
  }
}
class PhabricatorProjectQuery {
  public static $projects = array();
  public static $capabilities;
  private $ids = array();
  public function __call($name, $args) {
    if ($name === 'withIDs') { $this->ids = $args[0]; }
    if ($name === 'requireCapabilities') { self::$capabilities = $args[0]; }
    return $this;
  }
  public function executeOne() {
    $id = $this->ids[0];
    $project = isset(self::$projects[$id]) ? self::$projects[$id] : null;
    if ($project && !$project->visible) {
      throw new PhabricatorPolicyException('View denied.');
    }
    return $project;
  }
}
class PhabricatorProjectEditEngine {
  public $parent;
  public $milestone;
  private $controller;
  public function setController($controller) {
    $this->controller = $controller;
    return $this;
  }
  public function buildResponse() {
    // Exercise the controller prefix. The native engine appends its own
    // current-project and edit crumbs after this call.
    $build = new ReflectionMethod($this->controller, 'buildApplicationCrumbs');
    $build->setAccessible(true);
    return $build->invoke($this->controller);
  }
  public function getParentProject() { return $this->parent; }
  public function getMilestoneProject() { return $this->milestone; }
}

$overrides = dirname(__DIR__).'/config/phorge/overrides/';
$staging = getenv('TEAM_PROJECT_STAGING') === '1' ||
  in_array('--staging', $argv, true);
$controller_overrides = $staging
  ? dirname(__DIR__).'/config/phorge/progress-staging/'
  : $overrides;
require $controller_overrides.'PhabricatorProjectController.php';
require $overrides.'PhabricatorProjectEditController.php';

class NavigationTestController extends PhabricatorProjectController {
  public function useProject($project) { return $this->setProject($project); }
  public function crumbs($board = false) {
    return $board ? $this->newWorkboardCrumbs() : $this->buildApplicationCrumbs();
  }
}

$checks = array();
function navigation_check($name, $condition) {
  global $checks;
  if (!$condition) { throw new Exception($name); }
  $checks[] = $name;
}
function navigation_href($crumbs) {
  return $crumbs->actions[0]->properties['setHref'];
}

$root = new PhabricatorProject(12);
$child = new PhabricatorProject(21, $root);
$leaf = new PhabricatorProject(45, $child);
$controller = new NavigationTestController();

navigation_check('project list has no self-referencing back action',
  !$controller->crumbs()->actions);
$crumbs = $controller->useProject($root)->crumbs();
navigation_check('root project returns to the explicit hierarchy query',
  navigation_href($crumbs) === '/project/query/hierarchy/');
$crumbs = $controller->useProject($child)->crumbs();
navigation_check('child project returns to its parent directory',
  navigation_href($crumbs) === '/project/subprojects/12/');
$crumbs = $controller->useProject($leaf)->crumbs();
navigation_check('deep project returns exactly one hierarchy level',
  navigation_href($crumbs) === '/project/subprojects/21/');
navigation_check('ancestor crumbs link to each ancestor directory',
  $crumbs->crumbs[1][1] === '/project/subprojects/12/' &&
  $crumbs->crumbs[2][1] === '/project/subprojects/21/');
navigation_check('current project crumb still opens its profile',
  $crumbs->crumbs[3][1] === '/project/profile/45/');
navigation_check('mobile icon action retains an accessible label',
  $crumbs->actions[0]->properties['setMetadata']['tip'] === '返回上一级');
$child->hasWorkboard = true;
$crumbs = $controller->crumbs(true);
navigation_check('board back action still follows the directory hierarchy',
  navigation_href($crumbs) === '/project/subprojects/21/');
navigation_check('board ancestor crumb preserves workboard navigation',
  $crumbs->crumbs[2][1] === '/project/board/21/');
$child->visible = false;
$crumbs = $controller->crumbs();
navigation_check('inaccessible parent falls back to project hierarchy',
  navigation_href($crumbs) === '/project/query/hierarchy/');
navigation_check('inaccessible ancestor name is not rendered',
  count($crumbs->crumbs) === 3 &&
  $crumbs->crumbs[2][0] === 'Project 45');
$child->visible = true;

$edit = new PhabricatorProjectEditController();
$set_project = new ReflectionMethod('PhabricatorProjectController', 'setProject');
$set_project->setAccessible(true);
$set_project->invoke($edit, $child);
$build = new ReflectionMethod('PhabricatorProjectEditController', 'buildApplicationCrumbs');
$build->setAccessible(true);
$engine = new PhabricatorProjectEditEngine();
$edit->setEngine($engine);
$engine->parent = $child;
navigation_check('create child returns to its actual creation directory',
  navigation_href($build->invoke($edit)) === '/project/subprojects/21/');
$engine->parent = null;
$engine->milestone = $child;
navigation_check('create milestone returns to its actual creation directory',
  navigation_href($build->invoke($edit)) === '/project/subprojects/21/');

PhabricatorProjectQuery::$projects = array(12 => $root, 21 => $child, 45 => $leaf);
$request = new AphrontRequest(array('id' => 45));
$edit = id(new PhabricatorProjectEditController())->setRequest($request);
$crumbs = $edit->handleRequest($request);
navigation_check('existing project edit loads its project navigation context',
  navigation_href($crumbs) === '/project/subprojects/21/');
navigation_check('edit crumb prefix includes ancestor directories once',
  count($crumbs->crumbs) === 3 &&
  $crumbs->crumbs[1][1] === '/project/subprojects/12/' &&
  $crumbs->crumbs[2][1] === '/project/subprojects/21/');
navigation_check('existing edit leaves current project crumb to native engine',
  !in_array('Project 45', array_column($crumbs->crumbs, 0), true));
navigation_check('navigation preload preserves view-only comment access',
  PhabricatorProjectQuery::$capabilities === array(PhabricatorPolicyCapability::CAN_VIEW));

$request = new AphrontRequest(array('id' => 12));
$edit = id(new PhabricatorProjectEditController())->setRequest($request);
navigation_check('existing root edit returns to hierarchy query',
  navigation_href($edit->handleRequest($request)) === '/project/query/hierarchy/');
$request = new AphrontRequest(array('id' => 999));
$edit = id(new PhabricatorProjectEditController())->setRequest($request);
navigation_check('unknown project edit still returns not found',
  $edit->handleRequest($request) instanceof Aphront404Response);
$leaf->visible = false;
$request = new AphrontRequest(array('id' => 45));
$edit = id(new PhabricatorProjectEditController())->setRequest($request);
$denied = false;
try {
  $edit->handleRequest($request);
} catch (PhabricatorPolicyException $exception) {
  $denied = true;
}
navigation_check('navigation loading does not expose an inaccessible project', $denied);

echo json_encode(array('passed' => count($checks), 'checks' => $checks),
  JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)."\n";
