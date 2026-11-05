<?php

// Regression for an actual profile edit denial before setUser(). Run against
// the pinned upstream file to reproduce red, or the staged replacement to pass.
function id($object) { return $object; }
function urisprintf($pattern, ...$args) { return vsprintf($pattern, $args); }
class PhabricatorPolicyCapability {
  const CAN_VIEW = 'view';
  const CAN_EDIT = 'edit';
}
class PhabricatorPolicyException extends Exception {}
class Aphront404Response {}
class AphrontRequest {
  public function getURIData($key) { return 19; }
}
class PhabricatorUser {
  private $username;
  public function __construct($username) { $this->username = $username; }
  public function getUsername() { return $this->username; }
}
class PeopleDenialCrumbs {
  public $items = array();
  public function addTextCrumb($label, $uri = null) {
    $this->items[] = array($label, $uri);
    return $this;
  }
}
class PhabricatorPeopleController {
  public function getViewer() { return new PhabricatorUser('qa_reader'); }
  protected function buildApplicationCrumbs() {
    return id(new PeopleDenialCrumbs())->addTextCrumb('People', '/people/');
  }
}
class PhabricatorPeopleQuery {
  public static $deny = true;
  public static $capabilities;
  public function setViewer($viewer) { return $this; }
  public function withIDs(array $ids) { return $this; }
  public function needProfileImage($need) { return $this; }
  public function requireCapabilities(array $capabilities) {
    self::$capabilities = $capabilities;
    return $this;
  }
  public function executeOne() {
    if (self::$deny) {
      throw new PhabricatorPolicyException('Original edit policy denial.');
    }
    return null;
  }
}
$root = dirname(__DIR__);
$source = isset($argv[1]) ? $argv[1]
  : $root.'/config/phorge/progress-staging/PhabricatorPeopleProfileController.php';
require $source;
require $root.'/vendor/phorge/src/applications/people/controller/PhabricatorPeopleProfileEditController.php';

function render_crumbs($controller) {
  $method = new ReflectionMethod($controller, 'buildApplicationCrumbs');
  return $method->invoke($controller);
}
$checks = array();
function verify($name, $passed) {
  global $checks;
  $checks[] = array('name' => $name, 'passed' => (bool)$passed);
  if (!$passed) { throw new Exception($name); }
}
try {
  $controller = new PhabricatorPeopleProfileEditController();
  $denied = false;
  try { $controller->handleRequest(new AphrontRequest()); }
  catch (PhabricatorPolicyException $ex) {
    $denied = $ex->getMessage() === 'Original edit policy denial.';
  }
  verify('native edit query still requires both view and edit',
    PhabricatorPeopleQuery::$capabilities === array('view', 'edit'));
  verify('original policy denial is preserved before target is assigned',
    $denied && $controller->getUser() === null);
  $crumbs = render_crumbs($controller);
  verify('denial rendering has application crumbs without a secondary error',
    $crumbs->items === array(array('People', '/people/')));

  PhabricatorPeopleQuery::$deny = false;
  $missing = new PhabricatorPeopleProfileEditController();
  verify('missing target remains an ordinary 404',
    $missing->handleRequest(new AphrontRequest()) instanceof Aphront404Response);
  verify('missing-target response can render without profile context',
    render_crumbs($missing)->items === array(array('People', '/people/')));

  $controller->setUser(new PhabricatorUser('qa_self'));
  verify('loaded profile keeps its original username and profile link',
    render_crumbs($controller)->items === array(
      array('People', '/people/'), array('qa_self', '/p/qa_self/')));
  $report = array('source' => $source, 'checks' => $checks, 'passed' => true);
} catch (Throwable $ex) {
  $report = array('source' => $source, 'checks' => $checks,
    'passed' => false, 'error' => get_class($ex).': '.$ex->getMessage());
}
echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n";
exit($report['passed'] ? 0 : 1);
