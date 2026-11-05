<?php

// Isolated UI regression test: php tests/project-hierarchy.php
// Exercise the deployed controllers/search/view using in-memory collaborators.
// These fixtures do not connect to a database or create application objects.
function id($value) { return $value; }
function pht($pattern, ...$args) { return vsprintf($pattern, $args); }
function array_fuse(array $values) { return array_combine($values, $values); }
function assert_instances_of(array $values, $class) {
  foreach ($values as $value) {
    if (!($value instanceof $class)) { throw new Exception('Invalid fixture.'); }
  }
}
function phutil_tag($name, array $attributes, $content) {
  $html = '<'.$name;
  foreach ($attributes as $key => $value) {
    $html .= ' '.$key.'="'.htmlspecialchars($value, ENT_QUOTES, 'UTF-8').'"';
  }
  return $html.'>'.htmlspecialchars($content, ENT_QUOTES, 'UTF-8').'</'.$name.'>';
}
function phutil_implode_html($separator, array $values) {
  return implode($separator, $values);
}

class HierarchyViewer {
  public function getPHID() { return 'PHID-USER-viewer'; }
  public function isLoggedIn() { return true; }
}
class AphrontRequest {
  private $key;
  private $data;
  private $post;
  public function __construct($key = null, array $data = array(), $post = false) {
    $this->key = $key;
    $this->data = $data;
    $this->post = $post;
  }
  public function getURIData($key) {
    if ($key !== 'queryKey') { throw new Exception('Unexpected URI key.'); }
    return $this->key;
  }
  public function getPassthroughRequestData() { return $this->data; }
  public function isFormPost() { return $this->post; }
}
class PhabricatorProjectController {
  public function delegateToController($controller) { return $controller; }
}
class PhabricatorApplicationSearchController {
  public $engine;
  public $queryKey;
  public function setSearchEngine($engine) {
    $this->engine = $engine;
    return $this;
  }
  public function setQueryKey($key) { $this->queryKey = $key; return $this; }
}
class PhabricatorSavedQuery {
  private $key;
  private $parameters = array();
  public function setQueryKey($key) { $this->key = $key; return $this; }
  public function getQueryKey() { return $this->key; }
  public function setParameter($key, $value) {
    $this->parameters[$key] = $value;
    return $this;
  }
  public function getParameter($key, $default = null) {
    return array_key_exists($key, $this->parameters)
      ? $this->parameters[$key] : $default;
  }
}
class PhabricatorApplicationSearchEngine {
  public $controller;
  private $viewer;
  public function setController($controller) {
    $this->controller = $controller;
    return $this;
  }
  public function setViewer($viewer) { $this->viewer = $viewer; return $this; }
  protected function requireViewer() { return $this->viewer; }
  protected function newSavedQuery() { return new PhabricatorSavedQuery(); }
}
class PhabricatorProjectStatus {
  const STATUS_ACTIVE = 'active';
  const STATUS_ARCHIVED = 'archived';
  const STATUS_ACTIVE_KEY = 'active';
}
class PhabricatorPolicyCapability { const CAN_VIEW = 'view'; }
class PhabricatorPolicyFilter {
  public static function hasCapability($viewer, $project, $capability) {
    return $project->visible;
  }
}
class AphrontView {
  private $viewer;
  public function setViewer($viewer) { $this->viewer = $viewer; return $this; }
  public function getUser() { return $this->viewer; }
}
class PHUIIconView {
  public $icon;
  public function setIcon($icon) { $this->icon = $icon; return $this; }
}
class PHUIObjectItemView {
  public $object;
  public $header;
  public $href;
  public $imageURI;
  public $attributes = array();
  public $icons = array();
  public $disabled = false;
  public function setObject($object) { $this->object = $object; return $this; }
  public function setHeader($header) { $this->header = $header; return $this; }
  public function setHref($href) { $this->href = $href; return $this; }
  public function setImageURI($uri) { $this->imageURI = $uri; return $this; }
  public function addAttribute($attribute) {
    $this->attributes[] = $attribute;
    return $this;
  }
  public function addIcon($icon, $name) {
    $this->icons[$icon] = $name;
    return $this;
  }
  public function setDisabled($disabled) {
    $this->disabled = $disabled;
    return $this;
  }
}
class PHUIObjectItemListView extends AphrontView {
  public $items = array();
  public $noDataString;
  public function setNoDataString($text) {
    $this->noDataString = $text;
    return $this;
  }
  public function addItem($item) { $this->items[] = $item; return $this; }
}
class PhabricatorApplicationSearchResultView {
  public $objectList;
  public $noDataString;
  public function setObjectList($list) { $this->objectList = $list; return $this; }
  public function setNoDataString($text) {
    $this->noDataString = $text;
    return $this;
  }
}
class PhabricatorProject {
  private $id;
  private $name;
  public $ancestors = array();
  public $hasSubprojects = false;
  public $milestone = false;
  public $visible = true;
  public $archived = false;
  public $member = false;
  public $watcher = false;
  public function __construct($id, $name) { $this->id = $id; $this->name = $name; }
  public function getID() { return $this->id; }
  public function getName() { return $this->name; }
  public function getDisplayIconIcon() { return 'fa-briefcase'; }
  public function getDisplayIconName() { return 'Project'; }
  public function getProfileImageURI() { return '/image/project.png'; }
  public function getProfileURI() { return '/project/profile/'.$this->id.'/'; }
  public function getHasSubprojects() { return $this->hasSubprojects; }
  public function getAncestorProjects() { return $this->ancestors; }
  public function supportsSubprojects() { return !$this->milestone; }
  public function getStatus() { return $this->archived ? 'archived' : 'active'; }
  public function isUserMember($phid) { return $this->member; }
  public function isUserWatcher($phid) { return $this->watcher; }
  public function newSubtypeObject() { return null; }
}

$overrides = dirname(__DIR__).'/config/phorge/overrides/';
$staging = getenv('TEAM_PROJECT_STAGING') === '1' ||
  in_array('--staging', $argv, true);
$view_overrides = $staging
  ? dirname(__DIR__).'/config/phorge/progress-staging/'
  : $overrides;
require $overrides.'PhabricatorProjectListController.php';
require $overrides.'PhabricatorProjectSearchEngine.php';
require $view_overrides.'PhabricatorProjectListView.php';

$checks = array();
function hierarchy_check($name, $condition) {
  global $checks;
  if (!$condition) { throw new Exception($name); }
  $checks[] = $name;
}
function hierarchy_render(array $projects, $browse = true, $path = true) {
  return id(new PhabricatorProjectListView())
    ->setViewer(new HierarchyViewer())
    ->setProjects($projects)
    ->setBrowseHierarchy($browse)
    ->setShowHierarchyPath($path)
    ->renderList();
}
function hierarchy_text($item) {
  // Only rendered string attributes, never the model retained by setObject().
  return implode(' ', array_filter($item->attributes, 'is_string'));
}

$controller = new PhabricatorProjectListController();
foreach (array(
  array('default entry', new AphrontRequest()),
  array('forward cursor', new AphrontRequest(null, array('after' => '12'))),
  array('backward cursor', new AphrontRequest(null, array('before' => '21'))),
  array('UI flags', new AphrontRequest(null, array('nux' => '1', 'overheated' => '1'))),
) as $fixture) {
  $response = $controller->handleRequest($fixture[1]);
  hierarchy_check($fixture[0].' selects hierarchy regardless of old pinned query',
    $response->queryKey === 'hierarchy' &&
    $response->engine instanceof PhabricatorProjectSearchEngine &&
    $response->engine->controller === $controller);
}
foreach (array('all', 'joined', 'watching', 'hierarchy', 'advanced', 'saved-query-key') as $key) {
  hierarchy_check('explicit query is retained: '.$key,
    $controller->handleRequest(new AphrontRequest($key))->queryKey === $key);
}
hierarchy_check('custom search parameters retain normal search handling',
  $controller->handleRequest(new AphrontRequest(null,
    array('query' => 'robot', 'after' => '12')))->queryKey === null);
hierarchy_check('custom parent filter retains normal search handling',
  $controller->handleRequest(new AphrontRequest(null,
    array('parentPHIDs' => array('PHID-PROJ-parent'))))->queryKey === null);
hierarchy_check('form POST is not redirected to the default directory',
  $controller->handleRequest(new AphrontRequest(null, array(), true))->queryKey === null);

$engine = id(new PhabricatorProjectSearchEngine())->setViewer(new HierarchyViewer());
$builtin = $engine->buildSavedQueryFromBuiltin('hierarchy');
hierarchy_check('hierarchy query paginates only roots',
  $builtin->getQueryKey() === 'hierarchy' && $builtin->getParameter('isRoot') === true);
hierarchy_check('hierarchy excludes milestones at root and includes archived roots',
  $builtin->getParameter('isMilestone') === false &&
  $builtin->getParameter('status') === 'all');
hierarchy_check('hierarchy uses the supported stable name order',
  $builtin->getParameter('order') === 'name');
hierarchy_check('explicit all query still includes descendants',
  $engine->buildSavedQueryFromBuiltin('all')->getParameter('isRoot') === null);

$root = new PhabricatorProject(12, 'Root project');
$root->hasSubprojects = true;
$child = new PhabricatorProject(21, 'Child project');
$child->ancestors = array($root);
$child->hasSubprojects = true;
$leaf = new PhabricatorProject(45, 'Leaf project');
$leaf->ancestors = array($child, $root);
$milestone = new PhabricatorProject(50, 'Milestone');
$milestone->milestone = true;
$milestone->ancestors = array($child, $root);
$list = hierarchy_render(array($root, $child, $leaf, $milestone));
hierarchy_check('root and nested parents open their own child directories',
  $list->items[0]->href === '/project/subprojects/12/' &&
  $list->items[1]->href === '/project/subprojects/21/');
hierarchy_check('leaf and milestone titles retain project destinations',
  $list->items[2]->href === '/project/view/45/' &&
  $list->items[3]->href === '/project/view/50/');
hierarchy_check('root is explicitly identified without a synthetic parent',
  strpos(hierarchy_text($list->items[0]), '顶级项目') !== false);
$leaf_text = hierarchy_text($list->items[2]);
hierarchy_check('deep result path orders root before parent with directory links',
  strpos($leaf_text, '/project/subprojects/12/') <
    strpos($leaf_text, '/project/subprojects/21/') &&
  strpos($leaf_text, 'Root project</a> / <a') !== false &&
  strpos($leaf_text, 'Child project</a>') !== false);
hierarchy_check('parent directory preserves a separate project overview link',
  strpos(hierarchy_text($list->items[0]), '/project/profile/12/') !== false);
hierarchy_check('leaf offers its empty child directory for further creation',
  strpos($leaf_text, '/project/subprojects/45/') !== false);
hierarchy_check('milestone offers no unsupported child directory',
  strpos(hierarchy_text($list->items[3]), '/project/subprojects/50/') === false &&
  strpos(hierarchy_text($list->items[3]), '浏览子项目') === false);
hierarchy_check('flat search title still opens the project',
  hierarchy_render(array($root), false)->items[0]->href === '/project/view/12/');

$child->visible = false;
$restricted = hierarchy_render(array($leaf))->items[0];
hierarchy_check('inaccessible ancestor name and link never enter rendered path',
  strpos(hierarchy_text($restricted), 'Child project') === false &&
  strpos(hierarchy_text($restricted), '/project/subprojects/21/') === false &&
  strpos(hierarchy_text($restricted), '受限父项目') !== false);
$child->visible = true;
$root->archived = true;
$archived = hierarchy_render(array($root))->items[0];
hierarchy_check('archived root remains linked so descendants are reachable',
  $archived->disabled && $archived->href === '/project/subprojects/12/' &&
  isset($archived->icons['fa-ban']));
hierarchy_check('empty directory retains a useful empty state',
  !hierarchy_render(array())->items &&
  hierarchy_render(array())->noDataString === 'No projects found.');
$custom_empty = id(new PhabricatorProjectListView())
  ->setViewer(new HierarchyViewer())->setProjects(array())
  ->setNoDataString('没有可查看的子项目。')->renderList();
hierarchy_check('caller-specific empty message is retained',
  $custom_empty->noDataString === '没有可查看的子项目。');

$render = new ReflectionMethod('PhabricatorProjectSearchEngine', 'renderResultList');
$render->setAccessible(true);
$result = $render->invoke($engine, array($root), $builtin, array());
hierarchy_check('search engine wires hierarchy results to directory browsing',
  $result->objectList->items[0]->href === '/project/subprojects/12/');
$all = $engine->buildSavedQueryFromBuiltin('all');
$result = $render->invoke($engine, array($child), $all, array());
hierarchy_check('search results preserve project links and show ancestor path',
  $result->objectList->items[0]->href === '/project/view/21/' &&
  strpos(hierarchy_text($result->objectList->items[0]), 'Root project') !== false);

echo json_encode(array('passed' => count($checks), 'checks' => $checks),
  JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)."\n";
