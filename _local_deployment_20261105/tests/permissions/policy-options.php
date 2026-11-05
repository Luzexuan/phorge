<?php

/** Business-policy chooser regressions; never execute against production. */
$root = getenv('TEAM_PHORGE_ROOT') ?: '/opt/phorge/phorge';
require_once $root.'/scripts/__init_script__.php';
if (PhabricatorEnv::getEnvConfig('storage.default-namespace') !==
    'project_regression_base' ||
    !preg_match('/^team-project-regression-[a-f0-9]{8}-db$/D',
      PhabricatorEnv::getEnvConfig('mysql.host'))) {
  throw new Exception('Policy chooser regressions require the isolated test installation.');
}

final class TeamPolicyOptionsTestCase extends PhutilTestCase {

  public function testProjectChooserKeepsBusinessRules() {
    $rules = $this->rulesFor(new PhabricatorProject());
    $this->assertKeys($rules, array(
      'PhabricatorUsersPolicyRule', 'PhabricatorAdministratorsPolicyRule',
      'PhabricatorProjectsPolicyRule', 'PhabricatorProjectsAllPolicyRule',
      'TeamOrganizationDirectPolicyRule', 'TeamOrganizationDescendantsPolicyRule',
      'PhabricatorProjectMembersPolicyRule',
    ));
    $this->assertFalse(isset($rules['ManiphestTaskAuthorPolicyRule']));
    $this->assertFalse(isset($rules['TeamOrganizationMembersPolicyRule']));
    if (class_exists('TeamPrivateProjectPolicyRule')) {
      $this->assertTrue(isset($rules['TeamPrivateProjectPolicyRule']));
    }
  }

  public function testTaskChooserKeepsCreatorAndSubscribers() {
    $rules = $this->rulesFor(new ManiphestTask());
    $this->assertKeys($rules, array(
      'PhabricatorUsersPolicyRule', 'PhabricatorAdministratorsPolicyRule',
      'PhabricatorProjectsPolicyRule', 'PhabricatorProjectsAllPolicyRule',
      'TeamOrganizationDirectPolicyRule', 'TeamOrganizationDescendantsPolicyRule',
      'ManiphestTaskAuthorPolicyRule',
      'PhabricatorSubscriptionsSubscribersPolicyRule',
    ));
    $this->assertFalse(isset($rules['PhabricatorProjectMembersPolicyRule']));
    if (class_exists('TeamPrivateTaskPolicyRule')) {
      $this->assertTrue(isset($rules['TeamPrivateTaskPolicyRule']));
    }
  }

  public function testTeamChooserKeepsOnlyItsOwnObjectRule() {
    $rules = $this->rulesFor(new TeamOrganizationTeam());
    $this->assertKeys($rules, array(
      'PhabricatorUsersPolicyRule', 'PhabricatorAdministratorsPolicyRule',
      'PhabricatorProjectsPolicyRule', 'PhabricatorProjectsAllPolicyRule',
      'TeamOrganizationDirectPolicyRule', 'TeamOrganizationDescendantsPolicyRule',
      'TeamOrganizationMembersPolicyRule',
    ));
    $this->assertFalse(isset($rules['PhabricatorProjectMembersPolicyRule']));
    $this->assertFalse(isset($rules['ManiphestTaskAuthorPolicyRule']));
    $this->assertFalse(isset($rules['PhabricatorSubscriptionsSubscribersPolicyRule']));
  }

  public function testLegacyDetectionDoesNotRewriteMixedRules() {
    foreach (array('PhabricatorLunarPhasePolicyRule',
                   'PhabricatorLegalpadSignaturePolicyRule') as $retired) {
      $value = $retired === 'PhabricatorLunarPhasePolicyRule'
        ? 'waning' : array('PHID-LEGD-history');
      $rules = array(
        array('action' => 'allow', 'rule' => 'PhabricatorUsersPolicyRule',
          'value' => array('PHID-USER-owner')),
        array('action' => 'deny', 'rule' => $retired, 'value' => $value),
        array('action' => 'allow', 'rule' => 'PhabricatorAdministratorsPolicyRule',
          'value' => null),
      );
      $policy = id(new PhabricatorPolicy())->setRules($rules)
        ->setDefaultAction('deny');
      $this->assertTrue($this->invoke('hasRetiredRules', array($policy)));
      $this->assertEqual($rules, $policy->getRules());
      $this->assertEqual('deny', $policy->getDefaultAction());
      $this->assertTrue(class_exists($retired));
    }
    $policy = id(new PhabricatorPolicy())->setRules(array(array(
      'action' => 'allow', 'rule' => 'PhabricatorUsersPolicyRule',
      'value' => array('PHID-USER-owner'))))->setDefaultAction('allow');
    $this->assertFalse($this->invoke('hasRetiredRules', array($policy)));
    $this->assertEqual('allow', $policy->getDefaultAction());
    $project_rules = $this->rulesFor(new PhabricatorProject());
    foreach (array('PhorgeGlobalPolicyRule', 'ManiphestTaskAuthorPolicyRule') as $unavailable) {
      $policy = id(new PhabricatorPolicy())->setRules(array(array(
        'action' => 'deny', 'rule' => $unavailable, 'value' => 'users')))
        ->setDefaultAction('allow');
      $before = $policy->getRules();
      $this->assertTrue($this->invoke('hasUnavailableRules', array($policy, $project_rules)));
      $this->assertEqual($before, $policy->getRules());
    }
  }

  public function testReplacementURIKeepsOnlyLocalContextAndCapability() {
    foreach (array(
      array('objectPHID', 'PHID-PROJ-source', 'object'),
      array('objectType', 'TASK', 'type'),
      array('templateType', 'PROJ', 'template'),
    ) as $case) {
      $request = id(new AphrontRequest('policy-test.invalid', '/untrusted/'))
        ->setURIMap(array($case[0] => $case[1], 'phid' => 'PHID-PLCY-old'))
        ->setRequestData(array('capability' => 'view',
          'next' => 'https://outside.invalid/', 'phid' => 'PHID-PLCY-forged'));
      $uri = $this->invoke('newReplacementURI', array($request));
      $this->assertTrue($uri instanceof PhutilURI);
      $this->assertEqual('/policy/edit/'.$case[2].'/'.$case[1].
        '/select_custom/', $uri->getPath());
      $this->assertEqual(array('capability' => 'view'), $uri->getQueryParams());
      $this->assertEqual('', $uri->getDomain());
      $request = id(new AphrontRequest('policy-test.invalid', '/organization/project-policy/object/source/'))
        ->setURIMap(array($case[0] => $case[1]))
        ->setRequestData(array('capability' => 'view'));
      $uri = $this->invoke('newReplacementURI', array($request));
      $this->assertEqual('/organization/project-policy/'.$case[2].'/'.$case[1].
        '/select_custom/', $uri->getPath());
      $this->assertEqual(array('capability' => 'view'), $uri->getQueryParams());
    }
  }

  public function testOtherApplicationRulesRemainObjectScoped() {
    $project = $this->rulesFor(new PhabricatorProject());
    $event = $this->rulesFor(new PhabricatorCalendarEvent());
    foreach (array('PhabricatorCalendarEventHostPolicyRule',
                   'PhabricatorCalendarEventInviteesPolicyRule') as $key) {
      $this->assertFalse(isset($project[$key]));
      $this->assertTrue(isset($event[$key]));
    }
    $this->assertTrue(isset($project['PhabricatorAdministratorsPolicyRule']));
  }

  private function rulesFor(PhabricatorPolicyInterface $object) {
    $all = id(new PhutilClassMapQuery())
      ->setAncestorClass('PhabricatorPolicyRule')->execute();
    $rules = $this->invoke('selectBusinessRules', array($all, $object));
    foreach (array('PhabricatorLunarPhasePolicyRule',
                   'PhabricatorLegalpadSignaturePolicyRule',
                   'PhorgeGlobalPolicyRule') as $key) {
      $this->assertFalse(isset($rules[$key]), $key);
    }
    $last_order = -PHP_INT_MAX;
    foreach ($rules as $rule) {
      $this->assertTrue($rule->canApplyToObject($object));
      $this->assertFalse($rule->shouldHideFromUI());
      $this->assertTrue($last_order <= $rule->getRuleOrder());
      $last_order = $rule->getRuleOrder();
    }
    return $rules;
  }

  private function assertKeys(array $rules, array $keys) {
    foreach ($keys as $key) {
      $this->assertTrue(isset($rules[$key]), $key);
    }
  }

  private function invoke($method, array $arguments) {
    $reflection = new ReflectionMethod('PhabricatorPolicyEditController', $method);
    $reflection->setAccessible(true);
    return $reflection->invokeArgs(null, $arguments);
  }
}

$case = id(new TeamPolicyOptionsTestCase())->setEnableCoverage(false)
  ->setWorkingCopy(ArcanistWorkingCopyIdentity::newFromPath($root));
$results = $case->run();
$renderer = new ArcanistUnitConsoleRenderer();
$passed = count($results) === 6;
foreach ($results as $result) {
  echo $renderer->renderUnitResult($result);
  $passed = $passed && $result->getResult() === ArcanistUnitTestResult::RESULT_PASS;
}
exit($passed ? 0 : 1);
