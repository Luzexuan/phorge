<?php

/** Policy wording and rendering regressions only run in the isolated test DB. */
$root = getenv('TEAM_PHORGE_ROOT') ?: '/opt/phorge/phorge';
require_once $root.'/scripts/__init_script__.php';
if (PhabricatorEnv::getEnvConfig('storage.default-namespace') !==
    'project_regression_base') {
  throw new Exception('Policy display regressions require the isolated test installation.');
}

final class TeamPolicyDisplayTestCase extends PhabricatorTestCase {
  protected function getPhabricatorTestCaseConfiguration() {
    return array(self::PHABRICATOR_TESTCONFIG_BUILD_STORAGE_FIXTURES => true);
  }

  public function testMoonChooserKeepsNativeRuleAndStoredValues() {
    $locale = PhabricatorEnv::beginScopedLocale('zh_CN');
    $rule = new PhabricatorLunarPhasePolicyRule();
    $this->assertTrue(strpos($rule->getRuleDescription(), '月相') !== false);
    $this->assertTrue(strpos($rule->getRuleDescription(), '日期') !== false);
    $this->assertFalse(strpos($rule->getRuleDescription(), '当月亮') !== false);
    $template = $rule->getValueControlTemplate();
    $this->assertEqual(array(
      'full' => '满月', 'new' => '新月',
      'waxing' => '月盈（渐圆）', 'waning' => '月亏（渐缺）',
    ), $template['options']);
    $this->assertEqual(PhabricatorPolicyRule::CONTROL_TYPE_SELECT,
      $rule->getValueControlType());
    foreach (array_keys($template['options']) as $value) {
      $this->assertEqual($value, $rule->getValueForStorage($value));
    }
  }

  public function testLunarEvaluationStillDependsOnTimeRatherThanIdentity() {
    $ordinary = $this->generateNewTestUser();
    $admin = $this->generateNewTestUser()->setIsAdmin(1);
    $object = new PhabricatorProject();
    $rule = new PhabricatorLunarPhasePolicyRule();
    $epoch = 934354800;
    $period = 2551442.8768992;
    foreach (array(
      array($epoch, 'new', true),
      array($epoch, 'full', false),
      array($epoch + (int)round($period / 2), 'full', true),
      array($epoch + (int)round($period / 2), 'new', false),
      array($epoch + (int)round($period / 4), 'waxing', true),
      array($epoch + (int)round($period / 4), 'waning', false),
      array($epoch + (int)round($period * 3 / 4), 'waning', true),
      array($epoch + (int)round($period * 3 / 4), 'waxing', false),
    ) as $case) {
      $time = PhabricatorTime::pushTime($case[0], 'UTC');
      try {
        foreach (array($ordinary, $admin, new PhabricatorUser()) as $viewer) {
          $this->assertEqual($case[2],
            $rule->applyRule($viewer, $case[1], $object));
        }
      } finally {
        unset($time);
      }
    }
  }

  public function testSavedPolicyDetailsTranslateActionsAndLunarValues() {
    $locale = PhabricatorEnv::beginScopedLocale('zh_CN');
    $viewer = $this->generateNewTestUser();
    $rules = array();
    foreach (array('full', 'new', 'waxing', 'waning') as $index => $value) {
      $rules[] = array('action' => $index % 2 ? 'deny' : 'allow',
        'rule' => PhabricatorLunarPhasePolicyRule::class, 'value' => $value);
    }
    $policy = id(new PhabricatorPolicy())->setRules($rules)
      ->setDefaultAction('deny')->save();
    $html = $this->renderPolicy($viewer, $policy);
    $text = html_entity_decode(strip_tags($html), ENT_QUOTES, 'UTF-8');
    foreach (array('月相条件', '满月', '新月', '月盈', '月亏', '允许', '拒绝') as $label) {
      $this->assertTrue(strpos($text, $label) !== false, $label);
    }
    foreach (array('当月亮', 'Allow', 'Deny', 'waxing', 'waning') as $obsolete) {
      $this->assertFalse(strpos($text, $obsolete) !== false, $obsolete);
    }
    $fresh = id(new PhabricatorPolicy())->load($policy->getID());
    $this->assertEqual($rules, $fresh->getRules());
    $this->assertEqual('deny', $fresh->getDefaultAction());
  }

  public function testSelectedProjectRulesKeepUnionAndIntersection() {
    $locale = PhabricatorEnv::beginScopedLocale('zh_CN');
    $owner = $this->generateNewTestUser();
    $only_first = $this->generateNewTestUser();
    $both = $this->generateNewTestUser();
    $outside = $this->generateNewTestUser();
    $first = $this->project($owner, array($only_first, $both));
    $second = $this->project($owner, array($both));
    $values = array($first->getPHID(), $second->getPHID());
    $any = new PhabricatorProjectsPolicyRule();
    $all = new PhabricatorProjectsAllPolicyRule();
    $administrators = new PhabricatorAdministratorsPolicyRule();
    $this->assertEqual('站点管理员', $administrators->getRuleDescription());
    $this->assertEqual('站点管理员', PhabricatorPolicyQuery::getGlobalPolicy(
      PhabricatorPolicies::POLICY_ADMIN)->getName());
    $this->assertEqual('本项目成员',
      id(new PhabricatorProjectMembersPolicyRule())->getRuleDescription());
    $this->assertEqual('本任务创建者',
      id(new ManiphestTaskAuthorPolicyRule())->getRuleDescription());
    $this->assertFalse((bool)$administrators->applyRule($owner, null, $first));
    $site_admin = clone $owner;
    $site_admin->setIsAdmin(1);
    $this->assertTrue((bool)$administrators->applyRule($site_admin, null, $first));
    $this->assertTrue(strpos($any->getRuleDescription(), '所选任一') !== false);
    $this->assertTrue(strpos($all->getRuleDescription(), '所选全部') !== false);
    foreach (array(array($only_first, true, false), array($both, true, true),
      array($outside, false, false)) as $case) {
      $any->willApplyRules($case[0], array($values), array($first));
      $all->willApplyRules($case[0], array($values), array($first));
      $this->assertEqual($case[1], $any->applyRule($case[0], $values, $first));
      $this->assertEqual($case[2], $all->applyRule($case[0], $values, $first));
    }
  }

  public function testEnglishLocaleRetainsNativeMeanings() {
    $locale = PhabricatorEnv::beginScopedLocale('en_US');
    $viewer = $this->generateNewTestUser();
    $rule = new PhabricatorLunarPhasePolicyRule();
    $this->assertEqual('when the moon', $rule->getRuleDescription());
    $this->assertEqual('is new', $rule->getValueControlTemplate()['options']['new']);
    $this->assertEqual('administrators',
      id(new PhabricatorAdministratorsPolicyRule())->getRuleDescription());
    $this->assertEqual('members of project',
      id(new PhabricatorProjectMembersPolicyRule())->getRuleDescription());
    $this->assertEqual('task author',
      id(new ManiphestTaskAuthorPolicyRule())->getRuleDescription());
    $policy = id(new PhabricatorPolicy())->setRules(array(array(
      'action' => 'allow', 'rule' => PhabricatorLunarPhasePolicyRule::class,
      'value' => 'new')))->setDefaultAction('deny');
    $html = $this->renderPolicy($viewer, $policy);
    $this->assertTrue(strpos($html, 'Allow when the moon') !== false);
    $this->assertTrue(strpos($html, 'is new') !== false);
  }

  public function testUnknownPhaseRemainsEscapedAndDoesNotMatch() {
    $locale = PhabricatorEnv::beginScopedLocale('zh_CN');
    $viewer = $this->generateNewTestUser();
    $raw = '<unknown-moon-phase>';
    $rules = array(array('action' => 'allow',
      'rule' => PhabricatorLunarPhasePolicyRule::class, 'value' => $raw));
    $policy = id(new PhabricatorPolicy())->setRules($rules)->setDefaultAction('deny');
    $html = $this->renderPolicy($viewer, $policy);
    $this->assertTrue(strpos($html, '&lt;unknown-moon-phase&gt;') !== false);
    $this->assertFalse(strpos($html, $raw) !== false);
    $this->assertFalse(id(new PhabricatorLunarPhasePolicyRule())->applyRule(
      $viewer, $raw, new PhabricatorProject()));
    $this->assertEqual($rules, $policy->getRules());
  }

  private function renderPolicy($viewer, $policy) {
    return (string)hsprintf('%s', id(new PhabricatorPolicyRulesView())
      ->setViewer($viewer)->setPolicy($policy));
  }

  private function project($owner, array $members) {
    $result = id(new ConduitCall('project.edit', array('transactions' => array(
      array('type' => 'name', 'value' => 'Policy Display '.Filesystem::readRandomCharacters(12)),
      array('type' => 'members.add', 'value' => array_values(mpull($members, 'getPHID'))),
    ))))->setUser($owner)->execute();
    return id(new PhabricatorProjectQuery())
      ->setViewer(PhabricatorUser::getOmnipotentUser())
      ->withPHIDs(array($result['object']['phid']))->executeOne();
  }
}

$case = id(new TeamPolicyDisplayTestCase())->setEnableCoverage(false)
  ->setWorkingCopy(ArcanistWorkingCopyIdentity::newFromPath($root));
$case->willRunTestCases(array($case));
try { $results = $case->run(); } finally { $case->didRunTestCases(array($case)); }
$renderer = new ArcanistUnitConsoleRenderer();
$passed = count($results) === 6;
foreach ($results as $result) {
  echo $renderer->renderUnitResult($result);
  $passed = $passed && $result->getResult() === ArcanistUnitTestResult::RESULT_PASS;
}
exit($passed ? 0 : 1);
