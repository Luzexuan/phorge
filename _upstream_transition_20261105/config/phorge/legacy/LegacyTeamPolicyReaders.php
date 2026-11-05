<?php

/**
 * Read existing ORGT rules after replacing the old application implementation.
 * No directory, project roles, UI, writes, or new rule creation is installed.
 * The new upstream project automatic capabilities remain upstream behavior.
 */
abstract class DeploymentLegacyTeamPolicyRule extends PhabricatorPolicyRule {
  private $scope = array();
  abstract protected function includeDescendants();

  public static function readScope(PhabricatorUser $viewer, $descendants) {
    if (!$viewer->getPHID()) { return array(); }
    $dao = new PhabricatorUser();
    $conn = $dao->establishConnection('w');
    $person = queryfx_one($conn,
      'SELECT * FROM %T WHERE phid = %s',
      $dao->getTableName(), $viewer->getPHID());
    $current = $person ? $dao->loadFromArray($person) : null;
    if (!$current || !$current->getPHID() || !$current->isUserActivated() ||
        $current->getIsSystemAgent() || $current->getIsMailingList()) {
      return array();
    }
    $teams = queryfx_all($conn,
      'SELECT phid, parentPHID, isArchived FROM %T', 'user_organizationteam');
    $teams = ipull($teams, null, 'phid');
    $members = queryfx_all($conn,
      'SELECT teamPHID FROM %T WHERE userPHID = %s',
      'user_organizationmember', $viewer->getPHID());
    $scope = array(); $parents = array(); $visited = array();
    foreach ($members as $member) {
      $team = idx($teams, $member['teamPHID']);
      if (!$team || $team['isArchived']) { continue; }
      $scope[$team['phid']] = true;
      if ($descendants && $team['parentPHID']) { $parents[] = $team['parentPHID']; }
    }
    for ($depth = 0; $parents; $depth++) {
      if ($depth >= 64) { throw new Exception('Legacy team hierarchy exceeds its safety limit.'); }
      $parents = array_values(array_diff(array_unique($parents), array_keys($visited)));
      if (!$parents) { break; }
      $next = array();
      foreach ($parents as $phid) {
        $team = idx($teams, $phid);
        if (!$team) { continue; }
        $visited[$phid] = true;
        if (!$team['isArchived']) { $scope[$phid] = true; }
        if ($team['parentPHID']) { $next[] = $team['parentPHID']; }
      }
      $parents = $next;
    }
    return $scope;
  }

  public function willApplyRules(PhabricatorUser $viewer, array $values, array $objects) {
    $this->scope = self::readScope($viewer, $this->includeDescendants());
  }
  public function applyRule(PhabricatorUser $viewer, $value, PhabricatorPolicyInterface $object) {
    if (!is_array($value)) { return false; }
    foreach ($value as $phid) {
      if (is_string($phid) && isset($this->scope[$phid])) { return true; }
    }
    return false;
  }
  public function shouldHideFromUI() { return true; }
  public function getValueControlType() { return self::CONTROL_TYPE_NONE; }
  public function getValueForStorage($value) {
    throw new InvalidArgumentException('历史团队规则只供读取；请使用新版本策略建立替代规则。');
  }
  public function getValueForDisplay(PhabricatorUser $viewer, $value) {
    $result = array();
    foreach (is_array($value) ? $value : array() as $phid) {
      $result[$phid] = pht('历史团队授权（只读）');
    }
    return $result;
  }
  public function ruleHasEffect($value) { return is_array($value) && (bool)$value; }
}

final class TeamOrganizationDirectPolicyRule extends DeploymentLegacyTeamPolicyRule {
  protected function includeDescendants() { return false; }
  public function getRuleDescription() { return pht('历史团队本级成员（只读）'); }
  public function getRuleOrder() { return 210; }
}
final class TeamOrganizationDescendantsPolicyRule extends DeploymentLegacyTeamPolicyRule {
  protected function includeDescendants() { return true; }
  public function getRuleDescription() { return pht('历史团队及下级成员（只读）'); }
  public function getRuleOrder() { return 211; }
}
