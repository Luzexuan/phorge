G04 deployment override: PhabricatorFileQuery.php

Base: Phorge commit e5141c768b37eeb9a114198cc8df9664173be638
Original path: src/applications/files/query/PhabricatorFileQuery.php
Original SHA256: 0888121a7a69aba5250b10a38112cccc5f8e3fc3bf5f347162458fd8e03b68b8
Reviewable change: file-profile-ancestry.patch

Mount this complete file read-only over its original runtime path in phorge,
phorge-migrate and phorge-daemon. The vendor checkout remains unchanged.
Re-review/rebase this patch before changing the pinned Phorge revision.

Reason: native file queries skip ancestry for profile images, which exposes a
public-profile derivative of a confidential source through Conduit file.download,
file.search, and /F pages despite the deployment's raw-URL policy guard.

The change checks transform relations in one batch for non-builtin profile
images. Only profiles with a real original file lose the early visibility
optimization. Their normal native ancestry lookup then enforces original-file
visibility across all callers. Standalone public profiles, genuine builtin
resources and PHID_VOID builtin markers retain the native shortcut.

Regression commands:
  scripts/compose.sh exec -T phorge php < scripts/test-file-policy.php > state/acceptance/file-policy-native.json
  python3 scripts/test-file-policy-http.py

Project grant management (2026-10-27, deployed)
-------------------------------------------------------------------------
Development sources are organization-staging/TeamOrganizationPolicy.php and
organization-staging/TeamOrganizationApplication.php. The project overview
and native edit form expose a permissions entry at
/organization/project/<id>/permissions/. Both accepted extension files have
been atomically promoted to their canonical paths, and web, daemon, maintenance
have been force-recreated. No SQL migration was required.
An active approved user with current project VIEW and EDIT may manage grants;
site administrator status is not required. Global organization membership
management remains administrator-only.

TeamProjectAccessService operates on native VIEW/EDIT/JOIN policies. Add is the
default: prepend new allow rules for selected people, direct teams, or teams
including descendants, preserving the old rule order and default action. This
forms a union with the old policy, including individually invited cross-team
participants. Replace rebuilds only the selected capability's explicit rules
with default deny. Revoke removes selected user/team entries from allow rules;
remove-rule removes one entire allow rule, never a deny rule. Remaining grant
sources continue to apply. Native project-member VIEW and editor JOIN remain,
and these operations never edit project membership or global team assignments.

The existing team boundary is an additional AND constraint, not the ordinary
team grant entry. It is retained unless the manager explicitly selects
clearBoundary. Native milestone projects must be managed through their parent;
ordinary subprojects retain required parent visibility and tasks retain their
own ACLs. Named policies are not silently flattened: add/revoke/remove-rule
reject with a link back to native advanced management; explicit replace may
bind a new policy without modifying the named policy or any other object.

Mutations take the primary project row lock, reload the actor and project,
verify a state token over all three policies and the boundary, and use native
policy transactions inside the same outer transaction. Native self-lockout
protection remains. New subjects must be visible and active; hidden or archived
historical allow references may be removed. Global public capability limits
are preserved when composing a legacy global policy. Identical leading allow
grants are not duplicated; nonexistent revocations are no-ops. Rule growth is
bounded, while oversized legacy policies remain reducible. Existing policy
objects are immutable: an effective policy change creates a new policy so
shared objects and history remain intact. UI rule values use each native
rule's viewer-aware display helper;
hidden named policies are not expanded. POST requires CSRF and stale forms must
be reloaded.

The native project history retains operation metadata:
  team.project.access.operation = add / replace / revoke / remove-rule
  team.project.access.capability = view / edit / join
  team.project.access.clear-boundary = true (only on an explicit clear)
No schema or migration is added, and deployment does not rewrite existing
policies, team assignments, or boundaries. The existing 28-source runtime
manifest remains unchanged. Future deployments must atomically promote both
accepted extension files and force-recreate web, daemon, maintenance; verify
actual bind hashes.
New native coverage is tests/permissions/project-access.php. Browser coverage
is tests/browser/project-access-native.mjs via
scripts/test-project-access-ui-isolated.py.

Release verification passed: 40 native groups (4 existing project permissions,
9 node/comment, 15 organization, 12 grant operations); 451 browser checks (160
grant management, 125 organization, 166 node/comment); 102 public checks; and
24 reviewed screenshots. The three deployed runtimes each match all 28 accepted
source hashes (84 checks). Each runtime preserves all 28 real user/project
access combinations: 20 visible and 12 eligible to publish or manage grants;
36 viewer-specific native-policy reads also passed in each runtime.
Before, pre-deployment, and after snapshots preserve 7 projects, 4 users,
9 tasks, and the raw transaction/membership digests. Organization tables remain
0 teams, 0 assignments, 0 audit rows, and 1 lock row. The exact isolated test
containers, network, and temporary credentials were removed; all 102 evidence
artifacts remain unchanged. Final native evidence:
  state/acceptance/team-project-regression-87659c4c/report-native-recheck.json
Release summary:
  state/acceptance/project-access-union-release.json
See DEPLOYMENT.md for the full release procedure and verification scope.

Organization teams (2026-10-27, deployed)
-------------------------------------------------------------------------
Runtime manifest: organization-runtime.json. Development sources are in
config/phorge/organization-staging/. The shared source resolver mounts the
organization extensions and SQL in web, daemon, migrate, maintenance, and
isolated tests. No vendor checkout is modified. Accepted staging files have
been promoted to canonical production paths; native migration exited 0 and all
three runtime recreations are complete. All 102 public gateway checks passed.

Organization teams are independent Phorge objects (PHID-ORGT). Team hierarchy
does not reuse projects or aggregate their memberships. A person may belong
to several teams. Each level has independent directory VIEW and member-roster
policies; both default to direct members of that team. Parent visibility is
not an extended requirement. Viewer-aware queries and handles hide private
team names, ancestors, and rosters. Effective administrators can manage teams;
all mutations reload the actor from the primary database, serialize on one
database lock row, reject stale versions/member sets, and audit atomically.

Entry points: 团队架构 at /organization/, 账户维护 > 用户与白名单 > 分配团队,
and a read-only team-membership field on People profiles. Membership editing
is administrator-only, never a user self-edit field. Registrations and new
approvals receive no default team or project. Initial deployment creates no
business teams, member assignments, or synthetic production objects. The old
registration SQLite org_units/org_unit_id placeholders are not authorization
sources. Personal reporting-manager and position fields remain unimplemented.

Native custom policies can select direct team members or members of a team
and its descendants for project VIEW/EDIT/JOIN. Ordinary custom policies keep
native automatic project-member VIEW and editor JOIN behavior. The optional
project team boundary is an additional ExtendedPolicy check on all three
capabilities, including those automatic grants; empty means no extra boundary.
Native milestone projects use their parent's boundary. Active administrators
pass the boundary guard but must still satisfy the original project ACL.
Authorized project editors can deliberately change or remove the boundary;
this is not mandatory site-wide tenant isolation. Task ACLs remain independent
and are not copied from team membership, project tags, or the project boundary.

Archive preserves historical membership and permits removals, but rejects
new member additions until restoration. Archived teams never grant team-scope
access. Archiving a parent does not archive its children: an active child's
members can still match an active ancestor's descendant rule, even through
an archived intermediate team. Disabled/unapproved users retain stored
relationships if needed but cannot obtain grants through them.

Native patch: teamorganization:20261027.organization.sql
Dependency: phabricator:db.user
Runtime SQL: resources/sql/team-organization/20261027.organization.sql
Tables, all in the existing user schema:
  user_organizationteam, user_organizationmember,
  user_organizationaudit, user_organizationlock
Only the lock table is seeded (one row); business tables start empty.
Concrete DAO schemata are auto-discovered, but missing tables must be created
by this registered patch: storage adjust alone does not create them.

Migration probes use an isolated phorge_probe account with the exact schema
grants emitted for production by generate-core.py; root fixture credentials
are separate. Verify new storage, upgrade, and repeated upgrade, including
unchanged organization schema/data on repetition. Read-only before/after
snapshots use state/acceptance/team-organization/snapshot.php: existing project,
user, task, transaction and membership-edge digests are separate from the four
new tables. Only counts and aggregate hashes are emitted, never row contents.

Release order: capture read-only data snapshots and save the exact deployed
code/configuration. Run scripts/backup.py while canonical files still contain
the old version: its finally block starts the old containers, and a stop/start
can resolve file binds again, so promoting files first risks mixed versions.
Add deployed-code.tar.gz to that full backup directory with the six previously
deployed source/configuration files. Record in manifest.json that restoration
must apply this overlay after restoring the private deployment archive. Run
scripts/restore-check.py against the complete backup directory, including this
overlay. The backup must contain its own exact old-version recovery material.
Only then atomically promote the six accepted runtime source/SQL files, run
the native migration, and force-recreate web, daemon and maintenance:
  scripts/compose.sh run --rm --no-deps --entrypoint php phorge-migrate /opt/phorge/phorge/bin/storage upgrade --force --allow-surplus
  scripts/compose.sh up -d --no-deps --no-build --force-recreate phorge phorge-daemon maintenance
Verify actual mounted hashes after recreating atomic file binds.
Isolated development checks:
  python3 scripts/test-project-isolated.py --staging --keep
  python3 scripts/test-project-organization-ui-isolated.py --staging state/acceptance/RUN/report.json
Keep the exact report runtime until browser verification, then remove only its
containers/network/private credentials and retain evidence.

Release verification: 28 native groups (4 existing policy, 9 node/comment,
15 organization), 125 organization browser checks, 166 node browser checks,
and 51 navigation/hierarchy logic checks passed. All 18 screenshots were
reviewed. Each of the three runtimes matches all 28 baseline source hashes
(84 matches total); 21 resident services are healthy and 2 init jobs exited 0.
Each runtime returns the same ACL results for all 28 user/project pairs:
20 visible, 12 allowed to publish. Before/predeploy/after digests match for
7 projects, 4 users, 9 tasks, transactions and membership edges. Organization
tables contain 0 teams, 0 memberships, 0 audit entries and 1 lock seed row.
The isolated runtime is removed; cleanup passed and 116 evidence artifacts
were retained under state/acceptance/team-project-regression-2b574a7a/.
Full backup backups/20261026T171539Z includes deployed-code.tar.gz; its manifest
records restoration of the six exact old source/configuration files after the
private archive. Isolated restore verification passed for 518 SQL tables,
archive readability and hashes; this is not a full business disaster-recovery
exercise. All 102 final public gateway checks passed.
Release summary: state/acceptance/team-organization-release.json.

Do not blindly restore pre-organization code after policies or boundaries are
stored. Team rule classes/readers and the project boundary guard must remain
available: missing rules can break access, while removing the boundary guard
can reopen access for existing project members. Prefer a forward fix or an
explicitly audited policy migration. Do not restore old SQL over later user
assignments, project records, or other business changes for a code rollback.

Project membership and hierarchy overrides (2026-10-26, deployed)
-------------------------------------------------------------------------
Base revision and original file hashes: project-hierarchy-overrides.json.
Reviewable changes:
  subproject-permissions.patch
  project-hierarchy-browser.patch
  project-parent-navigation.patch

The first child no longer copies parent members. Ordinary children use their
own edit policy instead of granting parent editors automatic child edit/join
rights. Parent projects retain and can manage direct members; materialized
membership is the union of direct members and all descendant direct members.
The member page distinguishes direct membership from descendant membership.

The project landing page opens a root-only hierarchy, with visible immediate
children loaded one level at a time in name order. Explicit saved searches,
filters and API searches remain available and show ancestor context. Archived
roots remain navigable so active descendants are not hidden. Shared navigation
links back to the actual parent directory and works from search/bookmarks.

Existing semantics retained: viewing a child requires viewing its ancestors;
descendant members are visible members of ancestors; members can view their
own project and project editors can join; milestones inherit parent policies
and membership. Existing policies and child membership are not rewritten.

All 17 files mount read-only in phorge, phorge-daemon, phorge-migrate and the
maintenance runtime. scripts/generate-core.py reads the same manifest. No vendor
files or database schema change. Rebase these patches before updating Phorge.

Deployment status: APPLIED to phorge, phorge-daemon and maintenance after the
Docker access restriction was removed. PHP 8.3.35 in the application image ran
51 isolated logic checks. Four native database fixture cases and 46 browser
checks passed against a disposable MySQL/Gorge/Phorge installation. The actual
first-child form preserved all three selected policies, did not copy parent
members, and preserved the parent's membership. Desktop/mobile screenshots
were inspected. Temporary test containers, network and credentials were removed.

All 17 deployed files match the verified sources in each active PHP runtime.
The production preflight found no dormant edges in four existing parents.
Before/after snapshots confirm all 16 existing projects' persisted policies
and 45 direct/materialized member edges were unchanged. Public gateway and
service-health verification passed. Evidence: state/acceptance/project-hierarchy-release.json.

Before enabling the new membership logic on an existing installation, run:
  scripts/compose.sh exec -T phorge php < tests/permissions/audit-legacy-parent-members.php
This is read-only. Exit 2 means old direct member edges exist which are absent
from current effective membership. Do not activate the overrides until these
records have been reviewed and reconciled: otherwise they could become active
again. No automatic cleanup or broad membership rebuild is supplied.

Historical members copied into children cannot be reliably distinguished from
manual invitations and are not removed. Review those memberships separately.

Offline checks:
  python3 tests/project-overrides.py
  php tests/project-navigation.php
  php tests/project-hierarchy.php
Optional parser check:
  python3 tests/project-overrides.py --xhpast /path/to/xhpast

Native integration suite, only in a disposable test deployment with the
overrides mounted and permission to create Phorge storage-fixture schemas:
  php tests/permissions/subproject-permissions.php
TEAM_PHORGE_ROOT can override the default /opt/phorge/phorge installation path.
The fixture suite creates separate temporary schemas and rolls back its data;
do not grant the production SQL account broad schema creation privileges for it.

Reproducible isolated Docker setup (uses only locally available test images):
  python3 scripts/test-project-isolated.py --keep
  python3 scripts/test-project-ui-isolated.py state/acceptance/TEST-RUN/report.json
Without --keep the first command cleans up its containers and credentials.
With --keep, use the report's exact test container/network names to clean up
after browser verification. Never use production configuration or users here.

After the audit and integration/browser checks pass, recreate runtime services
using the updated Compose files (completed for this release):
  scripts/compose.sh up -d --no-deps --no-build phorge phorge-daemon maintenance
The next migration job also uses the same overrides. Verify root/child/grandchild
navigation, direct-URL return links, first/later child ACLs, and an unrelated
parent member before completing release acceptance. The current release passed
these tests; existing production data was checked read-only, with all creation
and authenticated browser operations confined to the disposable installation.

Rollback configuration and a project database snapshot are recorded in
state/acceptance/project-hierarchy-backup.json. The rollback overlay mounts the
pinned original project sources; the database snapshot is not needed for a
code-only rollback and must not be restored over subsequent user changes.

Project-node consolidation (2026-10-27, deployed)
-------------------------------------------------------------------------
This release merges manual update/milestone records into project nodes
(team:project-node), keeping work comments as discussion. New node status is
required: planned = 待开发, active, blocked, or done. It describes that node,
not the whole project. A done node never implies project completion of 100%.
The project percentage remains manually reported; blank retains its value.
Comments change neither the latest node state nor project completion.

Retain old progress/keynode/comment transaction classes and stored payloads.
Read old update/milestone filter aliases as the unified node history; old
entry IDs and links remain valid. Never infer a missing historical node state
from the legacy project-wide status projection. All new noncomment records,
including direct writes through legacy transaction editors, require a status;
nullable old payloads are supported only for reading. No database rewrite, native
milestone-project removal, or task permission change belongs to this release.
Both node and comment publication continue to require project CAN_EDIT.

Use the same four explicit record types for before/after release snapshots:
team:project-node, team:project-progress, team:project-keynode, and
team:project-comment. After any node is stored, rollback code must retain its
read handler/query support; old code which does not recognize the new type
will hide those entries. Do not restore old SQL for a code-only rollback.
Current entry points are 节点记录 and 发布节点. The public record types are
节点 and 工作评论. Historical release descriptions below retain their original
labels; the current semantics are defined in this section.

Validation passed: 13 native groups (4 existing permissions + 9 record groups),
166 browser assertions, 51 navigation/hierarchy assertions, and 102 public
checks. All 10 desktop/mobile screenshots were inspected. Six PHP sources were
atomically promoted, then web/daemon/maintenance were recreated. All 69 runtime
SHA256 values (23 files per role) match the tested baseline. Each role verified
20 visible project/user combinations: 12 publishable, 8 read-only, matching
project edit permission and the new node summary contract. All 21 resident
services are healthy; the two initialization services exited successfully.

Before/predeploy/after snapshots match for 7 projects, 4 users, 0 manual
records, and all project-edge digests. No production fixtures were created.
The disposable test installation and its temporary credentials were removed.
Release: state/acceptance/project-node-unification-release.json.
Native/browser evidence: state/acceptance/team-project-regression-01b08d88/.

Project progress records (2026-10-26)
-------------------------------------------------------------------------
Manifest: project-hierarchy-overrides.json (20 overrides, 3 extensions).
Reviewable integration: project-progress-entry.patch. Progress extensions are
loaded from src/extensions and contain native modular project transactions,
a project-local controller, the profile menu item, and the summary view.
No database schema or vendor checkout changes are required.

Entry points: the project menu's 进展记录, the overview's 项目进展 box,
project-list links, and the shared 发布进展 navigation action. The canonical
record page is /project/progress/{id}/. Three record kinds are supported:
项目进展, 工作评论, and 关键节点. Every record has its native transaction ID,
server-side author/date, title, remarkup body and participants. Corrections
are new records. No record edit/delete control is offered. The transaction
stream remains available in native project history and activity feeds.

Only users with project edit capability may publish, provided they can view
the project and its ancestors. Membership alone does not grant publication.
Other viewers can read records, and may be attributed as participants.
Participants must be active approved users who can view the project. The
controller requires native CSRF validation; direct transaction-editor calls
repeat authorization and input validation and require native CAN_EDIT.
Existing project ACLs are unchanged.

Progress/key-node records optionally update status and completion percentage
(0-100). Empty values preserve the prior value; unknown completion is never
shown as zero. Comments never update this projection. The native editor's
project lock serializes the projection update. Native transaction metadata is
used for attribution; caller-supplied authors/dates/IDs are not accepted.
The overview shows current state, latest progress, latest work comment and
latest key node. Comments never replace the latest progress summary. Stable
links use ?entry={transactionID}#entry-{transactionID}, including entries
older than the first 50 records. Normal history has cursor pagination and
kind filters. Existing milestone projects remain task-stage containers; the
subprojects page points users to key-node records for dated achievements.

Additional regressions:
  python3 scripts/test-project-isolated.py --keep
  python3 scripts/test-project-ui-isolated.py state/acceptance/RUN/report.json
  python3 scripts/test-project-progress-ui-isolated.py state/acceptance/RUN/report.json
Run hierarchy UI before progress UI on the same disposable runtime.
During development --staging uses progress-staging files without changing
live file-bind inodes. Runtime hashes must match the native test report.
Promote those files atomically, run tests/project-overrides.py without
--staging, then recreate phorge/phorge-daemon/maintenance after tests pass.

Historical fixture cleanup: scripts/cleanup-test-projects.py uses the exact
reviewed PHIDs from state/permissions-acceptance.json, not a prefix search.
It requires a verified application SQL backup before --apply and protects
real project/user rows and task content/policies with before/after hashes.
The cleanup removed 9 historical test projects; no test users remained.
It preserved 7 real projects, 4 real users and all 9 task objects. Native
project destruction removes the deleted projects' tags/board metadata.
Evidence: state/acceptance/test-project-cleanup/result.json.
SQL backup: backups/20261026T122142Z (private application snapshot).
Code rollback: state/acceptance/project-progress-code-backup.json. Its
overlay retains the previous hierarchy/permission fixes and disables the
new progress UI/classes. Records remain in SQL; re-enable the extension to
read them again. Never restore an old SQL snapshot for code-only rollback.

Progress deployment status: APPLIED. 20 overrides + 3 extensions match in all
three running PHP environments (69 hashes). 51 logic checks, 4 permission
fixture groups, 5 progress fixture groups, 46 hierarchy browser checks, 74
progress browser checks and 102 public checks passed. All temporary test
resources were removed. Evidence: state/acceptance/project-progress-release.json.

Publication policy update: project CAN_EDIT is required for all three record
kinds, including work comments. Membership alone does not grant publication.
Revoked edit permission is rechecked against the current project for both
the service and native editor. Six progress native groups and 84 browser
checks passed; isolated fixtures/credentials were destroyed. Evidence:
state/acceptance/project-progress-edit-permission-release.json.

Native activity integration audit (2026-10-26, deployed)
-------------------------------------------------------------------------
Task details remain in native task comments/status; project-level reporting
remains in manual progress transactions. The record page links to native
project-filtered Feed and task search and labels its manual-only history
explicitly. Existing Reports/Burnup covers task-count trends; manual percent
is a different reported metric and is not calculated from those counts.
Feed titles link directly to the saved entry; native detail views include
attribution, participants, state and percent. Stored payloads are unchanged.
The modular type obtains its bound storage from the native remarkup change
context's public getTransaction accessor because this fork's direct storage
getter is private; constructing that context has no persistence effects.

Eight native progress groups plus four prior permission groups, 139 browser
checks and 102 public checks passed. New tests execute actual PublishWorker
jobs and render the mixed native FeedBuilder; synthetic task activity remains
separate from the three saved project records. Cross-viewer remarkup checks
cover private task references after an authorized render has warmed the cache.
Task comments follow task VIEW/INTERACT and do not grant project CAN_EDIT.
Gorge HTTP/outbox/WS/email transport integrations were unchanged and were not
retested as a complete transport stack in this isolated regression.

Historical boundaries at that release: no automatic Git import into progress
entries, no derived percentage or descendant rollup, and no reverse mention
edges/@ subscriptions from project-record body text. Native task discussion
remains available for its existing collaboration behavior. Evidence is in
state/acceptance/project-progress-integration/assessment.json and
state/acceptance/project-progress-integration-release.json.

Live collaboration fixes (2026-10-27, deployed)
-------------------------------------------------------------------------
Project record bodies now provide native Remarkup changes for new task/object
reverse references. File references do not grant attachment access; old records
are not bulk rewritten, and project user-mention subscriptions are not added.
Native detail rendering reloads the project with full member/ancestor context
under the actual viewer, so mentions can evaluate other users without missing
attached-data failures. This repaired the real record 174 / worker 860 failure.

The reviewed PeopleProfileController override preserves application crumbs if
a denied profile query has not assigned its target. This keeps the native
permission rejection and missing-target response renderable without a second
null dereference. Its pinned upstream hash and five-line patch are tracked in
project-hierarchy-overrides.json and people-profile-denial.patch.

Final evidence: state/acceptance/team-project-regression-15c2120b/
report-live-fixes-accepted.json and progress-ui/report.json (45 native groups,
175 browser assertions). Production role hashes, real multi-user scenarios,
maintenance approval error fix, queue recovery, and deployment notes are in
state/acceptance/live-collaboration-20261027/ and DEPLOYMENT.md.
