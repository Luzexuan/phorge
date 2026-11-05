Upstream deployment transition, 2026-11-05

The parent commit preserves the complete earlier local source snapshot.
This supplementary directory records the later deployment integration only.
Phorge: 965a72308747346c0de539e78c0a79a0ebaa47d0
Paired Gorge: 55f8ba8e57b179a7dee92ad43c77038ca322f61c

Keep existing ingress, stable identity mapping and persistent volumes.
All previous native project/team/workboard source overrides were removed.
Three deployment bridges remain: entry session/file guard, stored author/admin
policy readers, and read-only legacy team rule readers. The old team's UI,
project role ceilings and extra team boundaries are not restored. This is a
native upstream permission-model transition, not proof of authority equivalence.
Upstream history/workspace feature flags retain their upstream defaults.

Private environment, keys, database, accounts and attachment bytes are excluded.
The full pre-transition recovery bundle is stored encrypted on the server.
Do not restore old SQL over later writes or roll back PHP in isolation.
