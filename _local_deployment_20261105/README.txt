Pre-upstream local deployment source snapshot, 2026-11-05.

The application tree retains the complete local integration based on PR48-50,
then overlays the exact PHP/SQL files bound into the running deployment.
_local_deployment_20261105 contains the local deployment/test tooling and reports.
The manifest lists each copied source path and digest.

Live environment files, interpolated Compose, credentials, private keys,
database contents, account stores, attachments and user sessions are excluded.
Those are preserved by a separate owner-only server backup before cutover.
This branch is a source recovery snapshot, not a new upstream feature PR.
