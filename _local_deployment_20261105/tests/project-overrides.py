#!/usr/bin/env python3
"""Check pinned source/patch consistency and all Phorge runtime mounts.

No Docker daemon, database, credentials, or application writes are required.
Optionally pass --xhpast PATH for an additional PHP parser check.
This does not execute PHP or replace the native permission regressions.
"""
import argparse
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

import yaml


ROOT = Path(__file__).resolve().parents[1]
OVERRIDES = ROOT / "config/phorge/overrides"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xhpast", type=Path)
    parser.add_argument("--staging", action="store_true",
                        help="Validate progress and organization staging sources before release.")
    parser.add_argument("--compose-root", type=Path, default=ROOT, help="Read candidate Compose files here during staged validation.")
    args = parser.parse_args()
    manifest = json.loads((OVERRIDES / "project-hierarchy-overrides.json").read_text())
    spec = importlib.util.spec_from_file_location("generate_core", ROOT / "scripts/generate-core.py")
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    assert manifest["baseCommit"] == generator.PHORGE_COMMIT
    files = manifest["files"]
    assert len({row["file"] for row in files}) == len(files)
    assert len({row["path"] for row in files}) == len(files)
    patches = [path.read_text() for path in (
        OVERRIDES / "subproject-permissions.patch",
        OVERRIDES / "project-parent-navigation.patch",
        OVERRIDES / "project-hierarchy-browser.patch",
        OVERRIDES / "project-progress-entry.patch",
        OVERRIDES / "people-profile-denial.patch",
        OVERRIDES / "project-membership-management.patch",
        OVERRIDES / "policy-language.patch",
        OVERRIDES / "policy-options.patch",
    )]
    sources = generator.project_runtime_sources(staging=args.staging)
    source_by_target = {row["path"]: ROOT / row["source"] for row in sources}
    mounts = []
    for row in files:
        target = Path(row["path"])
        assert (target.parts[:3] == ("src", "applications", "project") or
                target.as_posix() in (
                    "src/applications/maniphest/editor/ManiphestEditEngine.php",
                    "src/applications/maniphest/config/PhabricatorManiphestConfigOptions.php") or
                target.as_posix() == "src/applications/people/controller/PhabricatorPeopleProfileController.php" or
                target.as_posix() == "src/applications/policy/view/PhabricatorPolicyRulesView.php" or
                target.as_posix() == "src/applications/policy/controller/PhabricatorPolicyEditController.php" or
                target.as_posix() == "src/view/form/control/AphrontFormPolicyControl.php")
        assert target.name == row["file"] and ".." not in target.parts
        original = ROOT / "vendor/phorge" / target
        override = source_by_target[row["path"]]
        assert hashlib.sha256(original.read_bytes()).hexdigest() == row["upstreamSHA256"], original
        diff = "".join(difflib.unified_diff(
            original.read_text().splitlines(True), override.read_text().splitlines(True),
            fromfile="a/" + row["path"], tofile="b/" + row["path"]))
        assert diff and sum(diff in patch for patch in patches) == 1, override
        mounts.append("./config/phorge/overrides/" + row["file"] +
                      ":/opt/phorge/phorge/" + row["path"] + ":ro")
    print(f"PASS: {len(files)} pinned upstream hashes and reviewable patches")
    extensions = manifest.get("extensions", [])
    assert len(extensions) == 6
    assert len({row["file"] for row in extensions}) == len(extensions)
    for row in extensions:
        assert row["path"] == "src/extensions/" + row["file"]
        assert Path(row["file"]).name == row["file"]
        assert source_by_target[row["path"]].is_file(), row["file"]
        mounts.append("./config/phorge/extensions/" + row["file"] +
                      ":/opt/phorge/phorge/" + row["path"] + ":ro")

    organization = json.loads((OVERRIDES / "organization-runtime.json").read_text())
    assert organization["baseCommit"] == generator.PHORGE_COMMIT
    organization_files = organization["files"]
    assert len(organization_files) == 5
    assert len({row["file"] for row in organization_files}) == len(organization_files)
    for row in organization_files:
        assert Path(row["file"]).name == row["file"]
        assert row["source"] == ("config/phorge/organization/" if row["file"].endswith(".sql")
                                  else "config/phorge/extensions/") + row["file"]
        assert row["path"] == ("resources/sql/team-organization/" if row["file"].endswith(".sql")
                                else "src/extensions/") + row["file"]
        assert source_by_target[row["path"]].is_file(), row["file"]
        mounts.append("./" + row["source"] + ":/opt/phorge/phorge/" + row["path"] + ":ro")
    localization = json.loads((OVERRIDES / "localization-runtime.json").read_text())
    assert localization["baseCommit"] == generator.PHORGE_COMMIT
    assert len(localization["files"]) == 1
    for row in localization["files"]:
        assert row["file"] == "PhabricatorChineseTranslation.php"
        assert row["source"] == "config/phorge/overrides/" + row["file"]
        assert row["path"] == "src/infrastructure/internationalization/translation/" + row["file"]
        original = ROOT / "vendor/phorge" / row["path"]
        assert hashlib.sha256(original.read_bytes()).hexdigest() == row["imageBaselineSHA256"]
        replacement = source_by_target[row["path"]]
        diff = "".join(difflib.unified_diff(
            original.read_text().splitlines(True), replacement.read_text().splitlines(True),
            fromfile="a/" + row["path"], tofile="b/" + row["path"]))
        assert diff and sum(diff in patch for patch in patches) == 1
        mounts.append("./" + row["source"] + ":/opt/phorge/phorge/" + row["path"] + ":ro")
    assert len(source_by_target) == len(sources) == len(mounts)

    core = yaml.safe_load((args.compose_root / "compose.core.yaml").read_text())
    maintenance = yaml.safe_load((args.compose_root / "compose.maintenance.yaml").read_text())
    generated = generator.generate_compose(ROOT / "vendor/phorge")
    for service in ("phorge", "phorge-daemon", "phorge-migrate"):
        for mount in mounts:
            assert core["services"][service]["volumes"].count(mount) == 1, (service, mount)
            assert generated["services"][service]["volumes"].count(mount) == 1, (service, mount)
        # Optional maintenance settings must not mount another source over a
        # reviewed core runtime file. The private key/defaults remain there.
        override_mounts = maintenance["services"].get(service, {}).get("volumes", [])
        targets = {mount.split(":")[1] for mount in mounts}
        assert not any(mount.split(":")[1] in targets for mount in override_mounts)
    for mount in mounts:
        assert maintenance["services"]["maintenance"]["volumes"].count(mount) == 1, mount
    print("PASS: all four PHP roles share reviewed project/organization sources and SQL migration without duplicate mounts")

    if args.xhpast:
        paths = [path for path in source_by_target.values() if path.suffix == ".php"] + [
            ROOT / "tests/project-navigation.php",
            ROOT / "tests/project-hierarchy.php",
            ROOT / "tests/permissions/subproject-permissions.php",
            ROOT / "tests/permissions/audit-legacy-parent-members.php",
            ROOT / "tests/permissions/snapshot-project-state.php",
            ROOT / "tests/project-ui-fixture.php",
            ROOT / "tests/permissions/project-progress.php",
            ROOT / "tests/permissions/project-organization.php",
            ROOT / "tests/permissions/project-access.php",
            ROOT / "tests/project-progress-ui-fixture.php",
            ROOT / "tests/project-access-ui-fixture.php",
            ROOT / "tests/people-profile-denial.php",
        ]
        for path in paths:
            result = subprocess.run([str(args.xhpast.resolve())], input=path.read_bytes(),
                                    capture_output=True, check=True)
            json.loads(result.stdout)
        print(f"PASS: XHPAST syntax parsing for {len(paths)} PHP files (not runtime execution)")


if __name__ == "__main__":
    main()
