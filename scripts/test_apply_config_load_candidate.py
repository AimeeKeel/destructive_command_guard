"""Exercise the production #568 patch consumer with real Git blobs and git apply.

Run: python3 -m unittest discover -s scripts -p test_apply_config_load_candidate.py -v
No compiler, executable DCG, network, install, publication, or user config is used.
The baseline files come from actual immutable objects in the repository history;
this remains a producer/application test, not config-runtime acceptance.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import apply_config_load_candidate as candidate

SOURCE_BLOBS = {
    "src/config.rs": "18953a0a7eb22ac5c6e3c757113bec605017f596",
    "src/main.rs": "7a90d3f8cd48693a3f441968bb8f28b28357dfbd",
    "src/evaluator.rs": "d46131c2734cbf6a1ae60f8b48aec122b1f65db1",
    "src/cli.rs": "dd003d861a725e4fbf51e37ea7eb1886474a9d6e",
}

POSTIMAGES = {
    "src/config.rs": "720d6e408cdcd75a71007bd954e2d99c9d774aee342979559808827714fa9a6f",
    "src/main.rs": "7357563616f1d30165cf6ff09f18b75a702770908eea997262ffaae2347c05ba",
    "src/evaluator.rs": "0f38d575dafd611f9ef831a3cad2a26118949b4e57f1a3c4897abb997c6cb0c1",
    "src/cli.rs": "ed9f63206037ba50d1ec2fd7059cec3063e18bf6573352b9d7c61dce3a741109",
    "src/config_load_regression_tests.rs": "f7e097798629c7338655564f55c990ee1261a2c4de40a34aa45366cb9d9aeea8",
}


class CandidateApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="dcg-568-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name, oid in SOURCE_BLOBS.items():
            data = subprocess.check_output(["git", "cat-file", "blob", oid],
                                           cwd=candidate.ROOT, timeout=30)
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for name in [candidate.PATCH, candidate.REGRESSION]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(candidate.ROOT / name, path)

    def snapshot(self) -> dict[str, bytes]:
        return {str(path.relative_to(self.root)): path.read_bytes()
                for path in self.root.rglob("*") if path.is_file()}

    def run_consumer(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(candidate.ROOT / "scripts/apply_config_load_candidate.py"),
             "--root", str(self.root), *args],
            capture_output=True, text=True, check=False, timeout=30,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def assert_refused_without_changes(self, message: str) -> None:
        before = self.snapshot()
        result = self.run_consumer()
        self.assertNotEqual(result.returncode, 0, result)
        self.assertIn(message, result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_real_candidate_applies_exact_reviewed_source_and_unit_regressions(self):
        regression = (self.root / candidate.REGRESSION).read_bytes()
        result = self.run_consumer()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name, expected in POSTIMAGES.items():
            self.assertEqual(hashlib.sha256((self.root / name).read_bytes()).hexdigest(), expected, name)
        self.assertEqual((self.root / candidate.REGRESSION).read_bytes(), regression)
        self.assertIn(b'#[path = "config_load_regression_tests.rs"]',
                      (self.root / "src/config.rs").read_bytes())

    def test_check_only_proves_real_apply_without_changing_files(self):
        before = self.snapshot()
        result = self.run_consumer("--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_tampered_patch_fails_before_source_modification(self):
        with (self.root / candidate.PATCH).open("ab") as patch:
            patch.write(b"\n# unreviewed payload\n")
        self.assert_refused_without_changes("patch SHA256 mismatch")

    def test_empty_patch_is_not_a_candidate(self):
        (self.root / candidate.PATCH).write_bytes(b"")
        self.assert_refused_without_changes("patch SHA256 mismatch")

    def test_missing_patch_fails_before_source_modification(self):
        (self.root / candidate.PATCH).rename(self.root / "retained-patch")
        self.assert_refused_without_changes("missing regular candidate input")

    def test_wrong_base_outside_patch_context_still_refuses(self):
        with (self.root / "src/config.rs").open("ab") as source:
            source.write(b"\n// useful intervening source work\n")
        self.assert_refused_without_changes("source preimage mismatch")

    def test_existing_unit_regressions_are_never_overwritten(self):
        (self.root / candidate.NEW_UNIT_TESTS).write_text("// useful existing regressions\n")
        self.assert_refused_without_changes("refusing to overwrite existing unit regressions")

    def test_missing_process_protocol_consumers_refuse(self):
        (self.root / candidate.REGRESSION).rename(self.root / "retained-process-tests.rs")
        self.assert_refused_without_changes("missing regular candidate input")

    def test_changed_process_protocol_consumers_refuse(self):
        with (self.root / candidate.REGRESSION).open("ab") as tests:
            tests.write(b"\n// useful intervening regression\n")
        self.assert_refused_without_changes("regression preimage mismatch")

    def test_symlinked_patch_is_not_a_trusted_checkout_input(self):
        payload = self.root / candidate.PATCH
        retained = self.root / "retained-patch"
        payload.rename(retained)
        payload.symlink_to(retained)
        self.assert_refused_without_changes("must not be a symlink")

    def test_already_applied_candidate_cannot_publish_again(self):
        result = self.run_consumer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_refused_without_changes("source preimage mismatch")

    def test_workflow_uses_guarded_consumer_before_any_rust_gate(self):
        workflow = (candidate.ROOT / ".github/workflows/config-load-568.yml").read_text(encoding="utf-8")
        consumer = workflow.index("python3 scripts/apply_config_load_candidate.py")
        self.assertLess(consumer, workflow.index("- name: Format publication candidate"))
        self.assertLess(consumer, workflow.index("run: cargo test --locked"))
        self.assertIn("rustfmt --edition 2024", workflow)
        self.assertIn("--config skip_children=true", workflow)
        self.assertNotIn("run: cargo fmt\n", workflow)
        self.assertIn("run: cargo fmt --check", workflow)
        self.assertIn("if: github.event_name == 'workflow_dispatch' && inputs.publish",
                      workflow[:consumer])
        self.assertIn("test_apply_config_load_candidate.py -v", workflow)
        self.assertIn("git push --atomic origin HEAD:refs/heads/main HEAD:refs/heads/master", workflow)


if __name__ == "__main__":
    unittest.main()
