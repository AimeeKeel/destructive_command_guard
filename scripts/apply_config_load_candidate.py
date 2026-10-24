#!/usr/bin/env python3
"""Apply the immutable #568 candidate only to its reviewed source preimages.

The patch recovers the candidate archive whose Git blob is
8a8202da56093d3bb8c56303ddaee1a0706ca0af (SHA256
88ff782aba402680dc5115acd5fa1d5a6bdbf6fe82c1dd3e282c6fbe15bcee64).
Its original seven-blob transport is retained in commit 17982f8d. The Rust
changes preserve the original producer's output plus the batch config-error
protocol repair, formatted with the pinned rustfmt;
the newer process/protocol regressions remain in the checkout, not overwritten.
This command neither compiles code nor publishes any Git objects or refs.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PATCH = Path(".github/patches/config-load-568.patch")
PATCH_SHA256 = "82a4bbd07e3a6dde87a6ba7ff33f3f65f21b535f184c493ac9b0aded0400077e"
PREIMAGES = {
    "src/config.rs": "44c7948ee5fdd599a087bb8544bc77689ce1a5574aff7a4c613734abb59a10dd",
    "src/main.rs": "839736558a4b48014333134da237cc5af644460af0feb86051bd7e7b24d55731",
    "src/evaluator.rs": "dea96cdb666685172a563a63bf9973817bf9aa0dded78c08f1c17f0fdca4955a",
    "src/cli.rs": "9cae3d022a29fd2073b2fea1ff9513ebb06a49c5008512e7891651fa8f247e8f",
}
REGRESSION = Path("tests/repro_568_config_load.rs")
REGRESSION_SHA256 = "4ee42816b1b610202c96d68f81929a0c7b5f371079fb636da1870f181bae06d4"
NEW_UNIT_TESTS = Path("src/config_load_regression_tests.rs")


def regular_bytes(root: Path, relative: Path) -> bytes:
    path = root / relative
    # Reject symlinks in the path as well as at the leaf. All candidate inputs
    # must be the actual checkout bytes, not files reached outside the checkout.
    if any((root / Path(*relative.parts[:i])).is_symlink()
           for i in range(1, len(relative.parts) + 1)):
        raise ValueError(f"candidate input must not be a symlink: {relative}")
    if not path.is_file():
        raise ValueError(f"missing regular candidate input: {relative}")
    return path.read_bytes()


def apply_candidate(root: Path, *, check: bool = False) -> None:
    patch = regular_bytes(root, PATCH)
    if not patch or hashlib.sha256(patch).hexdigest() != PATCH_SHA256:
        raise ValueError("candidate patch SHA256 mismatch; refusing unreviewed payload")
    for name, expected in PREIMAGES.items():
        content = regular_bytes(root, Path(name))
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected:
            raise ValueError(f"{name}: source preimage mismatch; refusing source drift")
    regression = regular_bytes(root, REGRESSION)
    if hashlib.sha256(regression).hexdigest() != REGRESSION_SHA256:
        raise ValueError("process/protocol regression preimage mismatch")
    unit_tests = root / NEW_UNIT_TESTS
    if unit_tests.exists() or unit_tests.is_symlink():
        raise ValueError(f"refusing to overwrite existing unit regressions: {NEW_UNIT_TESTS}")
    # Feed the bytes that were hashed, so a patch-path replacement between the
    # guard and git apply cannot substitute a different candidate payload.
    subprocess.run(["git", "apply", "--check", "--whitespace=error-all", "-"],
                   input=patch, cwd=root, check=True, timeout=30)
    if not check:
        subprocess.run(["git", "apply", "--whitespace=error-all", "-"],
                       input=patch, cwd=root, check=True, timeout=30)
    print("Verified #568 candidate preimages" + (" (check only)." if check else "; applied five source/test paths."))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT,
                        help="checkout/export to validate and apply (default: repository)")
    parser.add_argument("--check", action="store_true", help="validate without changing source")
    args = parser.parse_args()
    try:
        apply_candidate(args.root.resolve(), check=args.check)
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"#568 candidate refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
