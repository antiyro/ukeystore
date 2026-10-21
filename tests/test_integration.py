import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("integrate", ROOT / "tools/integrate.py")
integrate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(integrate)


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tree = Path(self.temp.name).resolve()
        self.source = self.tree / "keystore2/src/lib.rs"
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b"upstream source\n")
        self.base = {"commit": "public-base", "preimages": [{
            "path": "keystore2/src/lib.rs",
            "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
        }]}

    def git_ok(self, tree, *args):
        if args == ("rev-parse", "--show-toplevel"):
            return str(tree)
        if args == ("rev-parse", "HEAD"):
            return self.base["commit"]
        return ""

    def test_rejects_modified_preimage(self):
        self.source.write_bytes(b"modified\n")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            integrate.verify_preimages(self.tree, self.base)

    def test_rejects_symlinked_source(self):
        self.source.unlink()
        outside = self.tree / "outside.rs"
        outside.write_bytes(b"upstream source\n")
        self.source.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symlinked"):
            integrate.verify_preimages(self.tree, self.base)

    def test_rejects_wrong_commit(self):
        def wrong(tree, *args):
            return "wrong" if args == ("rev-parse", "HEAD") else self.git_ok(tree, *args)
        with patch.object(integrate, "git", side_effect=wrong):
            with self.assertRaisesRegex(ValueError, "pinned"):
                integrate.verify_checkout(self.tree, self.base)

    def test_rejects_dirty_tree(self):
        def dirty(tree, *args):
            return " M file" if args[0] == "status" else self.git_ok(tree, *args)
        with patch.object(integrate, "git", side_effect=dirty):
            with self.assertRaisesRegex(ValueError, "clean"):
                integrate.verify_checkout(self.tree, self.base)

    def test_rejects_existing_destination(self):
        (self.source.parent / "attestation_shim.rs").write_text("existing\n")
        with patch.object(integrate, "git", side_effect=self.git_ok):
            with self.assertRaisesRegex(ValueError, "overwrite"):
                integrate.verify_checkout(self.tree, self.base)

    def test_rejects_symlinked_destination_directory(self):
        outside = self.tree / "other"
        outside.mkdir()
        (self.tree / "keystore2/ukeystore").symlink_to(outside, target_is_directory=True)
        with patch.object(integrate, "git", side_effect=self.git_ok):
            with self.assertRaisesRegex(ValueError, "Symlinked"):
                integrate.verify_checkout(self.tree, self.base)

    def test_dry_run_does_not_write(self):
        with patch.object(integrate, "verify_checkout"), patch.object(integrate.subprocess, "run") as run:
            before = sorted(str(p.relative_to(self.tree)) for p in self.tree.rglob("*"))
            result = integrate.integrate(self.tree)
            after = sorted(str(p.relative_to(self.tree)) for p in self.tree.rglob("*"))
        self.assertEqual(before, after)
        self.assertFalse(result["applied"])
        self.assertEqual(run.call_count, 1)
        self.assertIn("--check", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
