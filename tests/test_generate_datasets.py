"""Regression tests for deterministic datasets and fail-closed manifests."""
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "generate_datasets.py"
SPEC = importlib.util.spec_from_file_location("tested_generate_datasets", SCRIPT)
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


class DatasetGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / "data"
        counts = patch.dict(generator.RECORD_COUNTS, {
            "dataset_small.bin": 3,
            "dataset_medium.bin": 5,
            "dataset_large.bin": 7,
        }, clear=True)
        counts.start()
        self.addCleanup(counts.stop)

    def run_generator(self, *args, output=None):
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            code = generator.main(["--output-dir", str(output or self.output), *args])
        return code, captured.getvalue()

    def create(self):
        code, message = self.run_generator()
        self.assertEqual(code, 0, message)
        return self.output / "checksums.sha256"

    def test_fresh_generation_and_verification(self):
        manifest = self.create()
        self.assertEqual(len(generator.read_manifest(manifest)), 9)
        code, message = self.run_generator("--verify")
        self.assertEqual(code, 0, message)

    def test_missing_dataset_regenerates_identically_without_rewriting_manifest(self):
        manifest = self.create()
        original_manifest = manifest.read_bytes()
        medium = self.output / "dataset_medium.bin"
        original_medium = medium.read_bytes()
        medium.unlink()
        code, message = self.run_generator()
        self.assertEqual(code, 0, message)
        self.assertEqual(medium.read_bytes(), original_medium)
        self.assertEqual(manifest.read_bytes(), original_manifest)

    def test_corrupted_and_missing_aborts_before_writing_any_dataset(self):
        manifest = self.create()
        original_manifest = manifest.read_bytes()
        small = self.output / "dataset_small.bin"
        small.write_bytes(b"corrupted")
        medium = self.output / "dataset_medium.bin"
        medium.unlink()
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        code, message = self.run_generator()
        self.assertEqual(code, 1, message)
        self.assertFalse(medium.exists())
        self.assertEqual(manifest.read_bytes(), original_manifest)
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()}, before)
        self.assertNotIn("[OK]", message)
        self.assertEqual(self.run_generator("--verify")[0], 1)

    def test_force_restores_complete_canonical_set(self):
        manifest = self.create()
        originals = {name: (self.output / name).read_bytes() for name in generator.DATASET_NAMES}
        (self.output / "dataset_small.bin").write_bytes(b"corrupted")
        (self.output / "dataset_medium.bin").unlink()
        code, message = self.run_generator("--force")
        self.assertEqual(code, 0, message)
        self.assertTrue(manifest.exists())
        self.assertEqual({name: (self.output / name).read_bytes() for name in generator.DATASET_NAMES}, originals)
        self.assertEqual(self.run_generator("--verify")[0], 0)

    def test_update_manifest_requires_explicit_acceptance_and_a_complete_set(self):
        manifest = self.create()
        original_manifest = manifest.read_bytes()
        (self.output / "dataset_small.bin").write_bytes(b"explicitly accepted new bytes")
        self.assertEqual(self.run_generator()[0], 1)
        self.assertEqual(manifest.read_bytes(), original_manifest)
        self.assertEqual(self.run_generator("--update-manifest")[0], 0)
        self.assertEqual(self.run_generator("--verify")[0], 0)
        updated_manifest = manifest.read_bytes()
        (self.output / "dataset_medium.bin").unlink()
        self.assertEqual(self.run_generator("--update-manifest")[0], 1)
        self.assertEqual(manifest.read_bytes(), updated_manifest)
        self.assertFalse((self.output / "dataset_medium.bin").exists())

    def test_incomplete_duplicate_unknown_or_bad_hash_manifest_is_rejected(self):
        manifest = self.create()
        original = manifest.read_text()
        records = [line for line in original.splitlines() if line and not line.startswith("#")]
        variants = {
            "missing": "\n".join(records[:-1]) + "\n",
            "duplicate": original + records[0] + "\n",
            "unknown": original + "0" * 64 + "  ../../outside\n",
            "bad_hash": original.replace(records[0].split()[0], "not-a-hash", 1),
        }
        for label, content in variants.items():
            with self.subTest(label=label):
                manifest.write_text(content)
                with patch.object(generator, "compute_sha256", side_effect=AssertionError("must reject before reading dataset bytes")):
                    self.assertEqual(self.run_generator("--verify")[0], 1)
                    self.assertEqual(self.run_generator()[0], 1)
                self.assertEqual(manifest.read_text(), content)

    def test_reconstruction_must_match_preserved_hash_before_publication(self):
        manifest = self.create()
        medium = self.output / "dataset_medium.bin"
        expected = generator.compute_sha256(medium)
        medium.unlink()
        manifest.write_text(manifest.read_text().replace(expected, "0" * 64))
        before = manifest.read_bytes()
        code, message = self.run_generator()
        self.assertEqual(code, 1, message)
        self.assertFalse(medium.exists())
        self.assertEqual(manifest.read_bytes(), before)
        self.assertFalse(any(p.is_dir() for p in self.output.iterdir()))

    def test_output_directory_does_not_change_seed_or_manifest(self):
        manifest = self.create()
        alternate = Path(self.temporary.name) / "relocated"
        code, message = self.run_generator(output=alternate)
        self.assertEqual(code, 0, message)
        for name in generator.DATASET_NAMES:
            self.assertEqual((self.output / name).read_bytes(), (alternate / name).read_bytes())
        self.assertEqual(manifest.read_bytes(), (alternate / "checksums.sha256").read_bytes())

    def test_verification_without_manifest_creates_nothing(self):
        self.assertFalse(self.output.exists())
        self.assertEqual(self.run_generator("--verify")[0], 1)
        self.assertFalse(self.output.exists())

    def test_existing_untracked_data_is_not_implicitly_accepted(self):
        manifest = self.create()
        manifest.unlink()
        self.assertEqual(self.run_generator()[0], 1)
        self.assertFalse(manifest.exists())
        self.assertEqual(self.run_generator("--update-manifest")[0], 0)
        self.assertEqual(self.run_generator("--verify")[0], 0)

    def test_symlink_dataset_is_not_followed(self):
        self.create()
        small = self.output / "dataset_small.bin"
        external = Path(self.temporary.name) / "external.bin"
        external.write_bytes(b"outside known dataset files")
        small.unlink()
        small.symlink_to(external)
        with patch.object(generator, "compute_sha256", side_effect=AssertionError("symlink must be rejected before reading")):
            self.assertEqual(self.run_generator("--verify")[0], 1)
            self.assertEqual(self.run_generator()[0], 1)
        self.assertEqual(external.read_bytes(), b"outside known dataset files")

    def test_failed_atomic_manifest_replacement_preserves_previous_manifest(self):
        manifest = self.create()
        original = manifest.read_bytes()
        with patch.object(generator.os, "replace", side_effect=OSError("simulated rename failure")):
            code, message = self.run_generator("--update-manifest")
        self.assertEqual(code, 1, message)
        self.assertEqual(manifest.read_bytes(), original)
        self.assertEqual(sorted(p.name for p in self.output.iterdir()), sorted((*generator.DATASET_NAMES, "checksums.sha256")))


if __name__ == "__main__":
    unittest.main()
