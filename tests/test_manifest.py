"""Manifest signing, validation and the guarantees restore relies on."""

from __future__ import annotations

import unittest

from tests import __doc__ as _tests_package  # noqa: F401

from haven.chunker import ChunkParams
from haven.errors import ConfigError, IntegrityError
from haven.manifest import (
    FORMAT,
    make_manifest,
    new_snapshot_id,
    referenced_objects,
    sign_manifest,
    snapshot_created,
    validate_manifest,
    verify_manifest,
)

SECRET = b"\x01" * 32
OTHER = b"\x02" * 32
HEX_A = "a" * 64
HEX_B = "b" * 64


def manifest(**overrides) -> dict:
    entries = overrides.pop(
        "entries",
        [
            {"p": "etc", "t": "d", "m": 0o755, "mt": 0.0, "u": 0, "g": 0},
            {"p": "etc/hosts", "t": "f", "m": 0o644, "mt": 0.0, "u": 0, "g": 0, "s": 10, "c": [[HEX_A, 10]]},
            {"p": "etc/current", "t": "l", "m": 0o777, "mt": 0.0, "u": 0, "g": 0, "tg": "/etc/hosts"},
        ],
    )
    return make_manifest(
        snapshot_id=overrides.pop("snapshot_id", new_snapshot_id()),
        host=overrides.pop("host", "web-01"),
        paths=overrides.pop("paths", ["/etc"]),
        entries=entries,
        chunker=overrides.pop("chunker", ChunkParams()),
        codec="zlib:6",
        excludes=[],
        stats={"files": 1},
        secret=overrides.pop("secret", SECRET),
        **overrides,
    )


class ManifestTests(unittest.TestCase):
    def test_sign_and_verify(self):
        doc = manifest()
        self.assertTrue(doc["signature"].startswith("hmac-sha256:"))
        self.assertTrue(verify_manifest(doc, SECRET))
        self.assertFalse(verify_manifest(doc, OTHER))
        validate_manifest(doc, secret=SECRET)

    def test_tampering_detected(self):
        doc = manifest()
        doc["entries"][1]["s"] = 11
        doc["entries"][1]["c"] = [[HEX_A, 11]]
        self.assertFalse(verify_manifest(doc, SECRET))
        with self.assertRaises(IntegrityError):
            validate_manifest(doc, secret=SECRET)

    def test_signature_is_required(self):
        doc = manifest()
        del doc["signature"]
        with self.assertRaises(IntegrityError):
            validate_manifest(doc, secret=SECRET)
        with self.assertRaises(ConfigError):
            validate_manifest(manifest(), secret=None)

    def test_rejects_traversal(self):
        doc = manifest(
            entries=[
                {"p": "../etc/passwd", "t": "f", "m": 0o644, "mt": 0.0, "s": 10, "c": [[HEX_A, 10]]},
            ]
        )
        with self.assertRaises(ConfigError):
            validate_manifest(doc, secret=SECRET)

    def test_rejects_absolute_path(self):
        doc = manifest(
            entries=[{"p": "/etc/passwd", "t": "f", "m": 0o644, "mt": 0.0, "s": 10, "c": [[HEX_A, 10]]}]
        )
        with self.assertRaises(ConfigError):
            validate_manifest(doc, secret=SECRET)

    def test_rejects_duplicate_paths(self):
        doc = manifest(
            entries=[
                {"p": "etc/hosts", "t": "f", "m": 0o644, "mt": 0.0, "s": 10, "c": [[HEX_A, 10]]},
                {"p": "etc/hosts", "t": "f", "m": 0o644, "mt": 0.0, "s": 10, "c": [[HEX_A, 10]]},
            ]
        )
        with self.assertRaises(ConfigError):
            validate_manifest(doc, secret=SECRET)

    def test_rejects_size_mismatch(self):
        doc = manifest(
            entries=[{"p": "f", "t": "f", "m": 0o644, "mt": 0.0, "s": 99, "c": [[HEX_A, 10]]}]
        )
        with self.assertRaises(ConfigError):
            validate_manifest(doc, secret=SECRET)

    def test_rejects_unknown_type(self):
        doc = manifest(entries=[{"p": "f", "t": "z", "m": 0o644, "mt": 0.0}])
        with self.assertRaises(ConfigError):
            validate_manifest(doc, secret=SECRET)

    def test_rejects_bad_format_and_id(self):
        doc = manifest()
        doc["format"] = 99
        with self.assertRaises(ConfigError):
            validate_manifest(sign_manifest(doc, SECRET), secret=SECRET)
        doc = manifest()
        doc["id"] = "not-a-snapshot"
        with self.assertRaises(ConfigError):
            validate_manifest(sign_manifest(doc, SECRET), secret=SECRET)

    def test_rejects_hardlink_to_missing_entry(self):
        doc = manifest(
            entries=[
                {
                    "p": "etc/link",
                    "t": "f",
                    "m": 0o644,
                    "mt": 0.0,
                    "s": 10,
                    "c": [[HEX_A, 10]],
                    "hl": "etc/does-not-exist",
                }
            ]
        )
        with self.assertRaises(ConfigError):
            validate_manifest(doc, secret=SECRET)

    def test_rejects_hardlink_escape(self):
        doc = manifest(
            entries=[
                {"p": "etc/hosts", "t": "f", "m": 0o644, "mt": 0.0, "s": 10, "c": [[HEX_A, 10]]},
                {
                    "p": "etc/evil",
                    "t": "f",
                    "m": 0o644,
                    "mt": 0.0,
                    "s": 10,
                    "c": [[HEX_A, 10]],
                    "hl": "../../../../etc/shadow",
                },
            ]
        )
        with self.assertRaises(ConfigError):
            validate_manifest(doc, secret=SECRET)

    def test_rejects_hardlink_to_symlink(self):
        doc = manifest(
            entries=[
                {"p": "etc/current", "t": "l", "m": 0o777, "mt": 0.0, "tg": "/etc/hosts"},
                {
                    "p": "etc/evil",
                    "t": "f",
                    "m": 0o644,
                    "mt": 0.0,
                    "s": 10,
                    "c": [[HEX_A, 10]],
                    "hl": "etc/current",
                },
            ]
        )
        with self.assertRaises(ConfigError):
            validate_manifest(doc, secret=SECRET)

    def test_accepts_valid_hardlink(self):
        doc = manifest(
            entries=[
                {"p": "etc/hosts", "t": "f", "m": 0o644, "mt": 0.0, "s": 10, "c": [[HEX_A, 10]]},
                {
                    "p": "etc/hosts-2",
                    "t": "f",
                    "m": 0o644,
                    "mt": 0.0,
                    "s": 10,
                    "c": [[HEX_A, 10]],
                    "hl": "etc/hosts",
                },
            ]
        )
        validate_manifest(doc, secret=SECRET)

    def test_referenced_objects(self):
        doc = manifest()
        self.assertEqual(referenced_objects(doc["entries"]), {HEX_A})

    def test_snapshot_id_encodes_time(self):
        doc = manifest()
        self.assertAlmostEqual(snapshot_created(doc["id"]), snapshot_created(doc["id"]))
        self.assertGreater(snapshot_created(doc["id"]), 1_700_000_000)
        with self.assertRaises(ConfigError):
            snapshot_created("garbage")

    def test_format_constant(self):
        self.assertEqual(FORMAT, 1)


if __name__ == "__main__":
    unittest.main()
