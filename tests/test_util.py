"""Sizes, varints, glob matching, path safety, canonical JSON."""

from __future__ import annotations

import json
import unittest

from tests import __doc__ as _tests_package  # noqa: F401

from haven.errors import ConfigError, UsageError
from haven.util import (
    GlobSet,
    canonical_json,
    decode_varint,
    encode_varint,
    human_bytes,
    parse_size,
    safe_rel_parts,
    to_rel_posix,
)


class SizeTests(unittest.TestCase):
    def test_parse_size(self):
        self.assertEqual(parse_size("1024"), 1024)
        self.assertEqual(parse_size("1K"), 1024)
        self.assertEqual(parse_size("1 KiB"), 1024)
        self.assertEqual(parse_size("8M"), 8 * 1024 * 1024)
        self.assertEqual(parse_size("1.5G"), int(1.5 * 1024**3))
        self.assertEqual(parse_size(4096), 4096)
        with self.assertRaises(UsageError):
            parse_size("12 parsecs")

    def test_human_bytes(self):
        self.assertEqual(human_bytes(0), "0 B")
        self.assertEqual(human_bytes(1536), "1.5 KiB")
        self.assertEqual(human_bytes(5 * 1024**3), "5.0 GiB")


class VarintTests(unittest.TestCase):
    def test_round_trip(self):
        for value in (0, 1, 127, 128, 300, 2**32, 2**63 - 1):
            encoded = encode_varint(value)
            decoded, position = decode_varint(encoded)
            self.assertEqual(decoded, value)
            self.assertEqual(position, len(encoded))

    def test_truncated(self):
        with self.assertRaises(ValueError):
            decode_varint(b"\x80")
        with self.assertRaises(ValueError):
            encode_varint(-1)


class PathSafetyTests(unittest.TestCase):
    def test_accepts_relative(self):
        self.assertEqual(safe_rel_parts("etc/hosts"), ("etc", "hosts"))
        self.assertEqual(safe_rel_parts("a//b/./c"), ("a", "b", "c"))

    def test_rejects_escapes(self):
        for bad in ("/etc/passwd", "../etc/passwd", "a/../../b", "C:\\Windows", "..", "", "a\x00b"):
            with self.assertRaises(ConfigError, msg=bad):
                safe_rel_parts(bad)

    def test_to_rel_posix(self):
        import os

        root = os.path.abspath(os.sep)
        rel = to_rel_posix(os.path.join(root, "etc", "hosts"), root)
        self.assertEqual(rel, "etc/hosts")
        self.assertNotIn("\\", rel)


class GlobTests(unittest.TestCase):
    def test_basename_pattern_matches_any_depth(self):
        globs = GlobSet(["*.tmp"])
        self.assertTrue(globs.matches("var/tmp/x.tmp"))
        self.assertTrue(globs.matches("x.tmp"))
        self.assertFalse(globs.matches("x.tmpx"))

    def test_anchored_pattern(self):
        globs = GlobSet(["/proc"])
        self.assertTrue(globs.matches("proc"))
        self.assertFalse(globs.matches("var/proc"))

    def test_path_pattern(self):
        globs = GlobSet(["var/cache"])
        self.assertTrue(globs.matches("var/cache"))
        self.assertFalse(globs.matches("var/cachex"))
        self.assertFalse(globs.matches("srv/var/cache"))

    def test_double_star(self):
        globs = GlobSet(["**/logs/*.log"])
        self.assertTrue(globs.matches("a/b/logs/x.log"))
        self.assertTrue(globs.matches("logs/x.log"))
        self.assertFalse(globs.matches("a/logs/b/x.log"))
        trailing = GlobSet(["logs/**"])
        self.assertTrue(trailing.matches("logs/a/b"))
        self.assertTrue(trailing.matches("logs"))

    def test_directory_only(self):
        globs = GlobSet(["cache/"])
        self.assertTrue(globs.matches("cache", is_dir=True))
        self.assertFalse(globs.matches("cache", is_dir=False))

    def test_negation_last_wins(self):
        globs = GlobSet(["*.log", "!keep.log"])
        self.assertTrue(globs.matches("a/app.log"))
        self.assertFalse(globs.matches("keep.log"))

    def test_question_mark_and_class(self):
        globs = GlobSet(["file?.txt", "data[0-9].bin"])
        self.assertTrue(globs.matches("file1.txt"))
        self.assertFalse(globs.matches("file10.txt"))
        self.assertTrue(globs.matches("data7.bin"))
        self.assertFalse(globs.matches("datax.bin"))

    def test_patterns_are_recorded(self):
        globs = GlobSet(["/proc", "!keep.tmp", "cache/"])
        self.assertEqual(globs.patterns, ["proc", "!keep.tmp", "cache/"])


class CanonicalJsonTests(unittest.TestCase):
    def test_key_order_is_stable(self):
        self.assertEqual(canonical_json({"b": 1, "a": 2}), b'{"a":2,"b":1}')

    def test_non_utf8_filenames(self):
        payload = {"p": "broken-\udcff-name"}
        encoded = canonical_json(payload)
        self.assertEqual(json.loads(encoded.decode("utf-8")), payload)

    def test_no_whitespace(self):
        self.assertEqual(canonical_json({"a": [1, 2]}), b'{"a":[1,2]}')


if __name__ == "__main__":
    unittest.main()
