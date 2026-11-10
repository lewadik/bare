"""Chunking: determinism, size bounds, dedup across edits, fixed mode."""

from __future__ import annotations

import hashlib
import io
import os
import random
import unittest

from tests import __doc__ as _tests_package  # noqa: F401  (puts the project on sys.path)

from haven.chunker import ChunkParams, chunk_bytes, chunk_hashes, iter_chunks, parse_chunking_spec

PARAMS = ChunkParams(minimum=512, average=2048, maximum=8192)


def _random_bytes(size: int, seed: int = 7) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(size))


class ChunkerTests(unittest.TestCase):
    def test_sizes_within_bounds(self):
        data = _random_bytes(200_000)
        chunks = chunk_bytes(data, PARAMS)
        self.assertGreater(len(chunks), 10)
        self.assertEqual(b"".join(chunks), data)
        for chunk in chunks[:-1]:
            self.assertGreaterEqual(len(chunk), PARAMS.minimum)
            self.assertLessEqual(len(chunk), PARAMS.maximum)
        self.assertLessEqual(len(chunks[-1]), PARAMS.maximum)

    def test_deterministic_across_calls_and_streams(self):
        data = _random_bytes(50_000, seed=11)
        first = [hashlib.sha256(chunk).hexdigest() for chunk in chunk_bytes(data, PARAMS)]
        second = [hashlib.sha256(chunk).hexdigest() for chunk in chunk_bytes(data, PARAMS)]
        self.assertEqual(first, second)
        streamed = [hashlib.sha256(chunk).hexdigest() for chunk in iter_chunks(io.BytesIO(data), PARAMS, read_size=997)]
        self.assertEqual(first, streamed)

    def test_empty_and_tiny(self):
        self.assertEqual(chunk_bytes(b"", PARAMS), [])
        self.assertEqual(chunk_bytes(b"abc", PARAMS), [b"abc"])
        self.assertEqual(list(iter_chunks(io.BytesIO(b""), PARAMS)), [])

    def test_identical_prefix_reuses_chunks_after_insertion(self):
        data = _random_bytes(400_000, seed=3)
        edited = data[:100_000] + b"INSERTED-BYTES" + data[100_000:]
        before = set(chunk_hashes(data, PARAMS))
        after = set(chunk_hashes(edited, PARAMS))
        before_ids = {item[0] for item in before}
        after_ids = {item[0] for item in after}
        shared = before_ids & after_ids
        # All chunks before the edit plus everything after the next cut point.
        self.assertGreater(len(shared), len(before_ids) * 0.6)
        self.assertLess(len(shared), len(before_ids))

    def test_appending_rewrites_only_the_tail(self):
        data = _random_bytes(100_000, seed=5)
        appended = data + _random_bytes(20_000, seed=5)
        before = {item[0] for item in chunk_hashes(data, PARAMS)}
        after = {item[0] for item in chunk_hashes(appended, PARAMS)}
        # The final chunk of the original file was cut by EOF, so appending data
        # extends and re-cuts it; everything before that is untouched.
        self.assertLessEqual(len(before - after), 1)
        self.assertLess(len(after) - len(before), 4)

    def test_fixed_mode(self):
        params = ChunkParams(minimum=1024, average=1024, maximum=1024, mode="fixed")
        data = _random_bytes(5000)
        chunks = chunk_bytes(data, params)
        self.assertEqual([len(chunk) for chunk in chunks], [1024, 1024, 1024, 1024, 904])
        self.assertEqual(b"".join(chunks), data)

    def test_parse_spec(self):
        params = parse_chunking_spec("min=64K,avg=1M,max=8M")
        self.assertEqual((params.minimum, params.average, params.maximum), (65536, 1048576, 8388608))
        fixed = parse_chunking_spec("fixed=4M")
        self.assertEqual((fixed.mode, fixed.minimum), ("fixed", 4194304))

    def test_invalid_params(self):
        with self.assertRaises(Exception):
            ChunkParams(minimum=100, average=50, maximum=10)
        with self.assertRaises(Exception):
            ChunkParams(mode="magic")

    def test_identifier_tracks_parameters(self):
        self.assertEqual(PARAMS.identifier(), PARAMS.identifier())
        other = ChunkParams(minimum=512, average=2048, maximum=8192)
        self.assertEqual(PARAMS.identifier(), other.identifier())
        larger = ChunkParams(minimum=512, average=4096, maximum=8192)
        self.assertNotEqual(PARAMS.identifier(), larger.identifier())


if __name__ == "__main__":
    unittest.main()
