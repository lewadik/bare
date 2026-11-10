"""Pack container: round trip, corruption detection, spill behaviour."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from tests import __doc__ as _tests_package  # noqa: F401

from haven.codec import CODEC_RAW, CODEC_ZLIB, decode, encode
from haven.errors import IntegrityError
from haven.packfile import (
    PACK_MAGIC,
    PackWriter,
    Spill,
    extract_objects,
    iter_objects,
    read_pack_file,
    scan_pack,
    write_pack_file,
)
from haven.util import sha256_file


def _objects() -> list[tuple[str, int, int, bytes]]:
    payloads = [b"hello world", b"x" * 5000, os.urandom(300)]
    out = []
    for payload in payloads:
        flags, packed = encode(payload, CODEC_ZLIB, 6)
        out.append((hashlib.sha256(payload).hexdigest(), flags, len(payload), packed))
    return out


class PackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="haven-pack-"))

    def test_round_trip(self):
        pack = self.tmp / "a.pack"
        objects = _objects()
        pack_id, count, size = write_pack_file(pack, objects)
        self.assertEqual(count, 3)
        self.assertEqual(size, pack.stat().st_size)
        self.assertEqual(pack_id, sha256_file(pack))
        self.assertTrue(pack.read_bytes().startswith(PACK_MAGIC))

        scan = read_pack_file(pack, deep=True, check_objects=True, decoder=decode)
        self.assertEqual(set(scan.records), {item[0] for item in objects})
        self.assertEqual(scan.bad_objects, [])

        recovered = {
            obj_id: decode(flags, payload, plainlen)
            for obj_id, flags, plainlen, payload in iter_objects(pack)
        }
        for obj_id, _flags, plainlen, original_payload in objects:
            self.assertEqual(len(recovered[obj_id]), plainlen)

    def test_extract_by_location(self):
        pack = self.tmp / "b.pack"
        write_pack_file(pack, _objects())
        records = read_pack_file(pack).records
        wanted = dict(list(records.items())[:2])
        extracted = extract_objects(pack, wanted)
        self.assertEqual(set(extracted), set(wanted))

    def test_corrupt_payload_detected(self):
        pack = self.tmp / "c.pack"
        write_pack_file(pack, _objects())
        raw = bytearray(pack.read_bytes())
        raw[40] ^= 0xFF  # inside the first record's payload
        pack.write_bytes(bytes(raw))
        with self.assertRaises(IntegrityError):
            read_pack_file(pack, deep=True)

    def test_object_hash_mismatch_detected(self):
        pack = self.tmp / "d.pack"
        payload = b"payload that does not match its id"
        wrong_id = hashlib.sha256(b"something else entirely").hexdigest()
        # A pack whose trailer is valid but whose object id lies about the
        # content: the server must reject this at ingest.
        pack_id, _count, _size = write_pack_file(pack, [(wrong_id, CODEC_RAW, len(payload), payload)])
        self.assertEqual(pack_id, sha256_file(pack))
        scan = read_pack_file(pack, deep=True, check_objects=True, decoder=decode)
        self.assertEqual(scan.bad_objects, [wrong_id])

    def test_truncated_pack(self):
        pack = self.tmp / "e.pack"
        write_pack_file(pack, _objects())
        data = pack.read_bytes()
        pack.write_bytes(data[:-40])
        with self.assertRaises(IntegrityError):
            read_pack_file(pack)

    def test_bad_magic(self):
        pack = self.tmp / "f.pack"
        pack.write_bytes(b"NOTAPACK" + b"\0" * 100)
        with self.assertRaises(IntegrityError):
            read_pack_file(pack)

    def test_zlib_expansion_is_bounded(self):
        import zlib

        bomb = zlib.compress(b"\0" * (4 * 1024 * 1024), 9)
        with self.assertRaises(IntegrityError):
            decode(CODEC_ZLIB, bomb, 64)  # claims 64 bytes, expands to 4 MiB
        with self.assertRaises(IntegrityError):
            decode(CODEC_ZLIB, bomb, 1 << 40)

    def test_writer_streams_into_file(self):
        pack = self.tmp / "g.pack"
        with open(pack, "wb") as handle:
            writer = PackWriter(handle)
            for obj_id, flags, plainlen, payload in _objects():
                writer.add(obj_id, flags, plainlen, payload)
            digest = writer.close()
        self.assertEqual(digest, sha256_file(pack))
        self.assertEqual(len(read_pack_file(pack).records), 3)

    def test_spill_only_writes_selected_objects(self):
        spill = Spill(self.tmp / "work")
        try:
            objects = _objects()
            for obj_id, flags, plainlen, payload in objects:
                self.assertTrue(spill.add(obj_id, flags, plainlen, payload))
                self.assertFalse(spill.add(obj_id, flags, plainlen, payload))
            self.assertEqual(len(spill), 3)
            self.assertEqual(spill.plainlen(objects[1][0]), objects[1][2])
            wanted = {objects[0][0], objects[2][0]}
            pack_id, count, _size = spill.write_pack(self.tmp / "h.pack", wanted)
            self.assertEqual(count, 2)
            recovered = {obj_id for obj_id, *_ in iter_objects(self.tmp / "h.pack")}
            self.assertEqual(recovered, wanted)
        finally:
            spill.cleanup()


if __name__ == "__main__":
    unittest.main()
