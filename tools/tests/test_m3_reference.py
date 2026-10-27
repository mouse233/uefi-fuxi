#!/usr/bin/env python3
"""Offline fake-device tests for the TWRP reference collector."""
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('m3_reference', ROOT / 'tools/collect_fuxi_m3_reference.py')
m3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m3)


class Fake:
    def __init__(self):
        self.calls = []
        self.data = bytearray(4096)
        self.data[1024:1028] = bytes.fromhex('1020f5f2')
        self.responses = {
            ('get-state',): b'recovery\n',
            ('shell', 'getprop', 'ro.product.device'): b'fuxi\n',
            ('shell', 'getprop', 'ro.boot.serialno'): b'fcde91e\n',
            ('shell', 'getprop', 'ro.twrp.version'): b'3.7.1_A15\n',
            ('shell', 'getprop', 'ro.build.version.release'): b'17\n',
            ('shell', 'cat', '/proc/mounts'): b'/dev/block/dm-7 /data f2fs rw 0 0\n/dev/block/sda17 /metadata f2fs rw 0 0\n',
            ('shell', 'readlink', '-f', '/dev/block/by-name/userdata'): b'/dev/block/sda42\n',
            ('shell', 'cat', '/sys/class/block/dm-7/dm/name'): b'userdata\n',
            ('shell', 'ls', '-1', '/sys/class/block/dm-7/slaves'): b'sda42\n',
            ('exec-out', 'dd', 'if=/dev/block/dm-7', 'bs=4096', 'count=1', 'status=none'): bytes(self.data),
            ('exec-out', 'dd', 'if=/dev/block/by-name/userdata', 'bs=4096', 'count=1', 'status=none'): bytes(4096),
        }

    def __call__(self, *args):
        self.calls.append(args)
        return self.responses[args]


class TestReference(unittest.TestCase):
    def test_valid_hashes_and_no_raw_contents(self):
        fake = Fake()
        result = m3.collect(fake)
        self.assertTrue(result['mapped_data_first_block']['f2fs_superblock_magic_at_1024'])
        self.assertFalse(result['raw_userdata_first_block']['f2fs_superblock_magic_at_1024'])
        self.assertEqual(result['mapped_data_first_block']['sha256'], hashlib.sha256(fake.data).hexdigest())
        self.assertTrue(result['mapping']['direct_userdata_backing_match'])
        self.assertFalse(result['mapping']['table_geometry_verified'])
        self.assertNotIn('key', str(fake.calls))
        self.assertNotIn(bytes(fake.data), list(result.values()))

    def test_wrong_device_stops_before_reading_blocks(self):
        fake = Fake()
        fake.responses[('shell', 'getprop', 'ro.product.device')] = b'other\n'
        with self.assertRaises(RuntimeError):
            m3.collect(fake)
        self.assertFalse(any(args[0] == 'exec-out' for args in fake.calls))

    def test_unmounted_data_stops_before_reading_blocks(self):
        fake = Fake()
        fake.responses[('shell', 'cat', '/proc/mounts')] = b'/dev/block/sda17 /metadata f2fs rw 0 0\n'
        with self.assertRaises(RuntimeError):
            m3.collect(fake)
        self.assertFalse(any(args[0] == 'exec-out' for args in fake.calls))

    def test_short_block_is_rejected(self):
        fake = Fake()
        fake.responses[('exec-out', 'dd', 'if=/dev/block/dm-7', 'bs=4096', 'count=1', 'status=none')] = b'partial'
        with self.assertRaises(RuntimeError):
            m3.collect(fake)


if __name__ == '__main__':
    unittest.main()
