"""Tests of synthetic headers, not a hardware compatibility test."""
import struct
import unittest
from m3_ufs_crypto_layout import make_candidate_read_header


class CandidateLayoutTests(unittest.TestCase):
    def test_little_endian_vector(self):
        self.assertEqual(make_candidate_read_header(3, 8, 0x123456789abcdef0),
                         bytes.fromhex('03008014f0debc9a0f00000078563412'))

    def test_zero_and_maximum(self):
        self.assertEqual(struct.unpack('<IIII', make_candidate_read_header(0, 1, 0)),
                         (0x14800000, 0, 15, 0))
        self.assertEqual(struct.unpack('<IIII', make_candidate_read_header(255, 256, (1 << 64)-1)),
                         (0x148000ff, 0xffffffff, 15, 0xffffffff))

    def test_bad_capability_or_slot(self):
        for slot, count in ((0, 0), (0, 257), (-1, 1), (1, 1), (256, 256)):
            with self.subTest(slot=slot, count=count), self.assertRaises(ValueError):
                make_candidate_read_header(slot, count, 0)

    def test_bad_types_and_dun(self):
        for args in ((True, 1, 0), (0, True, 0), (0, 1, False),
                     (0, 1, -1), (0, 1, 1 << 64), (0, 1, 1.0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                make_candidate_read_header(*args)


if __name__ == '__main__':
    unittest.main()
