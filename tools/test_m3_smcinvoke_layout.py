#!/usr/bin/env python3
"""Host-only checks of restricted SMCI message prototypes."""
import struct
import unittest
from m3_smcinvoke_layout import build_register_with_null_credentials, build_open_app_loader, PAGE


class LayoutTests(unittest.TestCase):
    def test_register_exact_layout(self):
        b = build_register_with_null_credentials()
        self.assertEqual(len(b), PAGE)
        self.assertEqual(b[:28], struct.pack('<IIIQQ', 1, 5, 0x1100, 0, 0))
        self.assertFalse(any(b[28:]))

    def test_open_exact_layout(self):
        b = build_open_app_loader(2)
        self.assertEqual(len(b), PAGE)
        self.assertEqual(b[:36], struct.pack('<IIIIIQII', 2, 0, 0x1001, 32, 4, 0, 0, 122))
        self.assertFalse(any(b[36:]))

    def test_reject_untrusted_handles(self):
        for handle in (None, True, -1, 0, 1, 0x80000000, 0xffffffff, 0x100000000):
            with self.subTest(handle=handle), self.assertRaises(ValueError):
                build_open_app_loader(handle)

    def test_largest_remote_handle(self):
        self.assertEqual(struct.unpack_from('<I', build_open_app_loader(0x7fffffff))[0], 0x7fffffff)


if __name__ == '__main__':
    unittest.main()
