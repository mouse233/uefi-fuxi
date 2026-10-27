"""Host-only response and fail-closed checks against synthetic buffers."""
import struct
import unittest
from m3_smcinvoke_layout import PAGE, build_register_with_null_credentials, build_open_app_loader
from m3_smcinvoke_response import Quarantine, inspect_object_reply, build_synthetic_release


def successful_reply(req, obj=2):
    data = bytearray(req)
    struct.pack_into('<I', data, 20, obj)
    return bytes(data)


class ReplyTests(unittest.TestCase):
    def inspect(self, req, reply=None, out=None, **kw):
        return inspect_object_reply(req, successful_reply(req) if reply is None else reply,
            bytes(PAGE) if out is None else out,
            transport_ok=kw.get('transport_ok', True),
            terminal_verified=kw.get('terminal_verified', True),
            object_result=kw.get('object_result', 0))

    def test_two_output_locations_and_release(self):
        for req in (build_register_with_null_credentials(), build_open_app_loader(4)):
            self.assertEqual(self.inspect(req), 2)
        self.assertEqual(build_synthetic_release(2)[:12], bytes.fromhex('02000000ffff000000000000'))

    def test_status_must_be_verified(self):
        req = build_register_with_null_credentials()
        for kw in ({'transport_ok': False}, {'terminal_verified': False},
                   {'terminal_verified': None}, {'object_result': 1},
                   {'object_result': False}):
            with self.subTest(kw=kw), self.assertRaises(Quarantine):
                self.inspect(req, **kw)

    def test_output_objects_and_release_reject_invalid(self):
        req = build_register_with_null_credentials()
        for handle in (0, 1, 0x80000000, 0xffffffff):
            with self.subTest(handle=handle), self.assertRaises(Quarantine):
                self.inspect(req, successful_reply(req, handle))
            with self.assertRaises(ValueError):
                build_synthetic_release(handle)

    def test_unexpected_changes_and_piggyback_are_quarantined(self):
        req = build_open_app_loader(4)
        changed = bytearray(successful_reply(req)); changed[12] ^= 1
        out = bytearray(PAGE); out[8] = 1
        reserved = bytearray(successful_reply(req)); reserved[24] = 1
        for reply, output in ((bytes(changed), bytes(PAGE)),
                              (successful_reply(req), bytes(out)),
                              (bytes(reserved), bytes(PAGE)),
                              (b'short', bytes(PAGE))):
            with self.subTest(reply_len=len(reply), output_nonzero=any(output)), self.assertRaises(Quarantine):
                self.inspect(req, reply, output)

    def test_unsupported_request_is_quarantined(self):
        req = bytearray(build_register_with_null_credentials()); req[4] = 6
        with self.assertRaises(Quarantine):
            self.inspect(bytes(req))


if __name__ == '__main__':
    unittest.main()
