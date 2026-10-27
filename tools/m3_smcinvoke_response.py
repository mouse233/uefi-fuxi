"""Synthetic, fail-closed SMCI response inspection; no hardware access.

This is a restricted design experiment, not a production transport or a way
to determine that shared memory or objects may be freed on actual hardware.
"""
import struct
from m3_smcinvoke_layout import PAGE


class Quarantine(Exception):
    """The caller must retain resources pending a verified recovery path."""


def _remote(handle):
    return type(handle) is int and 1 < handle < 0x80000000


def inspect_object_reply(request, input_after, output_after, *, transport_ok,
                         terminal_verified, object_result):
    """Inspect only the two known single-output-object request shapes.

    transport_ok and terminal_verified must come from a future verified
    transport; this module deliberately does not infer them from raw SMC
    registers. Unknown, callback, nonempty piggyback, failure or malformed
    responses require quarantine rather than cleanup or further requests.
    """
    if transport_ok is not True or terminal_verified is not True:
        raise Quarantine('transport/terminal status not verified')
    if type(object_result) is not int or object_result != 0:
        raise Quarantine('object result is not successful')
    if any(type(x) is not bytes or len(x) != PAGE
           for x in (request, input_after, output_after)):
        raise Quarantine('invalid shared buffer shape')
    handle, op, counts = struct.unpack_from('<III', request)
    if (handle, op, counts) == (1, 5, 0x1100):
        output_offset = 20
    elif _remote(handle) and (op, counts) == (0, 0x1001):
        output_offset = 20
    else:
        raise Quarantine('request shape not supported')
    # QTEE returns output object handles in the original input message.
    if input_after[:output_offset] != request[:output_offset]:
        raise Quarantine('request header or input descriptor changed')
    # Unknown piggyback data may hold local object releases.  Do not ignore it.
    if any(output_after):
        raise Quarantine('callback or piggyback data requires handling')
    result, reserved = struct.unpack_from('<II', input_after, output_offset)
    if reserved != 0 or not _remote(result):
        raise Quarantine('invalid output remote object')
    return result


def build_synthetic_release(handle):
    """Build candidate remote release bytes only; never send this message."""
    if not _remote(handle):
        raise ValueError('expected non-root remote object')
    message = bytearray(PAGE)
    struct.pack_into('<III', message, 0, handle, 0xffff, 0)
    return bytes(message)
