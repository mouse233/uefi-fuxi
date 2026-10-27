#!/usr/bin/env python3
"""Host-only SMCI layout prototypes; never connects to a device or invokes SMC.

These encode two candidate object messages using the public SM8550 reference.
They are not authorization to use those messages on hardware; exact firmware
ABI, responses, callbacks and shared memory remain unverified.
"""
import struct

PAGE = 4096
ROOT_HANDLE = 1
NULL_HANDLE = 0
APP_LOADER_UID = 122
REGISTER_WITH_CREDENTIALS = 5
CLIENT_ENV_OPEN = 0


def _u32(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xffffffff:
        raise ValueError(label + ' must be an unsigned 32-bit integer')
    return value


def _write_header(buffer, handle, operation, counts):
    struct.pack_into('<III', buffer, 0, handle, operation, counts)


def build_register_with_null_credentials():
    """Create a synthetic root register request with one null input object."""
    buf = bytearray(PAGE)
    # BI=0, BO=0, OI=1, OO=1; each descriptor occupies 8 bytes.
    _write_header(buf, ROOT_HANDLE, REGISTER_WITH_CREDENTIALS, 0x1100)
    struct.pack_into('<I', buf, 12, NULL_HANDLE)
    return bytes(buf)


def build_open_app_loader(client_env_handle):
    """Create a synthetic open request; requires a non-root remote handle."""
    handle = _u32(client_env_handle, 'client_env_handle')
    if handle <= ROOT_HANDLE or handle & 0x80000000:
        raise ValueError('client environment handle must be a non-root remote object')
    buf = bytearray(PAGE)
    # BI=1, BO=0, OI=0, OO=1; data begins at the next 8-byte boundary.
    _write_header(buf, handle, CLIENT_ENV_OPEN, 0x1001)
    struct.pack_into('<II', buf, 12, 32, 4)
    struct.pack_into('<I', buf, 32, APP_LOADER_UID)
    return bytes(buf)
