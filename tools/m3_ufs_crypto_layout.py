"""Host-only candidate UFS crypto read-header layout; never submits I/O."""
import struct


def make_candidate_read_header(slot, slot_count, dun):
    """Return four synthetic LE UTRD words; slot_count must be supplied.

    This generic layout has not been validated against fuxi's crypto path.
    No key material, physical addresses or actual hardware access are involved.
    """
    for value in (slot, slot_count, dun):
        if type(value) is not int:
            raise ValueError('integer required')
    if not 1 <= slot_count <= 256 or not 0 <= slot < slot_count:
        raise ValueError('slot outside supplied candidate capability')
    if not 0 <= dun < (1 << 64):
        raise ValueError('DUN outside 64-bit range')
    return struct.pack('<IIII', 0x14800000 | slot, dun & 0xffffffff,
                       0x0f, dun >> 32)
