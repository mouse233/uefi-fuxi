#!/usr/bin/env python3
"""Isolated pinned vendor CBOR codecs on synthetic inputs; never a TA/device.

On this macOS host Unicorn must run outside the sandbox (CTR_EL0 native init).
Only the listed serializer/deserializer functions and QCBOR are executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from audit_fuxi_m3_setversion_encoder import PINS, verify
from audit_fuxi_m3_key_recovery import PINS as RECOVERY_PINS, elf_bytes


def cbor(value):
    def head(major, n):
        for limit, ai, size in ((24, 0, 0), (256, 24, 1), (65536, 25, 2), (1 << 32, 26, 4), (1 << 64, 27, 8)):
            if n < limit:
                return bytes([(major << 5) | (n if not size else ai)]) + (n.to_bytes(size, 'big') if size else b'')
        raise ValueError('integer outside uint64')
    if isinstance(value, dict):
        return head(5, len(value)) + b''.join(cbor(k) + cbor(v) for k, v in value.items())
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    return head(int(value < 0), value if value >= 0 else -1 - value)


class Codec:
    def __init__(self, libs):
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
        from unicorn import arm64_const as r
        self.r = r
        self.u = u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.qt, self.qc = 0x1000000, 0x2000000
        for name, base in [('libqtikeymint.so', self.qt), ('libqcbor.so', self.qc)]:
            raw = (libs / name).read_bytes(); verify(name, raw)
            u.mem_map(base, 0x80000)
            phoff = struct.unpack_from('<Q', raw, 32)[0]
            ents, count = struct.unpack_from('<HH', raw, 54)
            if raw[:7] != b'\x7fELF\x02\x01\x01' or ents != 56 or count > 32:
                raise ValueError('invalid pinned ELF')
            for i in range(count):
                kind, _, off, va, _, size, memory, _ = struct.unpack_from('<IIQQQQQQ', raw, phoff + i * ents)
                if kind == 1:
                    if size > memory or off + size > len(raw) or va + memory > 0x80000:
                        raise ValueError('ELF segment bounds')
                    u.mem_write(base + va, raw[off:off + size])
        u.mem_map(0x3000000, 0x100000)
        u.mem_map(0x4000000, 0x20000)
        self.this, self.params, self.blob, self.output = 0x3000000, 0x3001000, 0x3002000, 0x3003000
        self.data, self.buffer, self.stop = 0x3010000, 0x3020000, 0x300f000
        self.redirect = {self.qt + a: self.qc + b for a, b in {
            0x3de38: 0x3fd0, 0x3dee0: 0x4020, 0x3de50: 0x4040,
            0x3de68: 0x4030, 0x3de80: 0x4090, 0x3ddf0: 0x3fe0,
            0x3de08: 0x3ff0, 0x3dd78: 0x40a0, 0x3dce8: 0x40b0, 0x3dd90: 0x40c0}.items()}
        self.redirect[self.qt + 0x3ddd8] = self.qt + 0x34f4c
        # QCBOR's own PLT calls, resolved against this same pinned library.
        asm = subprocess.check_output(['/opt/homebrew/opt/llvm/bin/llvm-objdump', '-d', str(libs / 'libqcbor.so')], text=True)
        syms = subprocess.check_output(['/opt/homebrew/opt/llvm/bin/llvm-nm', '--dynamic', str(libs / 'libqcbor.so')], text=True)
        defs = {n: int(a, 16) for a, n in re.findall(r'^([0-9a-f]+) T (\S+)$', syms, re.M)}
        for address, symbol in re.findall(r'^([0-9a-f]+) <([^>]+)@plt>:', asm, re.M):
            if symbol in defs:
                self.redirect[self.qc + int(address, 16)] = self.qc + defs[symbol]
        self.libc = {self.qc + int(a, 16): n for a, n in re.findall(r'^([0-9a-f]+) <(memcpy|memmove|memset)@plt>:', asm, re.M)}
        self.heap = 0x3080000
        def hook(emu, address, size, unused):
            if address in self.redirect:
                emu.reg_write(r.UC_ARM64_REG_PC, self.redirect[address]); return
            if address in self.libc or address in (self.qt + 0x3c7a0,):
                dst, src, length = (emu.reg_read(getattr(r, 'UC_ARM64_REG_X' + str(i))) for i in range(3))
                if length > 0x10000: raise ValueError('bounded libc length')
                if length:
                    raw = bytes([src & 255]) * length if self.libc.get(address) == 'memset' else bytes(emu.mem_read(src, length))
                    emu.mem_write(dst, raw)
                emu.reg_write(r.UC_ARM64_REG_PC, emu.reg_read(r.UC_ARM64_REG_X30)); return
            if address in (self.qt + 0x3c458, self.qt + 0x3ccf8):
                size = emu.reg_read(r.UC_ARM64_REG_X0)
                if size > 0x10000 or self.heap + size > 0x3100000: raise ValueError('bounded allocation')
                emu.reg_write(r.UC_ARM64_REG_X0, self.heap); self.heap += (size + 15) & ~15
                emu.reg_write(r.UC_ARM64_REG_PC, emu.reg_read(r.UC_ARM64_REG_X30)); return
            if address in (self.qt + 0x3c728, self.qt + 0x3cdb8):
                emu.reg_write(r.UC_ARM64_REG_PC, emu.reg_read(r.UC_ARM64_REG_X30)); return
            if address == self.qt + 0x3c488:
                if emu.reg_read(r.UC_ARM64_REG_X0) != 0xbc49aa37818029db or emu.reg_read(r.UC_ARM64_REG_X1) != 0x3008000:
                    raise ValueError('unexpected codec-side CFI identity')
                emu.reg_write(r.UC_ARM64_REG_PC, emu.reg_read(r.UC_ARM64_REG_X30)); return
            if address == self.qt + 0x3d1c0:
                # Bounded host equivalent of km_memscpy; no KeyMint/TA hook.
                dst, cap, src, size = (emu.reg_read(getattr(r, 'UC_ARM64_REG_X' + str(i))) for i in range(1, 5))
                if size > cap or cap > 0x10000: raise ValueError('km_memscpy bounds')
                if size: emu.mem_write(dst, bytes(emu.mem_read(src, size)))
                emu.reg_write(r.UC_ARM64_REG_X0, size)
                emu.reg_write(r.UC_ARM64_REG_PC, emu.reg_read(r.UC_ARM64_REG_X30)); return
            if self.qt + 0x3c440 <= address < self.qt + 0x3e000 or self.qc + 0x4190 <= address < self.qc + 0x4300:
                raise ValueError('unlisted vendor import ' + hex(address))
        u.hook_add(UC_HOOK_CODE, hook)

    def call(self, entry, args):
        u, r = self.u, self.r
        u.reg_write(r.UC_ARM64_REG_SP, 0x401f000)
        u.reg_write(r.UC_ARM64_REG_TPIDR_EL0, 0x4001000)
        for i, value in enumerate(args): u.reg_write(getattr(r, 'UC_ARM64_REG_X' + str(i)), value)
        u.reg_write(r.UC_ARM64_REG_X30, self.stop)
        try:
            u.emu_start(self.qt + entry, self.stop, count=1000000)
        except Exception as error:
            raise ValueError('codec execution stopped at PC=' + hex(u.reg_read(r.UC_ARM64_REG_PC))) from error
        if u.reg_read(r.UC_ARM64_REG_PC) != self.stop or u.reg_read(r.UC_ARM64_REG_X0) != 0:
            raise ValueError('vendor codec did not complete successfully')

    def encode(self, kind, handle, blob, appid, nonce, data):
        u = self.u
        u.mem_write(self.this, struct.pack('<Q', self.qt + 0x3e870))
        u.mem_write(self.blob, struct.pack('<QQ', self.data, len(blob)))
        u.mem_write(self.data, blob)
        u.mem_write(self.output, struct.pack('<QQ', self.buffer, 0x8000))
        vals = [(0x20000004, 32), (0x20000006, 1), (0x300003eb, 128),
                (0x90000259, 0), (0x900003e9, 0)]
        params = b''
        for i, (tag, value) in enumerate(vals):
            if i >= 3:
                raw = appid if i == 3 else nonce
                ptr = self.data + 0x3000 + i * 0x100
                u.mem_write(ptr, raw)
                params += struct.pack('<IIQQ', tag, 0, ptr, len(raw))
            else: params += struct.pack('<IIQQ', tag, 0, value, 0)
        u.mem_write(self.params + 0x100, params)
        u.mem_write(self.params, struct.pack('<QQ', self.params + 0x100, 5))
        if kind == 'begin': self.call(0x367b4, [self.this, 1, self.params, self.blob, self.output])
        elif kind == 'update':
            u.mem_write(self.blob, struct.pack('<QQ', self.data, len(data))); u.mem_write(self.data, data)
            self.call(0x36ddc, [self.this, handle, 0, self.blob, self.output])
        elif kind == 'finish': self.call(0x374bc, [self.this, handle, 0, 0, 0, self.output])
        else: self.call(0x37b68, [self.this, handle, self.output])
        length = struct.unpack('<Q', u.mem_read(self.output + 8, 8))[0]
        if length > 0x8000: raise ValueError('vendor output bound')
        return bytes(u.mem_read(self.buffer, length))

    def decode(self, kind, raw, handle, data, consumed):
        u = self.u
        u.mem_write(self.this, struct.pack('<Q', self.qt + 0x3e870))
        u.mem_write(self.this + 16, struct.pack('<Q', 0x3008000))
        u.mem_write(0x3008000, struct.pack('<Q', 0x3008000))
        u.mem_write(self.data, raw)
        u.mem_write(self.output, bytes(64))
        if kind == 'begin':
            self.call(0x36a04, [self.this, self.data, len(raw), self.output, self.output + 32])
            if struct.unpack('<Q', u.mem_read(self.output + 32, 8))[0] != handle: raise ValueError('vendor handle mismatch')
        else:
            entry = 0x36fb0 if kind == 'update' else 0x376b8
            self.call(entry, [self.this, self.data, len(raw), self.output, self.output + 16, self.output + 32])
            ptr, size = struct.unpack('<QQ', u.mem_read(self.output + 16, 16))
            if size != len(data) or (size and bytes(u.mem_read(ptr, size)) != data): raise ValueError('vendor output mismatch')
            if kind == 'update' and struct.unpack('<Q', u.mem_read(self.output + 32, 8))[0] != consumed:
                raise ValueError('vendor consumption mismatch')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ramdisk', type=Path, required=True)
    p.add_argument('--partition', type=Path, required=True)
    p.add_argument('--recovery', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); libs = a.ramdisk / 'vendor/lib64'
    for name in ('libqtikeymint.so', 'libqcbor.so'): verify(name, (libs / name).read_bytes())
    verify('libkeymasterdeviceutils.so', (libs / 'libkeymasterdeviceutils.so').read_bytes())
    if hashlib.sha256(a.recovery.read_bytes()).hexdigest() != RECOVERY_PINS['recovery']: raise ValueError('fixed recovery mismatch')
    ta = a.partition.read_bytes()
    if hashlib.sha256(ta).hexdigest() != RECOVERY_PINS['partition']: raise ValueError('fixed TA mismatch')
    table = elf_bytes(ta, 0x5a5e0, 89 * 16)
    commands = {struct.unpack_from('<IIQ', table, i * 16)[0]: struct.unpack_from('<IIQ', table, i * 16)[2] for i in range(89)}
    for lo, hi in ((0x210f, 0x310f), (0x2111, 0x3111), (0x2112, 0x3112), (0x2113, 0x3113)):
        if commands[lo] != commands[hi]: raise ValueError('TA alias changed')
    a.output.mkdir(parents=True, exist_ok=True)
    (a.output / 'audit.json').write_text(json.dumps(dict(result='running', source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())) + '\n')
    ranges = {
        'aidl-begin': ('libqtikeymint.so', 0x1b118, 0x1b138, ['keymint_begin_operation']),
        'aidl-update': ('libqtikeymint.so', 0x1f570, 0x1f594, ['keymint_update_operation']),
        'aidl-finish': ('libqtikeymint.so', 0x1f8b0, 0x1f8d4, ['keymint_finish_operation']),
        'aidl-abort': ('libqtikeymint.so', 0x1fa40, 0x1fa60, ['abort_operation']),
        'command-begin': ('libqtikeymint.so', 0x31e54, 0x31e90, ['#0x310f', 'serializeClientBegin']),
        'command-update': ('libqtikeymint.so', 0x32260, 0x3229c, ['#0x3111', 'serializeClientUpdate']),
        'command-finish': ('libqtikeymint.so', 0x32428, 0x32468, ['#0x3112', 'serializeClientFinish']),
        'command-abort': ('libqtikeymint.so', 0x2fe28, 0x30000, ['#0x2113', '#0x2513', 'serializeClientAbort']),
        'signed-parameter-label': ('libqtikeymint.so', 0x34f4c, 0x34fdc, ['ldrsw x2, [x1]', 'QCBOREncode_AddBytes']),
        'legacy-selector': ('libkeymasterdeviceutils.so', 0x6708, 0x6734, ['cmp w9, #0x4', 'cmp w8, #0x0']),
        'recovery-security-level': ('recovery', 0x250200, 0x250224, ['mov w1, #0x1', 'blr x9']),
        'binding-initialize': ('recovery', 0x247aec, 0x247b14, ['stp q0, q0, [x0]', 'str x0, [x8, #0x398]']),
        'binding-first-use': ('recovery', 0x24b1dc, 0x24b210, ['cmp w9, #0x1', 'mov w9, #0x2', 'str w9, [x8, #0x18]']),
    }
    evidence = {}
    for name, (library, lo, hi, tokens) in ranges.items():
        file = a.recovery if library == 'recovery' else libs / library
        asm = subprocess.check_output(['/opt/homebrew/opt/llvm/bin/llvm-objdump', '-d', f'--start-address={lo}', f'--stop-address={hi}', str(file)], text=True)
        normalized = re.sub(r'[\t ]+', ' ', asm)
        if not all(token in normalized for token in tokens): raise ValueError('fixed call-chain range mismatch: ' + name)
        (a.output / (name + '.asm')).write_text(asm)
        evidence[name] = dict(input=library, start=hex(lo), end=hex(hi), sha256=hashlib.sha256(asm.encode()).hexdigest())
    codec = Codec(libs)
    rows = []
    for handle, size in ((1, 1), (0x1020304050607080, 208), ((1 << 64) - 1, 4096)):
        blob = bytes(i % 251 for i in range(size)); appid = bytes(range(64)); nonce = bytes(range(12)); data = bytes(range(32))
        params = {22: 6, 0x20000004: 32, 0x20000006: 1, 0x300003eb: 128,
                  -0x6ffffda7: appid, -0x6ffffc17: nonce, 0x20000001: 1, 23: blob}
        for kind, value in [('begin', params), ('update', {34: handle, 35: data}), ('finish', {34: handle}), ('abort', {34: handle})]:
            raw = codec.encode(kind, handle, blob, appid, nonce, data)
            if raw != cbor(value): raise ValueError('independent CBOR mismatch: ' + kind)
            name = f'{kind}-{size}.bin'; (a.output / name).write_bytes(raw)
            rows.append(dict(kind=kind, handle=handle, blob_bytes=size, file=name, sha256=hashlib.sha256(raw).hexdigest()))
    responses = []
    for kind, value in [('begin', {22: 0, 34: 0x1020304050607080}),
                        ('update', {22: 0, 36: bytes(range(32)), 37: 48}),
                        ('finish', {22: 0, 36: bytes(range(32))})]:
        raw = cbor(value)
        codec.decode(kind, raw, 0x1020304050607080, bytes(range(32)), 48)
        name = kind + '-response.bin'; (a.output / name).write_bytes(raw)
        responses.append(dict(kind=kind, file=name, sha256=hashlib.sha256(raw).hexdigest()))
    report = dict(result='passed', cases=len(rows)+len(responses), vectors=rows, responses=responses, input_sha256={n: PINS[n] for n in PINS}, evidence=evidence,
                  recovery_sha256=RECOVERY_PINS['recovery'], empty_seed_verified=False,
                  partition_sha256=RECOVERY_PINS['partition'], ta_aliases={hex(c): hex(commands[c]) for c in (0x210f,0x2111,0x2112,0x2113,0x310f,0x3111,0x3112,0x3113)},
                  scope='Pinned vendor/QCBOR request encoding and three response decoders versus synthetic vectors. Bounded libc/allocation/km_memscpy hooks and a fixed codec-side CFI identity shim; no KeyMint/TA/authentication hooks. No TA, transport, device, actual binding context or recovered key.',
                  source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (a.output / 'audit.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(result='passed', cases=report['cases'])))


if __name__ == '__main__': main()
