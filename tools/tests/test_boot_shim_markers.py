"""Execute only our shim and synthetic data in Unicorn; never phone firmware.

Cache/barrier operations are observed and modeled as no-ops. CTR_EL0 is supplied
by the harness. This verifies dataflow/ranges, not physical display or coherency.
Install unicorn==2.1.4 and capstone==5.0.9 for the dedicated marker check.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
TOOLS = all(shutil.which(t) for t in ('clang', 'llvm-objcopy', 'llvm-nm'))
LIBS = all(importlib.util.find_spec(m) is not None for m in ('unicorn','capstone'))
if os.environ.get('FUXI_REQUIRE_MARKER_TESTS')=='1' and not (TOOLS and LIBS):
    raise RuntimeError('Required BootShim simulator dependencies are missing')


@unittest.skipUnless(TOOLS and LIBS, 'dedicated check needs clang/llvm, Unicorn and Capstone')
class BootShimMarkerTests(unittest.TestCase):
    def compile(self, enabled, fd_size=4096, framebuffer=0xb8000000):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder = Path(temp.name)
        flags = ['-DREQUIRES_KERNEL_HEADER=1','-DFD_BASE=0xa7100000',f'-DFD_SIZE={fd_size}',
                 f'-DBOOT_STAGE_MARKERS={int(enabled)}',f'-DMARKER_FB_BASE={framebuffer}',
                 '-DMARKER_FB_SIZE=0x2b00000','-DMARKER_BAND_SIZE=0x40000']
        proc = subprocess.run(['clang','--target=aarch64-linux-gnu','-I',str(ROOT/'BootShim'),
                               '-c',str(ROOT/'BootShim/BootShim.S'),'-o',str(folder/'shim.o'),*flags],
                              capture_output=True,text=True)
        if proc.returncode:
            raise ValueError(proc.stderr)
        subprocess.run(['llvm-objcopy','-O','binary',str(folder/'shim.o'),str(folder/'shim.bin')],check=True)
        symbols = {}
        for line in subprocess.check_output(['llvm-nm','-n',str(folder/'shim.o')],text=True).splitlines():
            pieces = line.split()
            if len(pieces)==3:
                symbols[pieces[2]]=int(pieces[0],16)
        return (folder/'shim.bin').read_bytes(), symbols

    def test_disabled_is_byte_identical_to_prior_3mib_shim(self):
        blob,symbols=self.compile(False,0x300000)
        self.assertEqual(len(blob),192)
        self.assertEqual(hashlib.sha256(blob).hexdigest(),'f7ee5e091c70ece86710bcc99256974a66b41134b5b07d77ceea2cfa9f758d16')
        self.assertNotIn('_Stage1Marker',symbols)

    def test_wrong_framebuffer_rejected_at_assembly(self):
        with self.assertRaisesRegex(ValueError,'audited fuxi framebuffer'):
            self.compile(True,framebuffer=0xb9000000)

    def test_make_rebuilds_when_marker_switch_changes(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder=Path(temp.name)
        for name in ('BootShim.S','StageMarkers.inc','Makefile'):
            shutil.copyfile(ROOT/'BootShim'/name,folder/name)
        base=['make','REQUIRES_KERNEL_HEADER=1','FD_BASE=0xa7100000','FD_SIZE=0x300000',
              'MARKER_FB_BASE=0xb8000000','MARKER_FB_SIZE=0x2b00000','MARKER_BAND_SIZE=0x40000']
        subprocess.run([*base,'BOOT_STAGE_MARKERS=1'],cwd=folder,check=True,capture_output=True)
        self.assertNotEqual(len((folder/'BootShim.bin').read_bytes()),192)
        subprocess.run([*base,'BOOT_STAGE_MARKERS=0'],cwd=folder,check=True,capture_output=True)
        self.assertEqual(hashlib.sha256((folder/'BootShim.bin').read_bytes()).hexdigest(),
                         'f7ee5e091c70ece86710bcc99256974a66b41134b5b07d77ceea2cfa9f758d16')

    def emulate(self,enabled,in_place=False,line_bytes=64,fd_size=4096):
        import capstone
        import unicorn
        from unicorn import arm64_const as regs
        blob,symbols=self.compile(enabled,fd_size)
        fd_base=0xa7100000
        fb_base=0xb8000000
        band=0x40000
        source=fd_base-len(blob) if in_place else 0xa8080000
        payload=bytes(range(256))*(fd_size//256)
        cpu=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM)
        cpu.mem_map(fd_base-4096,fd_size+8192)
        if not in_place:
            cpu.mem_map(source,(len(blob)+len(payload)+4095)//4096*4096)
        cpu.mem_map(fb_base-4096,2*band+8192)
        cpu.mem_write(fb_base-4096,b'\xa5'*(2*band+8192))
        cpu.mem_write(source,blob+payload)
        decoder=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)
        # ARM64 headers/literal pools contain data. Decode individual words so
        # an invalid data word cannot hide later executable instructions.
        instructions={i.address:i for offset in range(0,symbols['_Payload'],4)
                      for i in decoder.disasm(blob[offset:offset+4],source+offset)}
        preserved={regs.UC_ARM64_REG_X0:0x1234567890, regs.UC_ARM64_REG_SP:0xdead000000,
                   regs.UC_ARM64_REG_X18:0x181818, regs.UC_ARM64_REG_X20:0x202020,
                   regs.UC_ARM64_REG_X30:0x303030}
        for register,value in preserved.items():
            cpu.reg_write(register,value)
        state={'reached_fd':False,'fd_bytes_written':0,'fb_bytes_written':0,'cleans':[], 'stage_order':[]}
        def code_hook(engine,address,size,user):
            if address==fd_base:
                state['reached_fd']=True
                engine.emu_stop()
                return
            for label in ('_Stage1Marker','_Stage2Marker'):
                if enabled and address==source+symbols[label]:
                    state['stage_order'].append(label)
            instruction=instructions.get(address)
            if instruction is None:
                raise AssertionError(f'Execution outside shim at {address:#x}')
            if instruction.mnemonic=='mrs' and instruction.op_str.endswith('ctr_el0'):
                register=instruction.op_str.split(',')[0].upper()
                # DminLine encodes log2(bytes/4).
                engine.reg_write(getattr(regs,'UC_ARM64_REG_'+register),((line_bytes//4).bit_length()-1)<<16)
                engine.reg_write(regs.UC_ARM64_REG_PC,address+4)
            elif instruction.mnemonic in ('dc','ic','dsb','isb'):
                if instruction.mnemonic=='dc':
                    register=instruction.op_str.split(',')[1].strip().upper()
                    state['cleans'].append(engine.reg_read(getattr(regs,'UC_ARM64_REG_'+register)))
                engine.reg_write(regs.UC_ARM64_REG_PC,address+4)
        def write_hook(engine,access,address,size,value,user):
            self.assertEqual(engine.reg_read(regs.UC_ARM64_REG_X0),preserved[regs.UC_ARM64_REG_X0])
            if fd_base <= address and address+size <= fd_base+len(payload):
                state['fd_bytes_written']+=size
            elif enabled and fb_base <= address and address+size <= fb_base+2*band:
                state['fb_bytes_written']+=size
            else:
                raise AssertionError(f'Unexpected memory write: {address:#x}+{size}')
        cpu.hook_add(unicorn.UC_HOOK_CODE,code_hook)
        cpu.hook_add(unicorn.UC_HOOK_MEM_WRITE,write_hook)
        cpu.emu_start(source,0,count=2000000)
        self.assertTrue(state['reached_fd'],'shim failed to branch to the synthetic FD')
        for register,value in preserved.items():
            self.assertEqual(cpu.reg_read(register),value)
        self.assertEqual(bytes(cpu.mem_read(fd_base,len(payload))),payload)
        self.assertEqual(state['fd_bytes_written'],0 if in_place else len(payload))
        self.assertEqual(bytes(cpu.mem_read(fb_base-4096,4096)),b'\xa5'*4096)
        self.assertEqual(bytes(cpu.mem_read(fb_base+2*band,4096)),b'\xa5'*4096)
        self.assertEqual(struct.unpack_from('<Q',blob,16)[0],len(blob)+len(payload))
        self.assertEqual(symbols['_Payload'],len(blob))
        if enabled:
            self.assertEqual(state['stage_order'],['_Stage1Marker','_Stage2Marker'])
            self.assertEqual(state['fb_bytes_written'],2*band)
            self.assertEqual(bytes(cpu.mem_read(fb_base,band)),b'\xff'*band)
            self.assertEqual(bytes(cpu.mem_read(fb_base+band,band)),b'\x80'*band)
            self.assertEqual([a for a in state['cleans'] if fb_base<=a<fb_base+2*band],
                             list(range(fb_base,fb_base+2*band,line_bytes)))
        else:
            self.assertEqual(state['fb_bytes_written'],0)
            self.assertEqual(bytes(cpu.mem_read(fb_base,2*band)),b'\xa5'*(2*band))

    def test_markers_copy_and_registers(self):
        self.emulate(True)

    def test_markers_in_place_copy_bypass(self):
        self.emulate(True,in_place=True)

    def test_markers_128_byte_cache_lines(self):
        self.emulate(True,line_bytes=128)

    def test_markers_real_3mib_copy_length(self):
        self.emulate(True,fd_size=0x300000)

    def test_disabled_never_writes_framebuffer(self):
        self.emulate(False)


@unittest.skipUnless(importlib.util.find_spec('coloredlogs'), 'build CLI checks need coloredlogs')
class MarkerBuildScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('marker_build_uefi',ROOT/'build_uefi.py')
        cls.builder=importlib.util.module_from_spec(spec)
        sys.modules[spec.name]=cls.builder
        spec.loader.exec_module(cls.builder)

    def context(self,device='fuxi',mode='DEBUG',enabled=True):
        return self.builder.BuildContext(device,0,mode,False,False,False,enabled)

    def config(self):
        import tomllib
        return tomllib.loads((ROOT/'Resources/Configs/fuxi.toml').read_text())

    def test_marker_flag_rejects_other_devices_and_release(self):
        for device,mode in [('fuxi','RELEASE'),('pipa','DEBUG')]:
            with self.subTest(device=device,mode=mode):
                proc=subprocess.run([sys.executable,str(ROOT/'build_uefi.py'),'-d',device,'-r',mode,'--boot-stage-markers'],capture_output=True,text=True)
                self.assertEqual(proc.returncode,2)
                self.assertIn('requires -d fuxi -r DEBUG',proc.stderr)

    def test_audited_config_accepted_only_on_opt_in(self):
        config=self.config()
        self.assertEqual(self.builder.get_boot_stage_marker_config(self.context(),config),config['boot_shim']['stage_markers'])
        self.assertIsNone(self.builder.get_boot_stage_marker_config(self.context(enabled=False),config))

    def test_changed_region_or_band_is_rejected(self):
        for key in ('framebuffer_base','framebuffer_size','band_size'):
            with self.subTest(key=key):
                config=self.config()
                config['boot_shim']['stage_markers'][key]+=4096
                with self.assertRaises(ValueError):
                    self.builder.get_boot_stage_marker_config(self.context(),config)

    def test_make_receives_disabled_switch_explicitly(self):
        with mock.patch.object(self.builder.subprocess,'run',return_value=mock.Mock(returncode=0)) as run:
            self.assertTrue(self.builder.compile_boot_shim({'requires_kernel_header':True},{'base':0xa7100000,'size':0x300000}))
        self.assertIn('BOOT_STAGE_MARKERS=0',run.call_args.args[0])
        self.assertFalse(any(arg.startswith('MARKER_FB_BASE=') for arg in run.call_args.args[0]))


if __name__=='__main__':
    unittest.main()
