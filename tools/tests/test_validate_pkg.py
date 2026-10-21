"""Regression cases that must turn a dangerous configuration into a CI failure."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAP = "Platforms/Xiaomi/fuxiPkg/Library/MemoryMapLib/MemoryMapLib.c"
CONFIG = "Resources/Configs/fuxi.toml"
DSC = "Platforms/Xiaomi/fuxiPkg/fuxi.dsc"


class ValidatePkgTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / "Platforms/Xiaomi/fuxiPkg", self.root / "Platforms/Xiaomi/fuxiPkg")
        (self.root / "Resources/Configs").mkdir(parents=True)
        shutil.copy(ROOT / CONFIG, self.root / CONFIG)

    def change(self, path, before, after):
        p = self.root / path
        text = p.read_text()
        self.assertIn(before, text)
        p.write_text(text.replace(before, after, 1))

    def check(self, expected=None):
        result = subprocess.run([sys.executable, str(ROOT / "tools/validate_pkg.py"), str(self.root)],
                                capture_output=True, text=True)
        if expected is None:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(expected, result.stdout)

    def test_baseline(self):
        self.check()

    def test_overlap_is_error(self):
        self.change(MAP, '0xA7400000, 0x00200000', '0xA7300000, 0x00200000')
        self.check("overlap:")

    def test_unaligned_region(self):
        self.change(MAP, '0xA7400000, 0x00200000', '0xA7400001, 0x00200000')
        self.check("not 4 KiB aligned")

    def test_zero_region(self):
        self.change(MAP, '0xA7400000, 0x00200000', '0xA7400000, 0x00000000')
        self.check("invalid memory range")

    def test_missing_table(self):
        self.change(MAP, 'gMemoryDescriptor[]', 'gUnexpectedDescriptor[]')
        self.check("table missing")

    def test_unparsed_row(self):
        self.change(MAP, '0xA7400000, 0x00200000', 'UNKNOWN_BASE, 0x00200000')
        self.check("non-literal memory range")

    def test_fd_base_disagreement(self):
        self.change(CONFIG, 'base = 0xA7100000', 'base = 0xA7000000')
        self.check("FD base/size disagree")

    def test_fd_size_disagreement(self):
        self.change(CONFIG, 'size = 0x300000', 'size = 0x400000')
        self.check("FD base/size disagree")

    def test_wrong_boot_header(self):
        self.change(CONFIG, 'header_version = 3\n', 'header_version = 0\n')
        self.check("header version 3")

    def test_stack_outside_reservation(self):
        self.change(DSC, 'PcdCPUCorePrimaryStackSize|0x40000', 'PcdCPUCorePrimaryStackSize|0x80000')
        self.check("stack PCD range exceeds")

    def test_framebuffer_too_large(self):
        self.change(DSC, 'PcdFrameBufferWidth|1080', 'PcdFrameBufferWidth|100000')
        self.check("framebuffer geometry exceeds")

    def test_unmapped_spmi(self):
        self.change(MAP, '0x0B000000, 0x04000000', '0x0B000000, 0x00100000')
        self.check("has no mapped MMIO")

    def test_spmi_core_window_truncated(self):
        self.change(MAP, '0x0B000000, 0x04000000', '0x0B000000, 0x01401000')
        self.check("SPMI_CORE_BASE")

    def test_spmi_observer_window_truncated(self):
        self.change(MAP, '0x0B000000, 0x04000000', '0x0B000000, 0x01444000')
        self.check("SPMI_OBSRVR_BASE")

    def test_missing_dsc_component(self):
        self.change(DSC, '  fuxiPkg/Drivers/FuxiKeyInputDxe/FuxiKeyInputDxe.inf',
                    '  fuxiPkg/Drivers/FuxiKeyInputDxe/Missing.inf')
        self.check("referenced INF missing")


if __name__ == "__main__":
    unittest.main()
