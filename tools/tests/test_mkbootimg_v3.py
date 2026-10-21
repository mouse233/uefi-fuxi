"""Independent AOSP writer comparisons for the Mu v3 helper."""
import contextlib
import gzip
import importlib.util
import io
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('mkbootimg_v3', ROOT/'tools/mkbootimg_v3.py')
v3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v3)


class BootV3Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.kernel = self.work/'gzip'
        self.dtb = self.work/'dtb'
        self.ramdisk = self.work/'ramdisk'
        self.kernel.write_bytes(gzip.compress(b'shim-and-fd-fixture'*41, mtime=0))
        # Container tests only: a small synthetic FDT-header fixture.
        self.dtb.write_bytes(struct.pack('>II',0xd00dfeed,40)+bytes(32))

    def aosp(self, data):
        self.ramdisk.write_bytes(data)
        (self.work/'field').write_bytes(self.kernel.read_bytes()+self.dtb.read_bytes())
        subprocess.run([sys.executable,str(ROOT/'Resources/Scripts/mkbootimg.py'),
                        '--header_version','3','--kernel',str(self.work/'field'),
                        '--ramdisk',str(self.ramdisk),'-o',str(self.work/'aosp.img')],
                       check=True, capture_output=True)
        return self.work/'aosp.img'

    def test_pack_matches_independent_aosp_writer(self):
        for size in (0,1,4095,4096,4097):
            with self.subTest(ramdisk_size=size):
                expected = self.aosp(b'R'*size).read_bytes()
                with contextlib.redirect_stdout(io.StringIO()):
                    v3.pack(str(self.kernel),str(self.dtb),str(self.ramdisk),str(self.work/'ours.img'))
                self.assertEqual((self.work/'ours.img').read_bytes(),expected)

    def test_unpack_aosp_ramdisk_at_page_boundary(self):
        expected = bytes(range(256))*17
        image = self.aosp(expected)
        with contextlib.redirect_stdout(io.StringIO()):
            v3.unpack(str(image),str(self.work/'unpacked'))
        self.assertEqual((self.work/'unpacked/ramdisk').read_bytes(),expected)
        self.assertEqual((self.work/'unpacked/kernel').read_bytes(),self.kernel.read_bytes())
        self.assertEqual((self.work/'unpacked/dtb').read_bytes(),self.dtb.read_bytes())

    def test_parse_rejects_incomplete_header(self):
        path = self.work/'bad.img'
        for content in (b'',b'ANDROID!', b'ANDROID!'+bytes(100)):
            with self.subTest(size=len(content)):
                path.write_bytes(content)
                with self.assertRaises(ValueError):
                    v3.parse(path)

    def test_parse_rejects_wrong_version_or_header_size(self):
        original = self.aosp(b'dummy').read_bytes()
        for offset,value in ((40,0),(40,4),(20,0),(20,4096)):
            with self.subTest(offset=offset,value=value):
                data = bytearray(original)
                struct.pack_into('<I',data,offset,value)
                (self.work/'bad.img').write_bytes(data)
                with self.assertRaises(ValueError):
                    v3.parse(self.work/'bad.img')

    def test_parse_rejects_truncated_payload(self):
        original = self.aosp(b'dummy').read_bytes()
        (self.work/'bad.img').write_bytes(original[:-1])
        with self.assertRaises(ValueError):
            v3.parse(self.work/'bad.img')


if __name__ == '__main__':
    unittest.main()
