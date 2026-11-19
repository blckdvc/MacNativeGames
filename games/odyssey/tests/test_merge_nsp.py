"""merge_nsp.py: an XCI base, and a card image's built-in update replaced by the update NSP (synthetic containers only)."""
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GAME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GAME / "third_party" / "totk-scripts"))

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from extract_exefs import partition_entries
except ImportError:   # the build's venv has it; a bare CI Python may not
    Cipher = None

BASE, UPDATE = 0x0100000000010000, 0x0100000000010800
RIGHTS = UPDATE.to_bytes(8, "big") + bytes(7) + b"\x04"


def table(magic, stride, files):
    strings = b"".join(name.encode() + b"\0" for name, _ in files)
    strings += b"\0" * (-(16 + stride * len(files) + len(strings)) % 0x20)
    rows, offset, name_at = b"", 0, 0
    for name, data in files:
        row = struct.pack("<QQI", offset, len(data), name_at)
        rows += row + b"\0" * (stride - len(row))
        offset += len(data)
        name_at += len(name) + 1
    return magic + struct.pack("<II", len(files), len(strings)) + b"\0" * 4 + rows + strings + b"".join(d for _, d in files)


@unittest.skipIf(Cipher is None, "needs the cryptography module")
class MergeNsp(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="odyssey-merge-nsp-")
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.header_key = os.urandom(32)   # a random test key, not a console's
        self.keys = self.dir / "test.keys"
        self.area_key = os.urandom(16)
        self.keys.write_text(f"header_key = {self.header_key.hex()}\nkey_area_key_application_00 = {self.area_key.hex()}\n")

    def nca(self, title_id, size, rights=bytes(16), kind=0, body=None, fs=None):
        header = bytearray(0xC00)
        header[0x200:0x204] = b"NCA3"
        header[0x205] = kind
        struct.pack_into("<QQ", header, 0x208, size, title_id)
        header[0x230:0x240] = rights
        if fs:   # one section from 0xC00 to the end, its FS header and that header's hash; its key in the key area
            header[0x300:0x340] = self._area
            struct.pack_into("<II", header, 0x240, 6, size // 512)
            header[0x280:0x2A0] = hashlib.sha256(fs).digest()
            header[0x400:0x600] = fs
        out = b""
        for sector in range(6):
            ctx = Cipher(algorithms.AES(self.header_key), modes.XTS(sector.to_bytes(16, "big"))).encryptor()
            out += ctx.update(bytes(header[sector * 512:(sector + 1) * 512])) + ctx.finalize()
        return out + (body if body is not None else os.urandom(size - 0xC00))

    def meta(self, content_ids):
        """An update's Meta NCA: a key-area AES-CTR PFS0 section holding the .cnmt that lists content_ids."""
        cnmt = struct.pack("<QIBBHHH", UPDATE, 0, 0x81, 0, 0x10, len(content_ids), 0) + bytes(12) + bytes(0x10)
        for content_id in content_ids:
            cnmt += os.urandom(0x20) + content_id + bytes(8)
        pfs = table(b"PFS0", 24, [("Patch_0100000000010800.cnmt", cnmt)])
        hashes = hashlib.sha256(pfs).digest()
        fs = bytearray(0x200)
        fs[2:5] = b"\x01\x02\x03"
        fs[8:40] = hashlib.sha256(hashes).digest()
        struct.pack_into("<II", fs, 0x28, 0x1000, 2)
        struct.pack_into("<QQQQ", fs, 0x30, 0, 0x20, 0x200, len(pfs))
        fs[0x140:0x148] = os.urandom(8)
        plain = hashes + bytes(0x200 - 0x20) + pfs
        plain += bytes(-len(plain) % 512)
        title_key = os.urandom(16)
        iv = bytes(fs[0x140:0x148])[::-1] + (0xC00 // 16).to_bytes(8, "big")
        ctx = Cipher(algorithms.AES(title_key), modes.CTR(iv)).encryptor()
        body = ctx.update(plain) + ctx.finalize()
        ctx = Cipher(algorithms.AES(self.area_key), modes.ECB()).encryptor()
        area = ctx.update(os.urandom(32) + title_key + os.urandom(16)) + ctx.finalize()
        self._area = area
        return self.nca(UPDATE, 0xC00 + len(body), kind=1, body=body, fs=bytes(fs))

    def update(self, name):
        """An update as a card carries it: besides the Program under the update's rights ID, a Control NCA with the base
        title's ID and no rights ID, which only the Meta NCA's content list ties to the update."""
        program, control = os.urandom(16), os.urandom(16)
        return [(program.hex() + ".nca", self.nca(BASE, 6000, RIGHTS)),
                (control.hex() + ".nca", self.nca(BASE, 4608, kind=2)),
                (f"{name}.cnmt.nca", self.meta([program, control])),
                (RIGHTS.hex() + ".tik", os.urandom(704)), (RIGHTS.hex() + ".cert", os.urandom(1792))]

    def write(self, name, data):
        path = self.dir / name
        path.write_bytes(data)
        return path

    def xci(self, name, files):
        root = table(b"HFS0", 64, [("update", b"U" * 512), ("secure", table(b"HFS0", 64, files))])
        head = bytearray(0xF000)
        head[0x100:0x104] = b"HEAD"
        struct.pack_into("<Q", head, 0x130, 0xF000)
        return self.write(name, bytes(head) + root)

    def merge(self, base, update, *extra):
        out = self.dir / "merged.nsp"
        done = subprocess.run([sys.executable, GAME / "scripts/merge_nsp.py", base, update, "--output", out, *extra],
                              capture_output=True, text=True)
        if done.returncode:
            return None, done.stderr
        with out.open("rb") as f:
            return {name: (f.seek(start), f.read(length))[1]
                    for name, start, length in partition_entries(f, 0, out.stat().st_size)}, done.stdout

    def test_xci_base_merges_like_an_nsp_base(self):
        base = [("b1.nca", self.nca(BASE, 5000)), ("b2.cnmt.nca", self.nca(BASE, 4000))]
        new = self.update("n")
        update = self.write("update.nsp", table(b"PFS0", 24, new))
        from_xci, _ = self.merge(self.xci("base.xci", base), update)
        from_nsp, _ = self.merge(self.write("base.nsp", table(b"PFS0", 24, base)), update)
        self.assertEqual(from_xci, dict(base + new))
        self.assertEqual(from_nsp, from_xci)

    def test_card_images_own_update_is_replaced(self):
        base = [("b1.nca", self.nca(BASE, 5000)), ("b2.cnmt.nca", self.nca(BASE, 4000))]
        old, new = self.update("o"), self.update("n")
        card = self.xci("base.xci", base[:1] + old + base[1:])
        update = self.write("update.nsp", table(b"PFS0", 24, new))
        merged, err = self.merge(card, update)             # without keys the two updates collide, as before
        self.assertIsNone(merged)
        self.assertIn("differs between", err)
        merged, out = self.merge(card, update, "--keys", self.keys)
        self.assertEqual(merged, dict(base + new))
        self.assertIn("leaving out its built-in update (5 entries", out)


if __name__ == "__main__":
    unittest.main()
