"""merge_nsp.py: an XCI base, and a card image's built-in update replaced by the update NSP (synthetic containers only)."""
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
        self.keys.write_text(f"header_key = {self.header_key.hex()}\n")

    def nca(self, title_id, size, rights=bytes(16)):
        header = bytearray(0xC00)
        header[0x200:0x204] = b"NCA3"
        struct.pack_into("<QQ", header, 0x208, size, title_id)
        header[0x230:0x240] = rights
        out = b""
        for sector in range(6):
            ctx = Cipher(algorithms.AES(self.header_key), modes.XTS(sector.to_bytes(16, "big"))).encryptor()
            out += ctx.update(bytes(header[sector * 512:(sector + 1) * 512])) + ctx.finalize()
        return out + os.urandom(size - 0xC00)

    def update(self, name):
        return [(f"{name}.nca", self.nca(BASE, 6000, RIGHTS)), (f"{name}.cnmt.nca", self.nca(UPDATE, 4000)),
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
        self.assertIn("leaving out its built-in update (4 entries", out)


if __name__ == "__main__":
    unittest.main()
