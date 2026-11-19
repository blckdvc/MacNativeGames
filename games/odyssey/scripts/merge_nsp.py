#!/usr/bin/env python3
"""Join a base game (NSP, or an XCI card image) and a separate update NSP into one NSP (PFS0), the single game file
the build reads. Of an XCI, the entries of its secure partition are taken.

A card image can carry the update it shipped with. With --keys, that built-in update (its NCAs, ticket and certificate)
is left out of the base, so the separate update NSP replaces it; for this only NCA headers and the built-in update's
content list (the .cnmt in its Meta NCA) are read.

    python3 scripts/merge_nsp.py BASE.nsp UPDATE.nsp --output Odyssey_build/input/odyssey.nsp

Every entry of both files is copied unchanged (NCAs, tickets, certificates); a name both files carry must hold the same
bytes. Nothing is decrypted, and no keys are needed. The output is written next to itself and renamed when complete.
"""

import argparse
import hashlib
import io
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "third_party" / "totk-scripts"))
from extract_exefs import (container_entries, decrypt, load_keys, nca_ctr_key, partition_entries, read_at,  # noqa: E402
                           read_nca_header, require)

CHUNK = 8 << 20


def digest(f, start, length):
    h = hashlib.sha256()
    f.seek(start)
    while length:
        block = f.read(min(CHUNK, length))
        require(block, "Truncated input")
        h.update(block)
        length -= len(block)
    return h.digest()


def is_update_id(title_id):
    return title_id & 0xFFF == 0x800


def meta_contents(f, start, hdr, keys):
    """The NCA file names an update's Meta NCA lists: its verified PFS0 section holds one .cnmt with a content table."""
    from cryptography.hazmat.primitives.ciphers import modes
    key = nca_ctr_key(hdr, keys, {})
    for i in range(4):
        first, last = struct.unpack_from("<II", hdr, 0x240 + 16 * i)
        fs = hdr[0x400 + 512 * i:0x600 + 512 * i]
        if not first or fs[2:5] != b"\x01\x02\x03":   # a PFS0 with hierarchical SHA-256, AES-CTR
            continue
        require(hashlib.sha256(fs).digest() == hdr[0x280 + 32 * i:0x2A0 + 32 * i], "Meta NCA: FS header hash mismatch")
        block, levels = struct.unpack_from("<II", fs, 0x28)
        hash_at, hash_size, pfs_at, pfs_size = struct.unpack_from("<QQQQ", fs, 0x30)
        require(levels == 2 and block > 0 and pfs_size <= 16 << 20, "Meta NCA: unsupported hash layout")

        def section(relative, size):
            require(0 <= relative and relative + size <= (last - first) * 512, "Meta NCA: read out of bounds")
            absolute = first * 512 + relative
            aligned = absolute & ~15
            iv = fs[0x140:0x148][::-1] + (aligned // 16).to_bytes(8, "big")
            return decrypt(key, modes.CTR(iv), read_at(f, start + aligned, size + absolute - aligned))[absolute - aligned:]

        hashes = section(hash_at, hash_size)
        require(hashlib.sha256(hashes).digest() == fs[8:40], "Meta NCA: hash table mismatch (check prod.keys)")
        pfs = section(pfs_at, pfs_size)
        for n, at in enumerate(range(0, pfs_size, block)):
            require(hashlib.sha256(pfs[at:at + block]).digest() == hashes[n * 32:(n + 1) * 32], "Meta NCA: block hash mismatch")
        cnmt = [pfs[at:at + size] for name, at, size in partition_entries(io.BytesIO(pfs), 0, len(pfs))
                if name.lower().endswith(".cnmt")]
        require(len(cnmt) == 1 and len(cnmt[0]) >= 0x20, "Meta NCA: expected one .cnmt")
        extended, count = struct.unpack_from("<HH", cnmt[0], 0x0E)
        table = 0x20 + extended
        require(table + count * 0x38 <= len(cnmt[0]), "Meta NCA: content table out of bounds")
        return {cnmt[0][table + n * 0x38 + 0x20:table + n * 0x38 + 0x30].hex() + ".nca" for n in range(count)}
    raise ValueError("Meta NCA: no content list found")


def builtin_update(f, found, keys):
    """Names of the base file's entries that belong to an update title (ID ending in 800): its Meta NCA, the NCAs that
    one lists (on a card they can carry the base title's ID and no rights ID), and anything under an update rights ID."""
    names, listed = set(), set()
    for name, start, length in found:
        lower = name.lower()
        if lower.endswith(".nca"):
            hdr = read_nca_header(f, start, length, keys)
            rights = hdr[0x230:0x240]
            if is_update_id(struct.unpack_from("<Q", hdr, 0x210)[0]):
                names.add(name)
                if hdr[0x205] == 1:   # content type 1: Meta
                    listed |= meta_contents(f, start, hdr, keys)
            elif rights != bytes(16) and is_update_id(int.from_bytes(rights[:8], "big")):
                names.add(name)
        elif lower.endswith((".tik", ".cert")):
            try:
                if is_update_id(int(name[:16], 16)):
                    names.add(name)
            except ValueError:
                pass
    names |= {name for name, _, _ in found if name.lower() in listed}
    return names


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("nsp", type=Path, nargs="+", help="the base NSP, then the update NSP")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--keys", type=Path, help="prod.keys: leave out an update the base file itself carries")
    args = p.parse_args()
    require(len(args.nsp) >= 2, "Give the base NSP and the update NSP")

    sources = [path.open("rb") for path in args.nsp]
    entries, seen = [], {}
    for index, (path, f) in enumerate(zip(args.nsp, sources)):
        size = path.stat().st_size
        try:
            _, found = container_entries(f, size)   # NSP: its PFS0 entries; XCI: its secure partition's (HFS0)
        except ValueError as e:
            raise ValueError(f"{path.name}: not an NSP (PFS0) or XCI ({e})") from None
        if index == 0 and args.keys:
            dropped = builtin_update(f, found, load_keys(args.keys))
            if dropped:
                require(any(n.lower().endswith(".nca") for n, _, _ in found if n not in dropped),
                        f"{path.name} holds only an update, not the base game")
                print(f"{path.name}: leaving out its built-in update ({len(dropped)} entries: "
                      f"{', '.join(sorted(dropped))})")
                found = [e for e in found if e[0] not in dropped]
        for name, start, length in found:
            if name in seen:
                other = entries[seen[name]]
                require(other[3] == length and digest(sources[other[0]], other[2], length) == digest(f, start, length),
                        f"{name} differs between {args.nsp[other[0]].name} and {path.name}")
                continue
            seen[name] = len(entries)
            entries.append((index, name, start, length))

    strings = b"".join(name.encode() + b"\0" for _, name, _, _ in entries)
    strings += b"\0" * (-(16 + 24 * len(entries) + len(strings)) % 0x20)
    table, offset, name_at = [], 0, 0
    for _, name, _, length in entries:
        table.append(struct.pack("<QQII", offset, length, name_at, 0))
        offset += length
        name_at += len(name.encode()) + 1
    header = b"PFS0" + struct.pack("<II", len(entries), len(strings)) + b"\0" * 4 + b"".join(table) + strings

    args.output.parent.mkdir(parents=True, exist_ok=True)
    partial = args.output.with_name(args.output.name + ".partial")
    with partial.open("wb") as out:
        out.write(header)
        for index, _, start, length in entries:
            f = sources[index]
            f.seek(start)
            while length:
                block = f.read(min(CHUNK, length))
                require(block, "Truncated input")
                out.write(block)
                length -= len(block)
    for f in sources:
        f.close()
    with partial.open("rb") as f:
        require(len(partition_entries(f, 0, partial.stat().st_size)) == len(entries), "Merged NSP does not read back")
    partial.replace(args.output)
    print(f"{len(entries)} entries from {len(args.nsp)} NSPs -> {args.output} ({args.output.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
