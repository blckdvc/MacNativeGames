#!/usr/bin/env python3
"""Join a base game (NSP, or an XCI card image) and a separate update NSP into one NSP (PFS0), the single game file
the build reads. Of an XCI, the entries of its secure partition are taken.

A card image can carry the update it shipped with. With --keys, that built-in update (its NCAs, ticket and certificate)
is left out of the base, so the separate update NSP replaces it; only NCA headers are read for this.

    python3 scripts/merge_nsp.py BASE.nsp UPDATE.nsp --output Odyssey_build/input/odyssey.nsp

Every entry of both files is copied unchanged (NCAs, tickets, certificates); a name both files carry must hold the same
bytes. Nothing is decrypted, and no keys are needed. The output is written next to itself and renamed when complete.
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "third_party" / "totk-scripts"))
from extract_exefs import container_entries, load_keys, partition_entries, read_nca_header, require  # noqa: E402

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


def builtin_update(f, found, keys):
    """Names of the base file's entries that belong to an update title (ID ending in 800)."""
    names = set()
    for name, start, length in found:
        lower = name.lower()
        if lower.endswith(".nca"):
            hdr = read_nca_header(f, start, length, keys)
            rights = hdr[0x230:0x240]
            if is_update_id(struct.unpack_from("<Q", hdr, 0x210)[0]) or \
                    (rights != bytes(16) and is_update_id(int.from_bytes(rights[:8], "big"))):
                names.add(name)
        elif lower.endswith((".tik", ".cert")):
            try:
                if is_update_id(int(name[:16], 16)):
                    names.add(name)
            except ValueError:
                pass
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
