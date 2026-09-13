from __future__ import annotations

import copy
import gzip
import posixpath
import stat
import struct
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass
class Entry:
    name: str
    mode: int
    data: bytes
    fields: list[int]
    offset: int = 0


def safe_name(name: str) -> str:
    if name.startswith("/") or ".." in PurePosixPath(name).parts or "\\" in name:
        raise ValueError(f"Unsafe archive path: {name!r}")
    return posixpath.normpath(name)


def parse_cpio(blob: bytes) -> tuple[list[Entry], int]:
    offset, entries = 0, []
    while offset + 110 <= len(blob):
        if blob[offset:offset + 6] != b"070701":
            raise ValueError(f"newc magic missing at {offset:#x}")
        fields = [int(blob[offset + 6 + 8*i:offset + 14 + 8*i], 16) for i in range(13)]
        size, name_size = fields[6], fields[11]
        if not 1 <= name_size <= 4096:
            raise ValueError(f"Invalid name size at {offset:#x}")
        raw_name = blob[offset + 110:offset + 110 + name_size]
        if len(raw_name) != name_size or raw_name[-1:] != b"\0":
            raise ValueError(f"Invalid name at {offset:#x}")
        name = raw_name[:-1].decode("utf-8", errors="strict")
        data_start = (offset + 110 + name_size + 3) & ~3
        data_end = data_start + size
        if data_end > len(blob):
            raise ValueError(f"Truncated data: {name}")
        if name == "TRAILER!!!":
            if size:
                raise ValueError("Nonempty trailer")
            return entries, offset
        entries.append(Entry(safe_name(name), fields[1], blob[data_start:data_end], fields, offset))
        offset = (data_end + 3) & ~3
    raise ValueError("Missing trailer")


def ramdisk(path: Path, offset: int, size_offset: int) -> bytes:
    blob = path.read_bytes()
    if len(blob) < max(offset, size_offset + 4):
        raise ValueError("Truncated image header")
    size = struct.unpack_from("<I", blob, size_offset)[0]
    if size <= 0 or offset + size > len(blob):
        raise ValueError("Ramdisk extends outside image")
    return gzip.decompress(blob[offset:offset + size])


def entry_map(entries: list[Entry]) -> dict[str, Entry]:
    return {entry.name: entry for entry in entries}


def resolve(entries: dict[str, Entry], path: str) -> str:
    parts = posixpath.normpath("/" + path.lstrip("/")).split("/")[1:]
    done, hops = [], 0
    while parts:
        part = parts.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if done:
                done.pop()
            continue
        done.append(part)
        entry = entries.get("/".join(done))
        if entry is not None and stat.S_ISLNK(entry.mode):
            hops += 1
            if hops > 40:
                raise ValueError(f"Symlink cycle: {path}")
            target = entry.data.decode()
            done.pop()
            if target.startswith("/"):
                done = []
            parts = target.split("/") + parts
    return "/".join(done)


def new_entry(name: str, mode: int, data: bytes = b"") -> Entry:
    fields = [0, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name.encode()) + 1, 0]
    return Entry(name, mode, data, fields)


def newc(entries: dict[str, Entry]) -> bytes:
    result = bytearray()
    sequence = list(entries.values()) + [new_entry("TRAILER!!!", 0)]
    for inode, entry in enumerate(sequence, 100):
        fields = entry.fields.copy()
        fields[0], fields[1], fields[4] = inode, entry.mode, 1
        fields[6], fields[11] = len(entry.data), len(entry.name.encode()) + 1
        header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
        if len(header) != 110:
            raise ValueError("newc field overflow")
        result.extend(header + entry.name.encode() + b"\0")
        result.extend(b"\0" * (-len(result) % 4))
        result.extend(entry.data)
        result.extend(b"\0" * (-len(result) % 4))
    return bytes(result)


def ordered_parents(entries, directory_sources=None):
    result, added = copy.deepcopy(entries), []
    directory_sources = directory_sources or {}
    for name in list(result):
        if name == ".":
            continue
        parent = posixpath.dirname(name)
        if resolve(result, parent) != parent:
            raise ValueError("Use the canonical parent for " + name)
        while parent:
            if parent not in result:
                source = directory_sources.get(parent)
                result[parent] = copy.deepcopy(source) if source and stat.S_ISDIR(source.mode) else new_entry(parent, stat.S_IFDIR | 0o755)
                added.append(parent)
            if not stat.S_ISDIR(result[parent].mode):
                raise ValueError("Parent is not a directory: " + parent)
            parent = posixpath.dirname(parent)
    directories = sorted((n for n in result if stat.S_ISDIR(result[n].mode)), key=lambda n: (n.count("/"), n))
    links = [n for n in result if stat.S_ISLNK(result[n].mode)]
    files = [n for n in result if not stat.S_ISDIR(result[n].mode) and not stat.S_ISLNK(result[n].mode)]
    return {n: result[n] for n in directories + links + files}, sorted(added)


def extraction_audit(sequence):
    extracted = {"": new_entry("", stat.S_IFDIR | 0o755)}
    errors = []
    for entry in sequence:
        if entry.name == ".":
            continue
        parent = resolve(extracted, posixpath.dirname(entry.name))
        if parent not in extracted or not stat.S_ISDIR(extracted[parent].mode):
            errors.append({"path": entry.name, "missing_parent": parent})
            continue
        extracted[posixpath.join(parent, posixpath.basename(entry.name))] = entry
    return extracted, errors
