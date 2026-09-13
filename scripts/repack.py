from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import json
import stat
import struct
import sys
import zlib
from pathlib import Path

from ramdisk import entry_map, extraction_audit, new_entry, newc, ordered_parents, parse_cpio, ramdisk, safe_name

ROOT = Path(__file__).resolve().parents[1]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True, help="Unmodified v20 baseline image")
    parser.add_argument("--vendor", type=Path, required=True, help="Matching recovery_vendor image, read only")
    parser.add_argument("--output", type=Path, default=ROOT / "build/recovery_ramdisk_twrp_v21_nondata_backup.img")
    parser.add_argument("--allow-recompression", action="store_true", help="Permit a different gzip stream only when the unpacked ramdisk exactly matches v21")
    args = parser.parse_args()
    config = json.loads((ROOT / "config/v21.json").read_text(encoding="utf-8"))
    base_path, vendor_path, output = args.base.resolve(strict=True), args.vendor.resolve(strict=True), args.output.resolve()
    require(output not in (base_path, vendor_path) and not output.exists(), "Output must be a new file, distinct from inputs")
    report_path = output.with_suffix(output.suffix + ".json")
    require(not report_path.exists(), "Output report already exists")
    raw, vendor_raw = base_path.read_bytes(), vendor_path.read_bytes()
    require(sha(raw) == config["base_sha256"], "Wrong v20 baseline SHA-256")
    require(sha(vendor_raw) == config["vendor_sha256"], "Recovery vendor SHA-256 does not match the validated layout")
    require(raw.startswith(b"ANDROID!") and len(raw) == config["image_size"], "Unsupported base image header or size")
    baseline = ramdisk(base_path, 4096, 12)
    vendor = ramdisk(vendor_path, 0x800, 0x10)
    old = entry_map(parse_cpio(baseline)[0])
    entries = copy.deepcopy(old)
    for name, info in config["patches"].items():
        require(safe_name(name) == name, "Noncanonical patch path")
        source = (ROOT / "patches/v21" / name).resolve(strict=True)
        require(source.is_relative_to((ROOT / "patches/v21").resolve()), "Patch path escapes its directory")
        data = source.read_bytes()
        require(sha(data) == info["sha256"], "Patch hash mismatch: " + name)
        require(stat.S_ISREG(info["mode"]), "Only regular-file patches are supported")
        entries[name] = new_entry(name, info["mode"], data)
    entries, added = ordered_parents(entries, entry_map(parse_cpio(vendor)[0]))
    require(not added, "Unexpected new ramdisk directory")
    cpio = newc(entries)
    parsed, trailer = parse_cpio(cpio)
    own = entry_map(parsed)
    _, errors = extraction_audit(parse_cpio(cpio[:trailer] + vendor)[0])
    require(not errors, "Merged initramfs extraction failed: " + repr(errors))
    require(sha(cpio) == config["ramdisk_sha256"], "Unpacked ramdisk differs from the tested v21 payload")
    changed = {name for name, entry in own.items() if name not in old or (entry.mode, entry.data) != (old[name].mode, old[name].data)}
    require(changed == set(config["patches"]) and old.keys() <= own.keys(), "Unexpected ramdisk changes")
    for name, digest in config["unchanged_runtime"].items():
        require(sha(own[name].data) == digest == sha(old[name].data), "Runtime helper changed: " + name)
    zipped = gzip.compress(cpio, compresslevel=9, mtime=0)
    # The original gzip OS byte is 0x0a. Normalize the metadata, not the payload.
    zipped = bytes.fromhex(config["gzip_header_hex"]) + zipped[10:]
    require(gzip.decompress(zipped) == cpio, "Gzip roundtrip failed")
    vbmeta = config["vbmeta_offset"]
    require(len(zipped) < vbmeta - 4096, "Compressed ramdisk exceeds its partition budget")
    require(len(cpio[:trailer] + vendor) < 0x9600000 - 0x800, "Merged ramdisk exceeds loader memory limit")
    result = bytearray(raw)
    struct.pack_into("<I", result, 12, len(zipped))
    result[4096:vbmeta] = bytes(vbmeta - 4096)
    result[4096:4096 + len(zipped)] = zipped
    salt = result[vbmeta + 0x2D4:vbmeta + 0x2F4]
    result[vbmeta + 0x2F4:vbmeta + 0x314] = hashlib.sha256(salt + result[:vbmeta]).digest()
    result[vbmeta + 0x100:vbmeta + 0x120] = hashlib.sha256(result[vbmeta:vbmeta + 0x100] + result[vbmeta + 0x240:vbmeta + 0x540]).digest()
    digest = sha(result)
    exact = digest == config["image_sha256"]
    require(exact or args.allow_recompression,
            "Payload matches but gzip output differs. Exact reference used Python 3.12.14 / zlib 1.3.2. "
            "Use a matching runtime or explicitly pass --allow-recompression; a changed image hash is not the tested release file.")
    report = {"revision": config["revision"], "image_sha256": digest, "image_size": len(result),
              "matches_release_image": exact, "ramdisk_matches_release": True,
              "base_sha256": config["base_sha256"], "vendor_sha256": config["vendor_sha256"],
              "ramdisk_sha256": sha(cpio), "gzip_size": len(zipped), "changed_paths": sorted(changed),
              "python": sys.version.split()[0], "zlib": zlib.ZLIB_RUNTIME_VERSION,
              "phone_connected_or_modified": False}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(result)
    require(sha(output.read_bytes()) == digest, "Output readback mismatch")
    with report_path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
