"""Read the matching Recovery vendor image over root ADB; no phone writes."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--output", type=Path, default=Path("inputs/recovery_vendor_a.img"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    config = json.loads((root / "config/v21.json").read_text(encoding="utf-8"))
    adb = [args.adb, "-s", args.serial]

    def shell(command):
        return subprocess.run(adb + ["shell", command], check=True, capture_output=True, timeout=20).stdout.decode().strip()

    if args.output.exists():
        parser.error("Output already exists")
    if shell("getprop ro.boot.mode") != "recovery" or shell("getprop ro.product.device") != "HNJLH":
        parser.error("Expected an HNJLH device already running Recovery")
    if shell("getprop ro.boot.slot_suffix") != "_a" or "uid=0(root)" not in shell("id"):
        parser.error("This extraction profile requires slot A and an existing root ADB shell")
    source = "/dev/block/by-name/recovery_vendor_a"
    expected = config["vendor_sha256"]
    size = int(shell("blockdev --getsize64 " + source))
    if size != 24 * 1024 * 1024 or shell("sha256sum " + source).split()[0] != expected:
        parser.error("Recovery vendor size/hash is incompatible with this build profile")
    data = subprocess.run(adb + ["exec-out", "cat", source], check=True, capture_output=True, timeout=90).stdout
    if len(data) != size or hashlib.sha256(data).hexdigest() != expected or shell("sha256sum " + source).split()[0] != expected:
        raise SystemExit("Readback or stable-source check failed; no output file written")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as stream:
        stream.write(data)
    print("PASS: matching recovery_vendor image copied; phone was only read")


if __name__ == "__main__":
    main()
