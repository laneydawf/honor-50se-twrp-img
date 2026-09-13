import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, default=os.environ.get("ANDROID_NDK_HOME"))
    parser.add_argument("--output", type=Path, default=ROOT / "build/helpers")
    parser.add_argument("--require-release-match", action="store_true")
    args = parser.parse_args()
    if args.ndk is None:
        parser.error("Provide --ndk or ANDROID_NDK_HOME (reference: 28.1.13356709)")
    suffix = ".exe" if sys.platform == "win32" else ""
    candidates = sorted((args.ndk / "toolchains/llvm/prebuilt").glob("*/bin/clang" + suffix))
    if len(candidates) != 1:
        parser.error("Expected one host Clang installation in the supplied NDK")
    clang, output = candidates[0].resolve(strict=True), args.output.resolve()
    flags = ["--target=aarch64-linux-android26", "-O2", "-Wall", "-Wextra", "-Werror"]
    targets = {
        "honor-backup": ("honor_backup.c", ["-fPIE", "-pie", "-Wl,--strip-debug"]),
        "honor-reset": ("honor_reset.c", ["-fPIE", "-pie", "-Wl,--build-id=sha1", "-Wl,-s"]),
        "libhonor_ro_runtime.so": ("recovery_data_runtime.c", ["-shared", "-fPIC", "-Wl,-z,relro,-z,now", "-Wl,-soname,libhonor_ro_runtime.so"]),
        "init": ("recovery_bootstrap_fastboot.c", ["-static", "-Wl,--build-id=sha1"]),
    }
    for name in [*targets, "init-unstripped", "helper-build.json"]:
        if (output / name).exists():
            parser.error("Output already exists: " + name)
    output.mkdir(parents=True, exist_ok=True)
    config = json.loads((ROOT / "config/v21.json").read_text(encoding="utf-8"))
    report = {"ndk_reference": "28.1.13356709", "phone_connected_or_modified": False, "files": {}}
    for name, (source_name, options) in targets.items():
        source = ROOT / "src" / source_name
        compiled = output / ("init-unstripped" if name == "init" else name)
        subprocess.run([str(clang), *flags, *options, str(source), "-o", str(compiled)], check=True)
        if name == "init":
            subprocess.run([str(clang.with_name("llvm-strip" + suffix)), "--strip-debug", "-o", str(output / name), str(compiled)], check=True)
        target = output / name
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        report["files"][name] = {"sha256": digest, "bytes": target.stat().st_size,
                                 "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                                 "matches_release_binary": digest == config["helpers"][name]["binary_sha256"]}
        print(name + ": " + digest, flush=True)
    report["all_match_release"] = all(row["matches_release_binary"] for row in report["files"].values())
    (output / "helper-build.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.require_release_match and not report["all_match_release"]:
        raise SystemExit("Compiled successfully, but one or more binaries differ from the release. Check source and NDK versions.")


if __name__ == "__main__":
    main()
