import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    config = json.loads((root / "config/v21.json").read_text(encoding="utf-8"))
    data = args.image.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != config["image_size"] or digest != config["image_sha256"]:
        raise SystemExit("Image does not match the published v21 size/SHA-256")
    print("PASS: v21 image, 33554432 bytes, SHA-256 " + digest)


if __name__ == "__main__":
    main()
