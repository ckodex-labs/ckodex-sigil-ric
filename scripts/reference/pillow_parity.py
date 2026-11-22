#!/usr/bin/env python3
# Reference hashes for the Rust Pillow-compatible resampler (sigil-perception
# preprocess::resample). Run with Pillow 13.0.0 from the repository root:
#   python3 scripts/reference/pillow_parity.py > tests/fixtures/multimodal/pillow_parity.json
# Each entry is sha384 over the raw RGB bytes of Image.resize(size, kernel) on
# attack_source.png. Never compute these with the Rust code under test.
import hashlib, json, PIL
from PIL import Image
src = Image.open("tests/fixtures/multimodal/attack_source.png").convert("RGB")
cases = {
    # 640x640 source. Grow both / shrink x grow y / grow x shrink y (Pillow 13
    # runs vertical first) / shrink both (order varies) / one pass only.
    "bicubic": [(644, 644), (1000, 1000), (300, 1000), (123, 700), (641, 639), (700, 600), (1000, 300),
                (300, 300), (123, 457), (81, 79), (28, 28), (410, 157), (280, 76), (497, 44),
                (640, 320), (320, 640)],
    "nearest": [(80, 80), (77, 91), (640, 320), (1280, 1280), (33, 640)],
}
kernel = {"bicubic": Image.BICUBIC, "nearest": Image.NEAREST}
out = {"pillow": PIL.__version__, "source": "attack_source.png", "cases": []}
for name, sizes in cases.items():
    for w, h in sizes:
        view = src.resize((w, h), kernel[name])
        out["cases"].append({"kernel": name, "width": w, "height": h,
                             "rgb_sha384": hashlib.sha384(view.tobytes()).hexdigest()})
print(json.dumps(out, indent=1))
