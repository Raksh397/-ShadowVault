"""scripts/make_sample_report.py - generate a sample forensic PDF."""
import os
import sys

import numpy as np
from Crypto.Random import get_random_bytes
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shadowvault.algorithms import LSBSteganography
from forensic_report import ForensicReportGenerator

key = get_random_bytes(32)
rng = np.random.default_rng(0)
cover = rng.integers(0, 256, size=(256, 256, 3), dtype=np.uint8)

os.makedirs("tmp_demo", exist_ok=True)
cover_path = "tmp_demo/cover.png"
stego_path = "tmp_demo/stego.png"
Image.fromarray(cover).save(cover_path)

lsb = LSBSteganography()
assert lsb.embed_file(cover_path, stego_path, "demo payload||ALGO:LSB", key)

gen = ForensicReportGenerator()
ok, err = gen.generate_report(
    cover_path=cover_path,
    stego_path=stego_path,
    output_pdf_path="tmp_demo/sample_report.pdf",
    detected_algorithm="LSB",
    confidence=95.0,
    extracted_message="demo payload",
)
print("OK" if ok else f"FAIL: {err}")
sys.exit(0 if ok else 1)
