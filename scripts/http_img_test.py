"""scripts/http_img_test.py - image-in-image HTTP endpoint test."""
import io
import sys

import numpy as np
import requests
from PIL import Image

cover_buf = io.BytesIO()
Image.fromarray(
    np.random.default_rng(2).integers(0, 256, (512, 512, 3), dtype=np.uint8)
).save(cover_buf, "PNG")
cover_buf.seek(0)

secret_buf = io.BytesIO()
Image.fromarray(
    np.random.default_rng(3).integers(0, 256, (32, 32, 3), dtype=np.uint8)
).save(secret_buf, "PNG")
secret_buf.seek(0)

r = requests.post(
    "http://127.0.0.1:5000/embed_image_in_image",
    files={
        "cover": ("cover.png", cover_buf, "image/png"),
        "secret": ("secret.png", secret_buf, "image/png"),
    },
)
print("IMG EMBED:", r.status_code, r.json().get("message"))
stego_url = r.json()["stegoUrl"]

img_bytes = requests.get("http://127.0.0.1:5000" + stego_url).content
r = requests.post(
    "http://127.0.0.1:5000/extract_image_from_image",
    files={"stego": ("stego.png", io.BytesIO(img_bytes), "image/png")},
)
e = r.json()
print("IMG EXTRACT:", e.get("success"), "| type:", e.get("dataType"),
      "| file:", e.get("filename"), "| size:", e.get("size"))
sys.exit(0 if e.get("success") else 1)
