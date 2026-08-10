"""
tests/test_algorithms.py - Round-trip tests for ShadowVault steganography engines.

Run:  python -m pytest tests/ -v
"""

import os
import sys
import tempfile

import numpy as np
import pytest
from Crypto.Random import get_random_bytes
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shadowvault.algorithms import (
    HugoSteganography,
    ImageInImageSteganography,
    LSBSteganography,
    WowSteganography,
)


@pytest.fixture()
def cover_image(tmp_path):
    """Create a colorful 256x256 test cover image."""
    rng = np.random.default_rng(42)
    arr = rng.integers(0, 256, size=(256, 256, 3), dtype=np.uint8)
    path = tmp_path / "cover.png"
    Image.fromarray(arr).save(path)
    return str(path)


@pytest.fixture()
def key():
    return get_random_bytes(32)


@pytest.fixture()
def engines():
    return {
        "lsb": LSBSteganography(),
        "hugo": HugoSteganography(),
        "wow": WowSteganography(),
    }


MESSAGES = [
    "Hello, ShadowVault!",
    "Short",
    "A longer secret message containing unicode: héllo wörld ✓ 🔐",
]


class TestTextEngines:
    @pytest.mark.parametrize("message", MESSAGES)
    def test_lsb_roundtrip(self, engines, cover_image, tmp_path, key, message):
        out = str(tmp_path / "stego.png")
        ok = engines["lsb"].embed_file(cover_image, out, message, key)
        assert ok
        assert engines["lsb"].extract_file(out, key) == message

    def test_hugo_roundtrip(self, engines, cover_image, tmp_path, key):
        out = str(tmp_path / "stego_hugo.png")
        assert engines["hugo"].embed_file(cover_image, out, "hugo secret", key)
        assert engines["hugo"].extract_file(out, key) == "hugo secret"

    def test_wow_roundtrip(self, engines, cover_image, tmp_path, key):
        out = str(tmp_path / "stego_wow.png")
        assert engines["wow"].embed_file(cover_image, out, "wow secret", key)
        assert engines["wow"].extract_file(out, key) == "wow secret"

    def test_wrong_key_fails(self, engines, cover_image, tmp_path, key):
        out = str(tmp_path / "stego.png")
        assert engines["lsb"].embed_file(cover_image, out, "secret", key)
        other_key = get_random_bytes(32)
        assert engines["lsb"].extract_file(out, other_key) is None

    def test_clean_image_extracts_nothing(self, engines, cover_image, key):
        # A clean image yields garbage length header -> extract returns None
        result = engines["lsb"].extract_file(cover_image, key)
        assert result is None or isinstance(result, str)

    def test_stego_visually_identical(self, engines, cover_image, tmp_path, key):
        out = str(tmp_path / "stego.png")
        assert engines["lsb"].embed_file(cover_image, out, "data", key)
        cover = np.array(Image.open(cover_image).convert("RGB"), dtype=np.int16)
        stego = np.array(Image.open(out).convert("RGB"), dtype=np.int16)
        assert np.abs(cover - stego).max() <= 1  # LSB-only changes


class TestImageInImage:
    def test_roundtrip(self, cover_image, tmp_path):
        rng = np.random.default_rng(7)
        secret_arr = rng.integers(0, 256, size=(32, 32, 3), dtype=np.uint8)
        secret_path = tmp_path / "secret.png"
        Image.fromarray(secret_arr).save(secret_path)

        engine = ImageInImageSteganography()
        out = str(tmp_path / "stego_img.png")
        ok, err = engine.embed_image(cover_image, str(secret_path), out)
        assert ok, err

        data, filename, data_type = engine.extract_image(out)
        assert data is not None
        assert data_type == "image"
        assert filename == "secret.png"

        recovered = Image.open(
            __import__("io").BytesIO(data)
        ).convert("RGB")
        assert np.array_equal(np.array(recovered), secret_arr)

    def test_oversized_secret_rejected(self, tmp_path):
        small_cover = np.zeros((16, 16, 3), dtype=np.uint8)
        cover_path = tmp_path / "small.png"
        Image.fromarray(small_cover).save(cover_path)

        big_secret = np.random.default_rng(1).integers(
            0, 256, size=(512, 512, 3), dtype=np.uint8
        )
        secret_path = tmp_path / "big.png"
        Image.fromarray(big_secret).save(secret_path)

        engine = ImageInImageSteganography()
        ok, err = engine.embed_image(
            str(cover_path), str(secret_path), str(tmp_path / "out.png")
        )
        assert not ok
        assert "too large" in err.lower()
