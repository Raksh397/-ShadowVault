"""
tests/test_app.py - Flask endpoint smoke tests for ShadowVault.
"""

import io
import os
import sys

import numpy as np
import pytest
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app  # noqa: E402


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def _png_file(size=(128, 128)):
    arr = np.random.default_rng(3).integers(0, 256, size=(*size, 3), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    buf.seek(0)
    return buf


class TestPages:
    @pytest.mark.parametrize(
        "route", ["/", "/embed", "/detect", "/extract", "/image_stego"]
    )
    def test_page_loads(self, client, route):
        resp = client.get(route)
        assert resp.status_code == 200
        assert b"ShadowVault" in resp.data


class TestEmbedDetectExtractFlow:
    def test_full_roundtrip(self, client):
        # Embed
        resp = client.post(
            "/perform_embed",
            data={
                "image": (_png_file(), "cover.png"),
                "message": "integration secret",
                "algorithm": "lsb",
            },
            content_type="multipart/form-data",
        )
        assert resp.status_code == 200
        payload = resp.get_json()
        assert payload["success"]
        assert payload["stegoUrl"].endswith(".png")

        # Fetch the generated stego image and re-upload it
        stego_resp = client.get(payload["stegoUrl"])
        assert stego_resp.status_code == 200

        # Detect
        resp = client.post(
            "/perform_detect",
            data={"image": (io.BytesIO(stego_resp.data), "stego.png")},
            content_type="multipart/form-data",
        )
        detection = resp.get_json()
        assert detection["success"]
        assert detection["prediction"] == "Stego Image"
        assert detection["algorithm"] == "LSB"
        assert detection["extractedMessage"] == "integration secret"

        # Extract
        resp = client.post(
            "/perform_extract",
            data={
                "image": (io.BytesIO(stego_resp.data), "stego.png"),
                "algorithm": "lsb",
            },
            content_type="multipart/form-data",
        )
        extraction = resp.get_json()
        assert extraction["success"]
        assert extraction["message"] == "integration secret"
        assert extraction["detectedAlgorithm"] == "LSB"

    def test_detect_clean_image(self, client):
        resp = client.post(
            "/perform_detect",
            data={"image": (_png_file(), "clean.png")},
            content_type="multipart/form-data",
        )
        data = resp.get_json()
        assert data["success"]
        assert data["prediction"] == "Cover Image"
        assert data["algorithm"] is None

    def test_embed_missing_fields(self, client):
        resp = client.post("/perform_embed", data={})
        assert resp.status_code == 400

    def test_invalid_algorithm_rejected(self, client):
        resp = client.post(
            "/perform_embed",
            data={
                "image": (_png_file(), "cover.png"),
                "message": "x",
                "algorithm": "bogus",
            },
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400


class TestImageInImageEndpoints:
    def test_image_roundtrip(self, client):
        cover = _png_file((512, 512))
        secret_buf = io.BytesIO()
        Image.fromarray(
            np.random.default_rng(9).integers(0, 256, size=(16, 16, 3), dtype=np.uint8)
        ).save(secret_buf, format="PNG")
        secret_buf.seek(0)

        resp = client.post(
            "/embed_image_in_image",
            data={"cover": (cover, "cover.png"), "secret": (secret_buf, "secret.png")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"]

        stego_resp = client.get(data["stegoUrl"])
        resp = client.post(
            "/extract_image_from_image",
            data={"stego": (io.BytesIO(stego_resp.data), "stego.png")},
            content_type="multipart/form-data",
        )
        ext = resp.get_json()
        assert ext["success"]
        assert ext["dataType"] == "image"
