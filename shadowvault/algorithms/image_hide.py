"""
image_hide.py - Hide an image (or arbitrary bytes) inside a cover image.

Technique: 2-bit LSB substitution across RGB channels.
Header layout (17 bytes):
    [1 byte  type flag: 0=image, 1=text]
    [12 bytes filename, right-padded with '0']
    [4 bytes payload length, little-endian]
"""

import io
import os

import numpy as np
from PIL import Image

HEADER_SIZE = 17
FILENAME_FIELD = 12
BITS_PER_CHANNEL = 2
CHANNEL_MASK = 0xFC  # keep upper 6 bits
VALUE_MASK = 0x03    # 2 bits carried per channel


class ImageInImageSteganography:
    """2-bit LSB image-in-image steganography."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def embed_image(self, cover_path, secret_path, output_path):
        """Embed the image at `secret_path` into `cover_path`.

        Returns (success: bool, error: str | None).
        """
        try:
            cover = np.array(Image.open(cover_path).convert("RGB"))

            secret_img = Image.open(secret_path)
            buffer = io.BytesIO()
            secret_img.save(buffer, format="PNG")
            payload = buffer.getvalue()

            filename = os.path.basename(secret_path)[:FILENAME_FIELD]

            capacity = self._capacity_bytes(cover)
            if len(payload) > capacity - HEADER_SIZE:
                return False, (
                    f"Secret image too large! Max: "
                    f"{(capacity - HEADER_SIZE) // 1024}KB, "
                    f"Yours: {len(payload) // 1024}KB"
                )

            stego = self._embed_bytes(cover, payload, filename, is_text=False)
            Image.fromarray(stego.astype(np.uint8)).save(output_path, "PNG")
            return True, None
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    def embed_data_bytes(self, cover_path, data_bytes, output_path,
                         filename="data.bin"):
        """Embed arbitrary bytes into the cover image (type = text)."""
        try:
            cover = np.array(Image.open(cover_path).convert("RGB"))
            filename = filename[:FILENAME_FIELD]

            capacity = self._capacity_bytes(cover)
            if len(data_bytes) > capacity - HEADER_SIZE:
                return False, (
                    f"Data too large! Max: {capacity - HEADER_SIZE} bytes, "
                    f"Yours: {len(data_bytes)} bytes"
                )

            stego = self._embed_bytes(cover, data_bytes, filename, is_text=True)
            Image.fromarray(stego.astype(np.uint8)).save(output_path, "PNG")
            return True, None
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    def extract_image(self, stego_path):
        """Extract hidden payload.

        Returns (data_bytes, filename, data_type) or (None, None, None).
        data_type is 'image' or 'text'.
        """
        try:
            stego = np.array(Image.open(stego_path).convert("RGB"))
            data, filename, data_type = self._extract_bytes(stego)
            if data is None:
                return None, None, None
            return bytes(data), filename, data_type
        except Exception as exc:  # noqa: BLE001
            print(f"[IMG] Extraction error: {exc}")
            return None, None, None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    @staticmethod
    def _capacity_bytes(img_array):
        h, w, c = img_array.shape
        return (h * w * c * BITS_PER_CHANNEL) // 8

    def _embed_bytes(self, img, payload, filename, is_text):
        header = bytearray()
        header.append(1 if is_text else 0)
        header.extend(filename.rjust(FILENAME_FIELD, "0").encode("utf-8"))
        header.extend(len(payload).to_bytes(4, "little"))
        blob = header + payload

        flat = img.reshape(-1)
        total_values = flat.size

        value_idx = 0
        for byte in blob:
            for shift in range(0, 8, BITS_PER_CHANNEL):
                if value_idx >= total_values:
                    raise ValueError("Cover image capacity exceeded")
                two_bits = (byte >> shift) & VALUE_MASK
                flat[value_idx] = (flat[value_idx] & CHANNEL_MASK) | two_bits
                value_idx += 1

        return flat.reshape(img.shape)

    def _extract_bytes(self, img):
        flat = img.reshape(-1)
        values_needed_header = HEADER_SIZE * 4  # 4 channel-values per byte
        if flat.size < values_needed_header:
            return None, None, None

        def read_bytes(count, start_value):
            out = bytearray()
            v = start_value
            accumulator = 0
            nibble_count = 0
            for _ in range(count):
                while True:
                    accumulator |= (flat[v] & VALUE_MASK) << (nibble_count * 2)
                    nibble_count += 1
                    v += 1
                    if nibble_count == 4:
                        out.append(accumulator)
                        accumulator = 0
                        nibble_count = 0
                        break
            return out, v

        header, cursor = read_bytes(HEADER_SIZE, 0)
        data_type = "text" if header[0] == 1 else "image"
        filename = (
            header[1 : 1 + FILENAME_FIELD].decode("utf-8").lstrip("0")
        )
        payload_len = int.from_bytes(
            header[1 + FILENAME_FIELD : HEADER_SIZE], "little"
        )

        if payload_len <= 0:
            return None, None, None

        payload, _ = read_bytes(payload_len, cursor)
        return payload, filename, data_type
