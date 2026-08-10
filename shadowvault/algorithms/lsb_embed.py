"""
lsb_embed.py - Least Significant Bit steganography with AES-256-CBC encryption.

Payload layout embedded into image LSBs:
    [32-bit big-endian length header][IV (16 bytes)][AES-CBC ciphertext]
"""

import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class LSBSteganography:
    """Embeds/extracts AES-encrypted payloads in image LSBs."""

    HEADER_BITS = 32

    def __init__(self, payload=0.3):
        self.payload = payload

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def embed_file(self, cover_path, output_path, data, key):
        """Embed `data` (str) into the image at `cover_path`. Returns bool."""
        try:
            img = Image.open(cover_path)
            pixels = np.array(img.convert("RGB"))

            cipher_bytes = self._encrypt(data, key)
            bitstream = self._int_to_bits(len(cipher_bytes), self.HEADER_BITS) \
                + self._bytes_to_bits(cipher_bytes)

            capacity_bits = pixels.size
            if len(bitstream) > capacity_bits:
                print(f"[LSB] Payload too large: need {len(bitstream)} bits, "
                      f"have {capacity_bits}")
                return False

            flat = pixels.flatten()
            for idx, bit in enumerate(bitstream):
                flat[idx] = (flat[idx] & 0xFE) | int(bit)

            stego = flat.reshape(pixels.shape).astype(np.uint8)
            Image.fromarray(stego).save(output_path)
            print(f"[LSB] Embedded {len(data)} chars into {cover_path}")
            return True
        except Exception as exc:  # noqa: BLE001
            print(f"[LSB] Embed failed: {exc}")
            return False

    def extract_file(self, stego_path, key):
        """Extract and decrypt payload from `stego_path`. Returns str or None."""
        try:
            img = Image.open(stego_path)
            flat = np.array(img.convert("RGB")).flatten()

            length_bits = "".join(str(v & 1) for v in flat[: self.HEADER_BITS])
            data_len = int(length_bits, 2)

            if data_len <= 0 or self.HEADER_BITS + data_len * 8 > flat.size:
                return None

            end = self.HEADER_BITS + data_len * 8
            payload_bits = "".join(str(v & 1) for v in flat[self.HEADER_BITS:end])
            cipher_bytes = self._bits_to_bytes(payload_bits)

            return self._decrypt(cipher_bytes, key)
        except Exception as exc:  # noqa: BLE001
            print(f"[LSB] Extract failed: {exc}")
            return None

    # ------------------------------------------------------------------
    # Crypto helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _encrypt(data, key):
        if isinstance(data, str):
            data = data.encode("utf-8")
        cipher = AES.new(key, AES.MODE_CBC)
        return cipher.iv + cipher.encrypt(pad(data, AES.block_size))

    @staticmethod
    def _decrypt(blob, key):
        iv, ct = blob[:16], blob[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8")

    # ------------------------------------------------------------------
    # Bit helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _int_to_bits(value, width):
        return format(value, f"0{width}b")

    @staticmethod
    def _bytes_to_bits(blob):
        return "".join(format(b, "08b") for b in blob)

    @staticmethod
    def _bits_to_bytes(bits):
        out = bytearray()
        for i in range(0, len(bits), 8):
            chunk = bits[i : i + 8]
            if len(chunk) == 8:
                out.append(int(chunk, 2))
        return bytes(out)
