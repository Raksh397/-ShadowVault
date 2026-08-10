"""
wow_embed.py - WOW (Wavelet Obtained Weights) interface.

This implementation reuses the LSB core engine as a placeholder backend.
A production build would implement wavelet-domain, content-adaptive
embedding with per-pixel distortion costs.
"""

from .lsb_embed import LSBSteganography


class WowSteganography:
    """WOW steganography facade backed by the LSB core engine."""

    def __init__(self, payload=0.3):
        self.payload = payload
        self._engine = LSBSteganography(payload)

    def embed_file(self, cover_path, output_path, data, key):
        return self._engine.embed_file(cover_path, output_path, data, key)

    def extract_file(self, stego_path, key):
        return self._engine.extract_file(stego_path, key)
