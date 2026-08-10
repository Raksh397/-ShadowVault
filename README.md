# 🛡️ ShadowVault — Steganography & Forensic Analysis Suite

A complete web platform for hiding encrypted data in images, detecting hidden
content, and generating professional forensic PDF reports.

> Rebuilt from scratch as an independent implementation.

## ✨ Features

| Module | Description |
|---|---|
| **Text Embed** | Hide AES-256-encrypted text in images (LSB / HUGO / WOW) |
| **Image Embed** | Hide a whole image inside another image (2-bit LSB) |
| **Detect** | Multi-algorithm extraction-based detection with auto algorithm ID |
| **Extract** | Recover & decrypt hidden messages, with algorithm verification |
| **Forensic Reports** | PDF reports with difference maps, ELA, LSB planes, histograms, PSNR/SSIM/MSE |

## 🚀 Quick Start

```bash
cd shadowvault
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000**.

## 📁 Structure

```
shadowvault/
├── app.py                      # Flask application & API routes
├── forensic_report.py          # PDF forensic report generator
├── requirements.txt
├── .encryption_key             # AES-256 key (auto-generated on first run)
├── shadowvault/
│   └── algorithms/
│       ├── lsb_embed.py        # LSB + AES-256-CBC core engine
│       ├── hugo_embed.py       # HUGO facade
│       ├── wow_embed.py        # WOW facade
│       └── image_hide.py       # 2-bit LSB image-in-image
├── templates/                  # Jinja2 UI (home/embed/detect/extract/image)
├── static/
│   ├── css/style.css
│   ├── generated/              # stego images
│   └── reports/                # PDF reports
├── uploads/                    # temp uploads
└── tests/                      # pytest suite
```

## 🔌 API

| Endpoint | Method | Purpose |
|---|---|---|
| `/perform_embed` | POST | Embed text (`image`, `message`, `algorithm`) |
| `/perform_detect` | POST | Detect hidden data (`image`) |
| `/perform_extract` | POST | Extract text (`image`, `algorithm`) |
| `/embed_image_in_image` | POST | Hide image (`cover`, `secret`) |
| `/extract_image_from_image` | POST | Recover hidden image (`stego`) |
| `/generate_report` | POST (JSON) | Build forensic PDF |
| `/download_report/<file>` | GET | Download report |

### Example

```python
import requests

requests.post(
    "http://127.0.0.1:5000/perform_embed",
    files={"image": open("cover.png", "rb")},
    data={"message": "meet me at midnight", "algorithm": "wow"},
)
```

## 🧪 Testing

```bash
python -m pytest tests/ -v
```

Covers algorithm round-trips (all three engines), image-in-image round-trip,
wrong-key rejection, Flask page loads, and the full
embed → detect → extract API flow.

## 🔒 Security Notes

- All text payloads are encrypted with AES-256-CBC before embedding.
- The key is stored in `.encryption_key` (generated once, persisted).
- Never commit `.encryption_key` to version control.
- Uploads are validated, size-limited (16 MB), and filenames sanitized.

## ⚠️ Disclaimer

For **educational and authorized security research use only**. Steganography
may be regulated in some jurisdictions — always obtain permission before
analyzing systems or images you do not own.
