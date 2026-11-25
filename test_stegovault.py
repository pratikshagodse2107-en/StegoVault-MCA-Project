import os
import pytest
import numpy as np
from PIL import Image
from stego_engine import hide_secret_in_image, extract_secret_from_image
from analysis_engine import compute_ssim, chi_square_lsb_test
from db_manager import register_user, verify_user

def _make_sample_image(width=200, height=200) -> Image.Image:
    x = np.linspace(20, 230, width, dtype=np.uint8)
    y = np.linspace(30, 220, height, dtype=np.uint8)
    xv, yv = np.meshgrid(x, y)
    r = xv
    g = yv
    b = ((xv.astype(np.uint16) + yv.astype(np.uint16)) // 2).astype(np.uint8)
    arr = np.stack([r, g, b], axis=-1)
    return Image.fromarray(arr)


def test_hide_and_extract_same_message():
    img = _make_sample_image()
    secret = b"Top Secret MCA Project Intelligence!"
    stego, _ = hide_secret_in_image(img, secret, "StrongKey@123")
    recovered, filename, is_file = extract_secret_from_image(stego, "StrongKey@123")
    assert recovered == secret
    assert is_file is False

def test_wrong_password_rejected():
    img = _make_sample_image()
    stego, _ = hide_secret_in_image(img, b"Confidential Data", "CorrectPass@1")
    with pytest.raises(Exception):
        extract_secret_from_image(stego, "WrongPass@999")

def test_tampered_image_detected():
    img = _make_sample_image()
    stego, _ = hide_secret_in_image(img, b"Integrity Check Payload", "Key@2026")
    arr = np.array(stego)
    # Tamper with multiple pixels in the stego image
    arr[10:40, 10:40, 0] ^= 0xFF
    tampered = Image.fromarray(arr)
    with pytest.raises(Exception):
        extract_secret_from_image(tampered, "Key@2026")

def test_message_too_big_for_image():
    tiny_img = _make_sample_image(width=20, height=20)
    huge_uncompressible_payload = os.urandom(5000)
    with pytest.raises(ValueError, match="exceeds image capacity"):
        hide_secret_in_image(tiny_img, huge_uncompressible_payload, "Pass@123")


def test_marathi_unicode_text():
    img = _make_sample_image()
    marathi_text = "स्टेगो व्हॉल्ट हा माझा एमसीए (MCA) सायबर सिक्युरिटी प्रोजेक्ट आहे! 🔒🛡️"
    stego, _ = hide_secret_in_image(img, marathi_text.encode("utf-8"), "MarathiKey@1")
    recovered_bytes, _, _ = extract_secret_from_image(stego, "MarathiKey@1")
    assert recovered_bytes.decode("utf-8") == marathi_text

def test_quality_and_steganalysis_metrics():
    img = _make_sample_image()
    stego, _ = hide_secret_in_image(img, b"Short secret", "Stealth@123")
    ssim = compute_ssim(img, stego)
    chi = chi_square_lsb_test(stego)
    assert ssim > 0.99
    assert chi["risk"] == "STEALTH VERIFIED"
