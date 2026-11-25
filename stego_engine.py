import numpy as np
from PIL import Image
import hashlib, secrets, struct, zlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _derive_aes_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
    )
    return kdf.derive(password.encode("utf-8"))

def _get_pixel_indices(total_channels: int, password: str) -> np.ndarray:
    """Generates a deterministic pseudo-random permutation of pixel channels from the password."""
    seed_bytes = hashlib.sha256(f"STEGOVAULT_PRNG::{password}".encode("utf-8")).digest()
    seed_int = int.from_bytes(seed_bytes[:16], "big")
    rng = np.random.Generator(np.random.PCG64(seed_int))
    return rng.permutation(total_channels)

def pack_and_encrypt_payload(raw_bytes: bytes, filename: str, is_file: bool, password: str) -> bytes:
    """Compresses payload with Zlib and encrypts with AES-256-GCM (No plaintext signature)."""
    compressed = zlib.compress(raw_bytes, level=9)
    name_bytes = filename.encode("utf-8")[:255]
    flags = 1 if is_file else 0
    
    # Inner plaintext structure: [1B flags][1B name_len][name_bytes][compressed_data]
    inner_plain = struct.pack("BB", flags, len(name_bytes)) + name_bytes + compressed
    
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive_aes_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, inner_plain, None)
    
    # Outer binary packet: [16B salt][12B nonce][4B ciphertext_len][ciphertext]
    return salt + nonce + struct.pack(">I", len(ciphertext)) + ciphertext

def decrypt_and_unpack_payload(packet: bytes, password: str) -> tuple[bytes, str, bool]:
    """Decrypts AES-256-GCM packet and decompresses Zlib payload."""
    if len(packet) < 32:
        raise ValueError("Corrupted or incomplete hidden payload.")
    
    salt = packet[:16]
    nonce = packet[16:28]
    (ct_len,) = struct.unpack(">I", packet[28:32])
    ciphertext = packet[32:32 + ct_len]
    
    key = _derive_aes_key(password, salt)
    inner_plain = AESGCM(key).decrypt(nonce, ciphertext, None)
    
    flags, name_len = struct.unpack("BB", inner_plain[:2])
    filename = inner_plain[2:2 + name_len].decode("utf-8")
    compressed = inner_plain[2 + name_len:]
    raw_bytes = zlib.decompress(compressed)
    
    return raw_bytes, filename, bool(flags)

def embed_random_lsb(image: Image.Image, packet: bytes) -> Image.Image:
    """Embeds encrypted bits into pseudo-random pixel channels determined by the password."""
    img = image.convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    flat = arr.flatten()
    
    bits = np.unpackbits(np.frombuffer(packet, dtype=np.uint8))
    if len(bits) > len(flat):
        raise ValueError(f"Payload too large ({len(bits)//8:,} B) for image capacity ({len(flat)//8:,} B)!")
    
    return flat, bits, arr.shape

def hide_secret_in_image(image: Image.Image, raw_bytes: bytes, password: str, filename: str = "message.txt", is_file: bool = False) -> tuple[Image.Image, int]:
    """Complete pipeline: Zlib Compress -> AES-256 Encrypt -> Password-Seeded Random LSB Embed."""
    packet = pack_and_encrypt_payload(raw_bytes, filename, is_file, password)
    img = image.convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    flat = arr.flatten()
    
    bits = np.unpackbits(np.frombuffer(packet, dtype=np.uint8))
    if len(bits) > len(flat):
        raise ValueError(f"Compressed payload ({len(packet):,} B) exceeds image capacity ({len(flat)//8:,} B)!")
    
    indices = _get_pixel_indices(len(flat), password)
    target_positions = indices[:len(bits)]
    flat[target_positions] = (flat[target_positions] & 0xFE) | bits
    
    return Image.fromarray(flat.reshape(arr.shape)), len(packet)

def extract_secret_from_image(image: Image.Image, password: str) -> tuple[bytes, str, bool]:
    """Complete pipeline: Password-Seeded Random LSB Extract -> AES-256 Decrypt -> Zlib Decompress."""
    img = image.convert("RGB")
    flat = np.array(img, dtype=np.uint8).flatten()
    
    if len(flat) < 256:
        raise ValueError("Image is too small to contain a StegoVault payload.")
    
    indices = _get_pixel_indices(len(flat), password)
    
    # First 32 bytes (256 bits) hold salt (16B) + nonce (12B) + ct_len (4B)
    header_bits = flat[indices[:256]] & 1
    header_bytes = np.packbits(header_bits).tobytes()
    (ct_len,) = struct.unpack(">I", header_bytes[28:32])
    
    total_bytes = 32 + ct_len
    total_bits = total_bytes * 8
    if total_bits > len(flat) or ct_len == 0:
        raise ValueError("Invalid key or no hidden data found in this image.")
    
    all_bits = flat[indices[:total_bits]] & 1
    packet = np.packbits(all_bits).tobytes()
    
    return decrypt_and_unpack_payload(packet, password)
