import hashlib
from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature
import numpy as np

def load_public_key(path: str = "public_key.pem") -> rsa.RSAPublicKey:
    """
    Loads an RSA public key from a PEM-encoded file.

    Args:
        path (str): Path to the public key PEM file.

    Returns:
        rsa.RSAPublicKey: The loaded RSA public key object.
    """
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def extract_signature_lsb(img: Image.Image, signature_len_bytes: int) -> bytes:
    """
    Extracts a digital signature from the least significant bits of an image.

    Args:
        img (PIL.Image.Image): The signed image.
        signature_len_bytes (int): Length of the signature in bytes.

    Returns:
        bytes: The extracted digital signature.
    """
    data = np.array(img)
    flat = data.flatten()
    bits = [str(flat[i] & 1) for i in range(signature_len_bytes * 8)]
    bytes_list = [int(''.join(bits[i:i+8]), 2) for i in range(0, len(bits), 8)]
    return bytes(bytes_list)

def get_image_bytes_cleaned(img: Image.Image) -> bytes:
    """
    Returns a byte representation of the image with LSBs cleared.

    Args:
        img (PIL.Image.Image): The signed image.

    Returns:
        bytes: Byte data of the cleaned image (LSBs zeroed out).
    """
    data = np.array(img)
    mask = np.uint8(0xFE)  # 11111110
    cleaned = data & mask  # обнуляємо LSB
    return cleaned.tobytes()

def verify_signature(public_key: rsa.RSAPublicKey, signature: bytes, image_hash: bytes) -> bool:
    """
    Verifies the digital signature of an image using its SHA-256 hash.

    Args:
        public_key (rsa.RSAPublicKey): The public RSA key.
        signature (bytes): The extracted digital signature.
        image_hash (bytes): The SHA-256 hash of the cleaned image.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            image_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def main():
    """
    Main function to verify a signed image:
        1. Load the signed image.
        2. Extract the embedded signature from its LSBs.
        3. Compute SHA-256 hash of the cleaned image.
        4. Verify the signature using the public RSA key.
    """
    path = "signed_image.png"  # JPEG image
    img = Image.open(path).convert("RGB")

    public_key = load_public_key()
    signature_len = public_key.key_size // 8  # e.g., 4096 bits → 512 bytes
    signature = extract_signature_lsb(img, signature_len)

    image_hash = hashlib.sha256(get_image_bytes_cleaned(img)).digest()  # Cleaned image hash

    if verify_signature(public_key, signature, image_hash):
        print("Signature is valid.")
    else:
        print("Signature is invalid.")

if __name__ == "__main__":
    main()
