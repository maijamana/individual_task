import hashlib
from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import numpy as np

def load_private_key(path: str = "private_key.pem") -> rsa.RSAPrivateKey:
    """
    Loads an RSA private key from a PEM-encoded file.

    Args:
        path (str): Path to the private key PEM file.

    Returns:
        rsa.RSAPrivateKey: The loaded RSA private key object.
    """

    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def get_image_bytes_cleaned(img: Image.Image) -> bytes:
    """
    Returns a byte representation of the image with all LSBs set to 0.

    This ensures that the signature bits embedded in the image do not affect
    the image hash during verification.

    Args:
        img (PIL.Image.Image): The input image (RGB).

    Returns:
        bytes: Byte data of the cleaned image.
    """
    data = np.array(img)
    mask = np.uint8(0xFE)
    cleaned = data & mask
    return cleaned.tobytes()


def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Creates a digital signature for the input data using RSA and SHA-256.

    Args:
        data (bytes): The data to be signed (typically the image hash).
        private_key (rsa.RSAPrivateKey): The RSA private key to sign with.

    Returns:
        bytes: The resulting digital signature.
    """
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def embed_signature_lsb(img: Image.Image, signature: bytes) -> Image.Image:
    """
    Embeds a digital signature into the least significant bits of an image.

    Args:
        img (PIL.Image.Image): The original image (RGB).
        signature (bytes): The digital signature to embed.

    Returns:
        PIL.Image.Image: A new image with the signature embedded in its pixels.
    
    Raises:
        ValueError: If the signature is too large to be embedded.
    """
    data = np.array(img)
    flat = data.flatten()

    bits = ''.join(f'{byte:08b}' for byte in signature)
    if len(bits) > len(flat):
        raise ValueError("Signature too large to embed.")

    mask = np.uint8(0xFE)  # замість ~1

    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & mask) | int(bit)

    embedded = flat.reshape(data.shape)
    return Image.fromarray(embedded.astype(np.uint8))



def main():
    """
    Main function to:
        1. Load the private key.
        2. Open and clean the input image.
        3. Compute the SHA-256 hash of the cleaned image.
        4. Sign the hash using RSA.
        5. Embed the signature into the image using LSB steganography.
        6. Save the signed image.
    """
    input_path = "original_image.jpg"  # JPEG image
    output_path = "signed_image.png"
    private_key = load_private_key()

    img = Image.open(input_path).convert("RGB")
    image_bytes = get_image_bytes_cleaned(img)

    image_hash = hashlib.sha256(image_bytes).digest()  # Cleaned image hash
    signature = sign_data(image_hash, private_key)

    img_with_signature = embed_signature_lsb(img, signature)
    img_with_signature.save(output_path, "PNG")
    print(f"Signed image saved to {output_path}")

if __name__ == "__main__":
    main()
