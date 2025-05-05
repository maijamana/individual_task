from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys(private_key_path: str = "private_key.pem", public_key_path: str = "public_key.pem") -> None:
    """
    Generates a 4096-bit RSA key pair and saves them as PEM files.

    Args:
        private_key_path (str): Path to save the private key file.
        public_key_path (str): Path to save the public key file.

    The private key is saved in PKCS8 format without encryption.
    The public key is saved in SubjectPublicKeyInfo format.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()

    # Save private key to PEM file
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key to PEM file
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Keys generated and saved.")

if __name__ == "__main__":
    generate_keys()
