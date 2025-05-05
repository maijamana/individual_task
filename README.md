# Individual task
This project demonstrates how to create and verify digital signatures for images using RSA encryption. The signature is embedded in the image using LSB steganography and can be verified using the corresponding public key. The solution is implemented in Python and relies on RSA for signing and verifying the image hash.

## Project Overview

The project provides:
1. **Key Generation**: Generate an RSA public-private key pair.
2. **Image Signing**: Sign an image by embedding the digital signature (generated from the hash of the image) into the image using LSB steganography.
3. **Signature Verification**: Extract and verify the embedded signature using the public key to ensure image integrity.

This project uses Python libraries such as:
- `cryptography` for RSA key generation, signing, and verification.
- `PIL` (Pillow) for image manipulation.
- `numpy` for efficient image data manipulation.
  
**The project uses a two-step approach**:
1. Digital Signature Creation and Embedding:
    - The image is first cleaned by zeroing out its least significant bits (LSBs) to avoid embedding noise.
    - A SHA-256 hash of this cleaned image is computed.
    - The hash is signed using a 4096-bit RSA private key (PKCS#8 format).
    - The signature (512 bytes) is then embedded bit-by-bit into the LSBs of the original image using steganography.
    - The result is a visually identical image that now contains an invisible, verifiable digital signature.

2. Signature Verification:
    - The image is loaded and the embedded signature is extracted from its LSBs.
    - The image is cleaned again to match the state used during signing.
    - A SHA-256 hash is computed over the cleaned image.
    - Using the corresponding RSA public key, the extracted signature is verified against the computed hash.
    - The result confirms whether the image was signed with the private key and hasn't been altered since.

## Potential Use Cases
Potential applications include:

- **Digital watermarking**: To protect image ownership and verify authenticity.
- **Tamper detection**: Ensure that images haven't been altered since being signed.
- **Secure image transmission**: Embedding a verifiable signature allows secure sharing of visual content, especially in journalism, legal, and research fields.
- **Steganographic security**: Embedding signatures in image LSBs makes them harder to detect and tamper with, increasing robustness against casual inspection.



## Features

- RSA key pair generation (4096 bits).
- Embedding digital signature in image (using LSB steganography).
- Verifying the image's authenticity by checking the signature.
- Supports image formats such as PNG and JPEG.

## Installation

To install the required dependencies, create a virtual environment and use `pip` to install the packages from the `requirements.txt` file.

1. Clone this repository:
    ```bash
    git clone https://github.com/your-username/rsa-digital-signature-for-images.git
    ```

2. Navigate into the project directory:
    ```bash
    cd rsa-digital-signature-for-images
    ```

3. Create and activate a virtual environment:
    ```bash
    python -m venv venv
    # On Windows:
    .\venv\Scripts\activate
    # On Mac/Linux:
    source venv/bin/activate
    ```

4. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Key Generation

To generate the RSA public and private keys, run the following command:

```bash
python generate_keys.py
```

This will generate two files:
- `private_key.pem`
- `public_key.pem`

These keys will be used for signing and verifying the image.

## Sign Image

To sign an image, use the `sign_image.py` script:

```bash
python sign_image.py
```
This will:

1. Load the image (`original_image.jpg`).

2. Generate a hash of the image.

3. Sign the hash with the private key.

4. Embed the signature into the image using LSB steganography.

5. Save the signed image as `signed_image.png`.

If the signature is valid, the script will print:

```bash
Signature is valid.
```

Otherwise:
```bash
Signature is invalid.
```

## Code Structure
- **generate_keys.py**: Generates an RSA public-private key pair.
- **sign_image.py**: Signs the image by embedding the RSA signature in the image using LSB steganography.
- **verify_image.py**: Verifies the signature of the signed image.
- **requirements.txt**: Lists all dependencies required to run the project.

