from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

def encode_file():
    # Load the private key
    with open("private.key", "rb") as sk_file:
        private_key = serialization.load_pem_private_key(
            sk_file.read(),
            password=None,
            backend=default_backend()
        )

    # Read the content of product.py
    with open("product.py", "rb") as product_file:
        product_content = product_file.read()

    # Sign the content
    signature = private_key.sign(
        product_content,
        ec.ECDSA(hashes.SHA256())
    )

    # Store the signature in Signature.bin
    with open("Signature.bin", "wb") as sig_file:
        sig_file.write(signature)

if __name__ == "__main__":
    encode_file()