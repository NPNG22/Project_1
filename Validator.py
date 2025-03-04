from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import subprocess

def validate_and_execute():
    # Load the public key
    with open("public.key", "rb") as pk_file:
        public_key = serialization.load_pem_public_key(
            pk_file.read(),
            backend=default_backend()
        )

    # Print the public key
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    print("Public Key:\n", public_key_pem)

    # Read the content of product.py
    with open("Product.py", "rb") as product_file:
        product_content = product_file.read()

    # Load the signature
    with open("Signature.bin", "rb") as sig_file:
        signature = sig_file.read()

    # Verify the signature
    try:
        public_key.verify(
            signature,
            product_content,
            ec.ECDSA(hashes.SHA256())
        )
        print("Signature is valid. Executing the program:")
        subprocess.run(["python", "Product.py"])
    except:
        print("Signature is invalid. Execution denied.")

if __name__ == "__main__":
    validate_and_execute()