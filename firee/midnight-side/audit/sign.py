"""Ed25519 signing for the audit hash-chain root hash."""

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

PRIVATE_KEY_PATH = Path(__file__).parent / "firewall_signing_key.pem"
PUBLIC_KEY_PATH = Path(__file__).parent / "firewall_verify_key.pem"


def generate_keypair(private_path: Path = PRIVATE_KEY_PATH, public_path: Path = PUBLIC_KEY_PATH) -> None:
    private_key = Ed25519PrivateKey.generate()
    private_path.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    public_path.write_bytes(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    print(f"Private key: {private_path}\nPublic key:  {public_path}")


def sign_root_hash(root_hash_hex: str, private_key_path: Path = PRIVATE_KEY_PATH) -> str:
    private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    signature = private_key.sign(bytes.fromhex(root_hash_hex))
    return signature.hex()


def verify_signature(root_hash_hex: str, signature_hex: str, verify_key_path: Path = PUBLIC_KEY_PATH) -> bool:
    public_key = serialization.load_pem_public_key(verify_key_path.read_bytes())
    if not isinstance(public_key, Ed25519PublicKey):
        return False
    try:
        public_key.verify(bytes.fromhex(signature_hex), bytes.fromhex(root_hash_hex))
        return True
    except InvalidSignature:
        return False


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python sign.py generate | sign <root_hash_hex> | verify <root_hash_hex> <signature_hex>")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "generate":
        generate_keypair()
    elif cmd == "sign":
        print(sign_root_hash(sys.argv[2]))
    elif cmd == "verify":
        print("VALID" if verify_signature(sys.argv[2], sys.argv[3]) else "INVALID")
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
