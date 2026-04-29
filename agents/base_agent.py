import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class BaseAgent:

    def __init__(self, agent_id: str, agent_name: str, agent_type: str, capabilities: list):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.agent_type = agent_type
        self.capabilities = capabilities
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._public_key = self._private_key.public_key()
        self.public_key_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def sign_request(self, request_body: str) -> str:
        signature = self._private_key.sign(
            request_body.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return signature.hex()

    def verify_signature(self, request_body: str, signature_hex: str, public_key_pem: str) -> bool:
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode())
            pub_key.verify(
                bytes.fromhex(signature_hex),
                request_body.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def get_registration_data(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "capabilities": self.capabilities,
            "encryption_public_key": self.public_key_pem,
        }
