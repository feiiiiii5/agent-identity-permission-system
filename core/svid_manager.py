import os
import time
import uuid
import re
import logging
import threading
from dataclasses import dataclass
from typing import Optional
from datetime import datetime, timedelta, timezone
from collections import OrderedDict
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


@dataclass
class SVID:
    spiffe_id: str
    cert_pem: str
    private_key_pem: str
    expires_at: float
    agent_id: str
    trust_domain: str
    issued_at: float
    serial_number: str


@dataclass
class SVIDVerifyResult:
    valid: bool
    spiffe_id: str = ""
    agent_id: str = ""
    error: str = ""


@dataclass
class AttestationResult:
    attested: bool
    svid: Optional[SVID]
    spiffe_id: str
    attestation_token: str


class SVIDManager:

    MAX_SVIDS = 5000

    def __init__(self, trust_domain: str = "agentpass.local", key_dir: str = None):
        self.trust_domain = trust_domain
        self._svids = OrderedDict()
        self._lock = threading.Lock()
        if key_dir is None:
            key_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "keys")
        self.key_dir = key_dir
        os.makedirs(key_dir, exist_ok=True)
        self._ca_key, self._ca_cert = self._load_or_generate_ca()

    def _load_or_generate_ca(self):
        ca_key_path = os.path.join(self.key_dir, "svid_ca_private.pem")
        ca_cert_path = os.path.join(self.key_dir, "svid_ca_cert.pem")
        if os.path.exists(ca_key_path) and os.path.exists(ca_cert_path):
            try:
                with open(ca_key_path, "rb") as f:
                    ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                with open(ca_cert_path, "rb") as f:
                    ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                now = datetime.now(timezone.utc)
                if ca_cert.not_valid_after_utc > now:
                    return ca_key, ca_cert
            except Exception as e:
                logger.warning("Failed to load CA from disk, regenerating: %s", e)
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        ca_cert = self._generate_ca_cert_with_key(ca_key)
        try:
            key_pem = ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
            with open(ca_key_path, "wb") as f:
                f.write(key_pem)
            with open(ca_cert_path, "wb") as f:
                f.write(cert_pem)
        except Exception as e:
            logger.warning("Failed to persist CA to disk: %s", e)
        return ca_key, ca_cert

    def _generate_ca_cert(self):
        return self._generate_ca_cert_with_key(self._ca_key)

    def _generate_ca_cert_with_key(self, ca_key):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"AgentPass CA - {self.trust_domain}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentPass"),
        ])
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(
                datetime.now(timezone.utc)
                - timedelta(days=1)
            )
            .not_valid_after(
                datetime.now(timezone.utc)
                + timedelta(days=365)
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

    def issue_svid(self, agent_id: str, agent_type: str, ttl_seconds: int = 3600) -> SVID:
        spiffe_id = f"spiffe://{self.trust_domain}/ns/prod/agent/{agent_id}"

        agent_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_seconds)

        san = x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(spiffe_id),
        ])

        serial_number = x509.random_serial_number()

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"agentpass-{agent_id}"),
            ]))
            .issuer_name(self._ca_cert.subject)
            .public_key(agent_key.public_key())
            .serial_number(serial_number)
            .not_valid_before(now - timedelta(seconds=60))
            .not_valid_after(expires)
            .add_extension(san, critical=False)
            .sign(self._ca_key, hashes.SHA256(), default_backend())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        private_key_pem = agent_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        svid = SVID(
            spiffe_id=spiffe_id,
            cert_pem=cert_pem,
            private_key_pem=private_key_pem,
            expires_at=expires.timestamp(),
            agent_id=agent_id,
            trust_domain=self.trust_domain,
            issued_at=now.timestamp(),
            serial_number=str(serial_number),
        )

        with self._lock:
            self._svids[agent_id] = svid
            while len(self._svids) > self.MAX_SVIDS:
                self._svids.popitem(last=False)

        return svid

    def verify_svid(self, cert_pem: str) -> SVIDVerifyResult:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            self._ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception as e:
            return SVIDVerifyResult(valid=False, error=f"Certificate verification failed: {e}")

        now = datetime.now(timezone.utc)
        if cert.not_valid_after_utc < now:
            return SVIDVerifyResult(valid=False, error="Certificate expired")

        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            spiffe_id = ""
            for name in san_ext.value:
                if isinstance(name, x509.UniformResourceIdentifier):
                    spiffe_id = name.value
                    break
        except Exception:
            return SVIDVerifyResult(valid=False, error="No SPIFFE ID in SAN")

        agent_id = ""
        if spiffe_id:
            parts = spiffe_id.split("/")
            agent_id = parts[-1] if parts else ""

        return SVIDVerifyResult(valid=True, spiffe_id=spiffe_id, agent_id=agent_id)

    def get_svid(self, agent_id: str) -> Optional[SVID]:
        with self._lock:
            return self._svids.get(agent_id)

    def rotate_svid(self, agent_id: str) -> SVID:
        with self._lock:
            old = self._svids.get(agent_id)
        agent_type = ""
        if old:
            parts = old.spiffe_id.split("/")
            agent_type = parts[-1] if parts else old.agent_id
        new_svid = self.issue_svid(agent_id, agent_type)
        return new_svid

    def get_trust_bundle(self) -> dict:
        ca_pem = self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        return {
            "trust_domain": self.trust_domain,
            "x509_authorities": [ca_pem],
            "refresh_hint": 3600,
        }

    def attest_agent(self, agent_id: str, agent_type: str, public_key_pem: str) -> AttestationResult:
        if not agent_id or not re.match(r'^[a-zA-Z0-9_-]+$', agent_id):
            return AttestationResult(attested=False, svid=None, spiffe_id="", attestation_token="")

        try:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            pub = load_pem_public_key(public_key_pem.encode(), default_backend())
            if not isinstance(pub, (rsa.RSAPublicKey,)):
                return AttestationResult(attested=False, svid=None, spiffe_id="", attestation_token="")
        except Exception:
            try:
                from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
                pub2 = load_pem_public_key(public_key_pem.encode(), default_backend())
                if not isinstance(pub2, (rsa.RSAPublicKey, EllipticCurvePublicKey)):
                    return AttestationResult(attested=False, svid=None, spiffe_id="", attestation_token="")
            except Exception:
                return AttestationResult(attested=False, svid=None, spiffe_id="", attestation_token="")

        svid = self.issue_svid(agent_id, agent_type)
        token = uuid.uuid4().hex

        return AttestationResult(
            attested=True,
            svid=svid,
            spiffe_id=svid.spiffe_id,
            attestation_token=token,
        )
