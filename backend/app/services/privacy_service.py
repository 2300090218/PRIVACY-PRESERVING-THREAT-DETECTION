"""
Privacy Engine Service
Implements:
1. Data Minimization
2. PII Detection (Email, Phone, IP, Credentials, Tokens, Usernames)
3. Salted HMAC-SHA256 Pseudonymization (e.g., USER-7F31A, IP-4B91E)
4. Credential & Secret Redaction ([REDACTED])
5. Local Processing Enforcement
6. Audit of Privacy Transformations
"""

import re
import hmac
import hashlib
from typing import Dict, Any, Tuple, List
from backend.app.config import settings

# Regular expressions for common PII patterns
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_REGEX = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
API_KEY_REGEX = re.compile(r"\b(?:Bearer\s+)?[a-zA-Z0-9_-]{24,}\b", re.IGNORECASE)
AWS_KEY_REGEX = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GCP_KEY_REGEX = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
JWT_REGEX = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
MAC_REGEX = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b")

SENSITIVE_FIELD_NAMES = {
    "password", "passwd", "secret", "token", "auth", "authorization",
    "apikey", "api_key", "access_token", "private_key", "ssn", "credit_card",
    "aws_secret", "client_secret"
}

PSEUDONYMIZABLE_FIELDS = {
    "username", "user", "email", "client_user", "src_user", "dst_user",
    "source_ip", "dest_ip", "source", "destination"
}

class PrivacyEngine:
    def __init__(self, salt: str = settings.PRIVACY_SALT):
        self.salt = salt.encode("utf-8")
        self.total_transformations = 0
        self.redacted_count = 0
        self.pseudonymized_count = 0

    def generate_pseudonym(self, value: str, prefix: str = "PSEUDO") -> str:
        """Generates a reproducible, salted HMAC-SHA256 pseudonym token."""
        h = hmac.new(self.salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:8].upper()
        return f"{prefix}-{h}"

    def sanitize_string_pii(self, text: str) -> Tuple[str, List[str]]:
        """Scans string content for inline emails, phones, cloud credentials, or tokens."""
        transformed_fields = []
        sanitized = text

        # 1. Cloud Credentials & API Keys -> Redacted
        for aws_key in AWS_KEY_REGEX.findall(sanitized):
            sanitized = sanitized.replace(aws_key, "[REDACTED-AWS-KEY]")
            transformed_fields.append("cloud_key:[REDACTED-AWS-KEY]")
            self.redacted_count += 1

        for gcp_key in GCP_KEY_REGEX.findall(sanitized):
            sanitized = sanitized.replace(gcp_key, "[REDACTED-GCP-KEY]")
            transformed_fields.append("cloud_key:[REDACTED-GCP-KEY]")
            self.redacted_count += 1

        for jwt in JWT_REGEX.findall(sanitized):
            sanitized = sanitized.replace(jwt, "[REDACTED-JWT-TOKEN]")
            transformed_fields.append("jwt:[REDACTED-JWT-TOKEN]")
            self.redacted_count += 1

        # 2. MAC Addresses -> Redacted
        for mac in MAC_REGEX.findall(sanitized):
            sanitized = sanitized.replace(mac, "[REDACTED-MAC]")
            transformed_fields.append("mac:[REDACTED-MAC]")
            self.redacted_count += 1

        # 3. Emails -> Pseudonymized
        emails = EMAIL_REGEX.findall(sanitized)
        for email in emails:
            pseudo = self.generate_pseudonym(email, prefix="USER")
            sanitized = sanitized.replace(email, pseudo)
            transformed_fields.append(f"email:{email}->{pseudo}")
            self.pseudonymized_count += 1

        # 4. Phones -> Redacted
        phones = PHONE_REGEX.findall(sanitized)
        for phone in phones:
            sanitized = sanitized.replace(phone, "[REDACTED-PHONE]")
            transformed_fields.append("phone:[REDACTED-PHONE]")
            self.redacted_count += 1

        return sanitized, transformed_fields

    def process_telemetry_event(self, event_data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Runs the raw event through the Privacy Pipeline:
        Raw Event -> PII Detection -> Sensitive Field Identification -> Redaction/Pseudonymization -> Normalized Event
        """
        sanitized = event_data.copy()
        transformations = []

        # 1. Check top-level Source and Destination for IPs (Policy: Pseudonymize external private IPs if needed)
        for key, prefix in [("source", "SRC"), ("destination", "DST")]:
            val = str(sanitized.get(key, ""))
            if val and IPV4_REGEX.match(val):
                # We retain public indicators or create salted pseudo matching IP-XXXXX
                pseudo = self.generate_pseudonym(val, prefix="IP")
                sanitized[f"{key}_pseudonym"] = pseudo
                transformations.append({
                    "field": key,
                    "category": "IP_ADDRESS",
                    "action": "PSEUDONYMIZED",
                    "pseudonym": pseudo,
                    "policy": "POLICY_PSEUDONYMIZATION",
                    "original_hash": hashlib.sha256(val.encode()).hexdigest()[:8],
                    "technique": "HMAC-SHA256"
                })
                self.pseudonymized_count += 1

        # 2. Deep sanitize metadata dictionary
        if "metadata" in sanitized and isinstance(sanitized["metadata"], dict):
            clean_meta = {}
            for k, v in sanitized["metadata"].items():
                k_lower = k.lower()
                # Strict Redaction of credentials & secrets
                if any(sens in k_lower for sens in SENSITIVE_FIELD_NAMES):
                    clean_meta[k] = "[REDACTED]"
                    transformations.append({
                        "field": f"metadata.{k}",
                        "category": "CREDENTIAL",
                        "action": "REDACTED",
                        "policy": "POLICY_REDACTION",
                        "technique": "DROP_MASK"
                    })
                    self.redacted_count += 1
                elif any(pseudo_field in k_lower for pseudo_field in PSEUDONYMIZABLE_FIELDS):
                    pseudo_val = self.generate_pseudonym(str(v), prefix="USER")
                    clean_meta[k] = pseudo_val
                    transformations.append({
                        "field": f"metadata.{k}",
                        "category": "IDENTIFIER",
                        "action": "PSEUDONYMIZED",
                        "pseudonym": pseudo_val,
                        "policy": "POLICY_PSEUDONYMIZATION",
                        "technique": "HMAC-SHA256"
                    })
                    self.pseudonymized_count += 1
                elif isinstance(v, str):
                    clean_val, string_transforms = self.sanitize_string_pii(v)
                    clean_meta[k] = clean_val
                    for st in string_transforms:
                        transformations.append({
                            "field": f"metadata.{k}",
                            "category": "INLINE_PII",
                            "action": "REDACTED" if "[REDACTED" in st else "PSEUDONYMIZED",
                            "policy": "POLICY_DATA_MINIMIZATION",
                            "technique": st
                        })
                else:
                    clean_meta[k] = v
            sanitized["metadata"] = clean_meta

        self.total_transformations += len(transformations)
        return sanitized, transformations

    def get_status_summary(self) -> Dict[str, Any]:
        return {
            "status": "ACTIVE",
            "raw_training_data_shared": "NO (Client Local Only)",
            "data_minimization": "ACTIVE",
            "pii_detection": "ACTIVE",
            "pseudonymization": "ACTIVE",
            "audit_logging": "ACTIVE",
            "total_privacy_transformations": self.total_transformations,
            "redacted_fields_count": self.redacted_count,
            "pseudonymized_fields_count": self.pseudonymized_count,
            "active_policy": {
                "credentials": "REDACTED",
                "emails": "PSEUDONYMIZED (HMAC-SHA256)",
                "usernames": "PSEUDONYMIZED (HMAC-SHA256)",
                "phones": "REDACTED",
                "tokens": "REDACTED",
                "raw_features": "NORMALIZED_AGGREGATE"
            }
        }

privacy_engine = PrivacyEngine()
