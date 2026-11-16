"""Shared privacy-preserving fields for structured operational logs."""

import hashlib
import hmac
import os
import secrets
import threading

import boto3

LOG_SECRET_ID = os.environ.get("LOG_SECRET_ID", "")
_key = None
_key_lock = threading.Lock()
_local_key = secrets.token_bytes(32)


def _pseudonym_key():
    """Load the deployment log key once; local/test processes use an unlinkable random key."""
    global _key
    if _key is None:
        with _key_lock:
            if _key is None:
                if LOG_SECRET_ID:
                    raw = boto3.client("secretsmanager").get_secret_value(SecretId=LOG_SECRET_ID)["SecretString"]
                    if not raw:
                        raise RuntimeError("log pseudonym key is empty")
                    _key = raw.encode("utf-8")
                else:
                    _key = _local_key
    return _key


def uref(identity):
    """Return a short keyed pseudonym without logging the source identity."""
    digest = hmac.new(_pseudonym_key(), str(identity or "").encode("utf-8"), hashlib.sha256).hexdigest()
    return "u_" + digest[:16]


def exception_fields(error):
    """Return exception metadata that cannot include provider, request, user, driver, or model text."""
    return {"error_type": type(error).__name__}
