"""Compatibility exports for the canonical peppered HMAC key implementation."""

from app.core.security import generate_api_key, hash_api_key, verify_api_key

__all__ = ["generate_api_key", "hash_api_key", "verify_api_key"]
