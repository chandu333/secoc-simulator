"""
crypto_engine.py — Cryptographic MAC generation and verification.

Implements:
  - CMAC-AES128 (NIST SP 800-38B) via the `cryptography` library
  - HMAC-SHA256 (RFC 2104) via stdlib
  - MAC truncation per AUTOSAR SecOC specification

The DataToAuth (input to MAC) is constructed as:
  Secured I-PDU Header (PDU ID) || Authentic I-PDU Data || Freshness Value
"""

from __future__ import annotations

import hmac as hmac_mod
import hashlib
import struct

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

from .types import MACAlgorithm


class CryptoEngine:
    """
    SecOC Cryptographic Engine.

    Responsible for MAC computation and truncation using either
    CMAC-AES128 or HMAC-SHA256.
    """

    def __init__(self, algorithm: MACAlgorithm, key: bytes) -> None:
        self._algorithm = algorithm
        self._key = key
        self._validate_key()

    def _validate_key(self) -> None:
        if self._algorithm == MACAlgorithm.CMAC_AES128:
            if len(self._key) != 16:
                raise ValueError(
                    f"CMAC-AES128 requires 16-byte key, got {len(self._key)}"
                )
        elif self._algorithm == MACAlgorithm.HMAC_SHA256:
            if len(self._key) not in (16, 32):
                raise ValueError(
                    f"HMAC-SHA256 requires 16 or 32-byte key, "
                    f"got {len(self._key)}"
                )

    def _build_data_to_authenticate(
        self,
        pdu_id: int,
        authentic_payload: bytes,
        freshness_value: int,
        freshness_bits: int,
    ) -> bytes:
        """
        Construct the DataToAuth per AUTOSAR SecOC.

        DataToAuth = PDU_ID (2 bytes, big-endian)
                   || Authentic I-PDU Data
                   || Freshness Value
        """
        pdu_id_bytes = struct.pack(">H", pdu_id & 0xFFFF)
        fv_byte_len = (freshness_bits + 7) // 8
        fv_bytes = freshness_value.to_bytes(fv_byte_len, byteorder="big")
        return pdu_id_bytes + authentic_payload + fv_bytes

    def compute_mac(
        self,
        pdu_id: int,
        authentic_payload: bytes,
        freshness_value: int,
        freshness_bits: int,
    ) -> bytes:
        """Compute full MAC over the DataToAuth."""
        data = self._build_data_to_authenticate(
            pdu_id, authentic_payload, freshness_value, freshness_bits
        )

        if self._algorithm == MACAlgorithm.CMAC_AES128:
            return self._compute_cmac(data)
        elif self._algorithm == MACAlgorithm.HMAC_SHA256:
            return self._compute_hmac(data)
        else:
            raise ValueError(f"Unsupported algorithm: {self._algorithm}")

    def _compute_cmac(self, data: bytes) -> bytes:
        """Compute AES-128-CMAC (NIST SP 800-38B)."""
        c = CMAC(algorithms.AES128(self._key))
        c.update(data)
        return c.finalize()

    def _compute_hmac(self, data: bytes) -> bytes:
        """Compute HMAC-SHA256 (RFC 2104)."""
        return hmac_mod.new(self._key, data, hashlib.sha256).digest()

    def compute_truncated_mac(
        self,
        pdu_id: int,
        authentic_payload: bytes,
        freshness_value: int,
        freshness_bits: int,
        truncated_bits: int,
    ) -> tuple[bytes, bytes]:
        """
        Compute and truncate the MAC.

        AUTOSAR SecOC truncates the MAC to fit within CAN frame
        constraints. Truncation takes the most-significant bits.

        Returns:
            Tuple of (truncated_mac, full_mac).
        """
        full_mac = self.compute_mac(
            pdu_id, authentic_payload, freshness_value, freshness_bits
        )
        truncated = self._truncate_mac(full_mac, truncated_bits)
        return truncated, full_mac

    @staticmethod
    def _truncate_mac(mac: bytes, bits: int) -> bytes:
        """
        Truncate MAC to the specified number of bits (MSB-first).

        Takes the most-significant `bits` from the MAC and returns
        them as a byte string (zero-padded on the right if not
        byte-aligned).
        """
        if bits <= 0:
            raise ValueError("Truncation bits must be positive")

        full_bytes = bits // 8
        remaining_bits = bits % 8

        if remaining_bits == 0:
            return mac[:full_bytes]
        else:
            result = bytearray(mac[: full_bytes + 1])
            mask = (0xFF << (8 - remaining_bits)) & 0xFF
            result[-1] &= mask
            return bytes(result)

    def verify_mac(
        self,
        pdu_id: int,
        authentic_payload: bytes,
        freshness_value: int,
        freshness_bits: int,
        truncated_bits: int,
        received_truncated_mac: bytes,
    ) -> bool:
        """
        Verify a received truncated MAC against a recomputed one.

        Uses constant-time comparison to prevent timing attacks.
        """
        expected_trunc, _ = self.compute_truncated_mac(
            pdu_id, authentic_payload, freshness_value,
            freshness_bits, truncated_bits,
        )
        return hmac_mod.compare_digest(expected_trunc, received_truncated_mac)
