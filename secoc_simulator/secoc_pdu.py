"""
secoc_pdu.py — Secured I-PDU Builder and Verifier.

This is the core module that ties together the CryptoEngine and
FreshnessManager to produce and verify Secured I-PDUs per AUTOSAR SecOC.

Secured I-PDU structure:
  ┌──────────────────────┬─────────────────┬──────────────┐
  │ Authentic I-PDU Data │ Freshness Value │ Truncated MAC│
  │  (N bytes)           │  (M bytes)      │  (T bytes)   │
  └──────────────────────┴─────────────────┴──────────────┘
"""

from __future__ import annotations

from typing import Optional

from .types import (
    AuthenticPDU,
    KeyEntry,
    MACAlgorithm,
    PDUProfile,
    SecOCConfig,
    SecuredPDU,
    VerificationResult,
    VerificationStatus,
)
from .crypto_engine import CryptoEngine
from .freshness_manager import FreshnessManager


class SecOCPDUBuilder:
    """
    Builds and verifies Secured I-PDUs per AUTOSAR SecOC specification.
    """

    def __init__(
        self,
        config: SecOCConfig,
        freshness_manager: FreshnessManager,
    ) -> None:
        """
        Initialize the PDU builder.

        Args:
            config: Global SecOC configuration.
            freshness_manager: Shared freshness counter manager.
        """
        self._config = config
        self._freshness = freshness_manager
        self._crypto_cache: dict[str, CryptoEngine] = {}

    def _get_crypto_engine(self, ecu_name: str) -> CryptoEngine:
        """
        Get or create a CryptoEngine for the given ECU.

        Caches engines to avoid repeated key setup.
        """
        if ecu_name not in self._crypto_cache:
            if ecu_name not in self._config.keys:
                raise KeyError(
                    f"No key configured for ECU '{ecu_name}'. "
                    f"Available: {list(self._config.keys.keys())}"
                )
            key_entry = self._config.keys[ecu_name]
            self._crypto_cache[ecu_name] = CryptoEngine(
                algorithm=self._config.mac_algorithm,
                key=key_entry.key_bytes,
            )
        return self._crypto_cache[ecu_name]

    def _get_profile(self, pdu_id: int) -> PDUProfile:
        """Look up the PDU profile by ID."""
        if pdu_id not in self._config.pdu_profiles:
            raise KeyError(
                f"No PDU profile for ID 0x{pdu_id:03X}. "
                f"Available: {[hex(k) for k in self._config.pdu_profiles.keys()]}"
            )
        return self._config.pdu_profiles[pdu_id]

    def build_secured_pdu(
        self,
        pdu_id: int,
        payload: bytes,
        freshness_override: Optional[int] = None,
    ) -> SecuredPDU:
        """
        Build a Secured I-PDU from an Authentic I-PDU.

        Steps:
          1. Look up PDU profile and source ECU key
          2. Obtain freshness value (counter)
          3. Compute MAC over (PDU_ID || Payload || Freshness)
          4. Truncate MAC to configured bit-length
          5. Assemble Secured I-PDU

        Args:
            pdu_id: PDU identifier.
            payload: Authentic payload bytes.
            freshness_override: If set, use this freshness value instead
                                of auto-incrementing (for testing).

        Returns:
            SecuredPDU containing the authenticated frame data.
        """
        profile = self._get_profile(pdu_id)
        crypto = self._get_crypto_engine(profile.source_ecu)

        # Validate payload length
        if len(payload) != profile.payload_length:
            raise ValueError(
                f"Payload length mismatch for PDU 0x{pdu_id:03X} "
                f"'{profile.name}': expected {profile.payload_length}, "
                f"got {len(payload)}"
            )

        # Get freshness value
        if freshness_override is not None:
            freshness = freshness_override
        else:
            freshness = self._freshness.get_tx_freshness(pdu_id)

        # Compute truncated MAC
        truncated_mac, full_mac = crypto.compute_truncated_mac(
            pdu_id=pdu_id,
            authentic_payload=payload,
            freshness_value=freshness,
            freshness_bits=profile.freshness_bits,
            truncated_bits=profile.truncated_mac_bits,
        )

        return SecuredPDU(
            pdu_id=pdu_id,
            authentic_payload=payload,
            freshness_value=freshness,
            freshness_bytes_len=profile.freshness_bytes,
            truncated_mac=truncated_mac,
            full_mac=full_mac,
        )

    def verify_secured_pdu(
        self,
        pdu_id: int,
        secured_payload: bytes,
    ) -> VerificationResult:
        """
        Verify a received Secured I-PDU.

        Steps:
          1. Parse the Secured I-PDU into components
          2. Verify freshness value
          3. Recompute and compare MAC

        Args:
            pdu_id: PDU identifier.
            secured_payload: Raw secured payload bytes.

        Returns:
            VerificationResult with status and diagnostic info.
        """
        try:
            profile = self._get_profile(pdu_id)
        except KeyError as e:
            return VerificationResult(
                status=VerificationStatus.KEY_NOT_FOUND,
                pdu_id=pdu_id,
                detail=str(e),
            )

        # Calculate expected lengths
        expected_len = (
            profile.payload_length
            + profile.freshness_bytes
            + profile.truncated_mac_bytes
        )

        if len(secured_payload) != expected_len:
            return VerificationResult(
                status=VerificationStatus.INVALID_LENGTH,
                pdu_id=pdu_id,
                detail=(
                    f"Expected {expected_len} bytes "
                    f"(payload={profile.payload_length} + "
                    f"freshness={profile.freshness_bytes} + "
                    f"mac={profile.truncated_mac_bytes}), "
                    f"got {len(secured_payload)}"
                ),
            )

        # Parse components
        payload_end = profile.payload_length
        freshness_end = payload_end + profile.freshness_bytes
        mac_end = freshness_end + profile.truncated_mac_bytes

        authentic_payload = secured_payload[:payload_end]
        freshness_bytes = secured_payload[payload_end:freshness_end]
        received_mac = secured_payload[freshness_end:mac_end]

        received_freshness = int.from_bytes(freshness_bytes, byteorder="big")

        # Verify freshness
        freshness_ok, freshness_detail = self._freshness.verify_freshness(
            pdu_id, received_freshness
        )
        if not freshness_ok:
            # Determine specific failure reason
            expected_fv = self._freshness.peek_rx(pdu_id) - 1  # was just updated
            if received_freshness < expected_fv:
                status = VerificationStatus.FRESHNESS_BEHIND
            else:
                status = VerificationStatus.FRESHNESS_EXPIRED
            return VerificationResult(
                status=status,
                pdu_id=pdu_id,
                freshness_received=received_freshness,
                freshness_expected=expected_fv,
                detail=freshness_detail,
            )

        # Verify MAC
        try:
            crypto = self._get_crypto_engine(profile.source_ecu)
        except KeyError as e:
            return VerificationResult(
                status=VerificationStatus.KEY_NOT_FOUND,
                pdu_id=pdu_id,
                detail=str(e),
            )

        expected_trunc, full_mac = crypto.compute_truncated_mac(
            pdu_id=pdu_id,
            authentic_payload=authentic_payload,
            freshness_value=received_freshness,
            freshness_bits=profile.freshness_bits,
            truncated_bits=profile.truncated_mac_bits,
        )

        if not crypto.verify_mac(
            pdu_id=pdu_id,
            authentic_payload=authentic_payload,
            freshness_value=received_freshness,
            freshness_bits=profile.freshness_bits,
            truncated_bits=profile.truncated_mac_bits,
            received_truncated_mac=received_mac,
        ):
            return VerificationResult(
                status=VerificationStatus.MAC_MISMATCH,
                pdu_id=pdu_id,
                expected_mac=expected_trunc,
                received_mac=received_mac,
                freshness_received=received_freshness,
                detail=(
                    f"MAC mismatch: expected={expected_trunc.hex().upper()}, "
                    f"received={received_mac.hex().upper()}"
                ),
            )

        return VerificationResult(
            status=VerificationStatus.OK,
            pdu_id=pdu_id,
            expected_mac=expected_trunc,
            received_mac=received_mac,
            freshness_received=received_freshness,
            detail="Secured I-PDU verified successfully",
        )

    def build_and_verify_roundtrip(
        self,
        pdu_id: int,
        payload: bytes,
    ) -> tuple[SecuredPDU, VerificationResult]:
        """
        Build a Secured PDU and immediately verify it (roundtrip test).

        Args:
            pdu_id: PDU identifier.
            payload: Authentic payload.

        Returns:
            Tuple of (SecuredPDU, VerificationResult).
        """
        secured = self.build_secured_pdu(pdu_id, payload)
        result = self.verify_secured_pdu(pdu_id, secured.secured_payload)
        return secured, result
