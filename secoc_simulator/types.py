"""
types.py — Data structures and type definitions for SecOC Simulator.

Defines the core data containers used across all modules:
  - SecOCConfig: global SecOC parameters
  - KeyEntry: per-ECU symmetric key record
  - PDUProfile: per-message authentication profile
  - AuthenticPDU: the original (unprotected) PDU
  - SecuredPDU: the authenticated PDU (payload + freshness + truncated MAC)
  - VerificationResult: MAC verification outcome
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class MACAlgorithm(Enum):
    """Supported MAC algorithms per AUTOSAR SecOC."""
    CMAC_AES128 = auto()
    HMAC_SHA256 = auto()

    @classmethod
    def from_string(cls, value: str) -> "MACAlgorithm":
        mapping = {
            "CMAC-AES128": cls.CMAC_AES128,
            "CMAC_AES128": cls.CMAC_AES128,
            "HMAC-SHA256": cls.HMAC_SHA256,
            "HMAC_SHA256": cls.HMAC_SHA256,
        }
        result = mapping.get(value.upper().replace(" ", ""))
        if result is None:
            # Try normalized lookup
            normalized = value.upper().replace("-", "_").replace(" ", "")
            result = mapping.get(normalized)
        if result is None:
            raise ValueError(
                f"Unsupported MAC algorithm: '{value}'. "
                f"Supported: {list(mapping.keys())}"
            )
        return result


class VerificationStatus(Enum):
    """Outcome of SecOC verification."""
    OK = "VERIFIED"
    MAC_MISMATCH = "MAC_MISMATCH"
    FRESHNESS_EXPIRED = "FRESHNESS_EXPIRED"
    FRESHNESS_BEHIND = "FRESHNESS_BEHIND"
    INVALID_LENGTH = "INVALID_LENGTH"
    KEY_NOT_FOUND = "KEY_NOT_FOUND"
    DECODE_ERROR = "DECODE_ERROR"


class AttackType(Enum):
    """Types of attacks the simulator can execute."""
    REPLAY = "replay"
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    FUZZING = "fuzzing"


@dataclass(frozen=True)
class KeyEntry:
    """Symmetric key record for an ECU."""
    ecu_name: str
    key_id: int
    key_bytes: bytes
    description: str = ""

    def __post_init__(self) -> None:
        if len(self.key_bytes) not in (16, 32):
            raise ValueError(
                f"Key for '{self.ecu_name}' must be 16 or 32 bytes, "
                f"got {len(self.key_bytes)}"
            )


@dataclass(frozen=True)
class PDUProfile:
    """Authentication profile for a specific PDU (message)."""
    pdu_id: int
    name: str
    source_ecu: str
    dest_ecu: str
    payload_length: int
    freshness_bits: int = 32
    truncated_mac_bits: int = 24
    description: str = ""

    @property
    def truncated_mac_bytes(self) -> int:
        """Number of bytes needed for the truncated MAC (ceiling)."""
        return (self.truncated_mac_bits + 7) // 8

    @property
    def freshness_bytes(self) -> int:
        """Number of bytes needed for the freshness value (ceiling)."""
        return (self.freshness_bits + 7) // 8


@dataclass
class SecOCConfig:
    """Global SecOC simulator configuration."""
    mac_algorithm: MACAlgorithm = MACAlgorithm.CMAC_AES128
    mac_length_bits: int = 128
    truncated_mac_bits: int = 24
    freshness_bits: int = 32
    freshness_max_delta: int = 5
    keys: dict[str, KeyEntry] = field(default_factory=dict)
    pdu_profiles: dict[int, PDUProfile] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthenticPDU:
    """Original (unprotected) Protocol Data Unit."""
    pdu_id: int
    payload: bytes

    def to_hex(self) -> str:
        return self.payload.hex().upper()


@dataclass(frozen=True)
class SecuredPDU:
    """
    Secured I-PDU per AUTOSAR SecOC.

    Structure:
      [ Authentic I-PDU Data | Freshness Value | Truncated MAC ]
    """
    pdu_id: int
    authentic_payload: bytes
    freshness_value: int
    freshness_bytes_len: int
    truncated_mac: bytes
    full_mac: bytes  # stored for debugging/logging

    @property
    def secured_payload(self) -> bytes:
        """Concatenated secured payload ready for CAN frame."""
        fv_bytes = self.freshness_value.to_bytes(
            self.freshness_bytes_len, byteorder="big"
        )
        return self.authentic_payload + fv_bytes + self.truncated_mac

    def to_hex(self) -> str:
        return self.secured_payload.hex().upper()

    @property
    def total_length(self) -> int:
        return len(self.secured_payload)


@dataclass(frozen=True)
class VerificationResult:
    """Result of SecOC MAC verification."""
    status: VerificationStatus
    pdu_id: int
    expected_mac: Optional[bytes] = None
    received_mac: Optional[bytes] = None
    freshness_received: Optional[int] = None
    freshness_expected: Optional[int] = None
    detail: str = ""

    @property
    def is_verified(self) -> bool:
        return self.status == VerificationStatus.OK

    def summary(self) -> str:
        status_str = "✅ PASS" if self.is_verified else "❌ FAIL"
        return (
            f"{status_str} | PDU 0x{self.pdu_id:03X} | "
            f"{self.status.value} | {self.detail}"
        )
