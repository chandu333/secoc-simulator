"""
attack_simulator.py — SecOC Attack Scenario Simulator.

Simulates common automotive CAN bus attacks against SecOC-protected
messages to validate that the authentication detects them correctly.

Attack types:
  - Replay: Resend a previously captured valid frame
  - Spoofing: Forge a frame with an incorrect key
  - Tampering: Modify payload bits after MAC generation
  - Fuzzing: Random payloads with random MACs
"""

from __future__ import annotations

import os
import copy
import struct
from dataclasses import dataclass
from typing import Optional

from .types import (
    AttackType,
    MACAlgorithm,
    SecuredPDU,
    VerificationResult,
    VerificationStatus,
)
from .secoc_pdu import SecOCPDUBuilder
from .crypto_engine import CryptoEngine
from .freshness_manager import FreshnessManager
from .logger import SecOCLogger


@dataclass
class AttackResult:
    """Result of an attack simulation."""
    attack_type: AttackType
    pdu_id: int
    description: str
    verification: VerificationResult
    tampered_payload: Optional[bytes] = None
    original_payload: Optional[bytes] = None

    @property
    def detected(self) -> bool:
        """True if the attack was correctly detected (verification failed)."""
        return not self.verification.is_verified

    def summary(self) -> str:
        detected_str = "🛡️  DETECTED" if self.detected else "⚠️  BYPASSED"
        return (
            f"{detected_str} | {self.attack_type.value.upper()} | "
            f"PDU 0x{self.pdu_id:03X} | "
            f"{self.verification.status.value} | "
            f"{self.description}"
        )


class AttackSimulator:
    """
    Simulates attacks against SecOC-protected CAN communications.
    """

    def __init__(
        self,
        pdu_builder: SecOCPDUBuilder,
        freshness_manager: FreshnessManager,
        logger: Optional[SecOCLogger] = None,
    ) -> None:
        self._builder = pdu_builder
        self._freshness = freshness_manager
        self._log = logger or SecOCLogger()

    def run_all_attacks(
        self,
        pdu_id: int,
        payload: bytes,
    ) -> list[AttackResult]:
        """
        Run all attack scenarios against a PDU.

        First generates a legitimate secured frame, then runs each attack
        type and reports whether the SecOC layer correctly detected it.
        """
        self._log.section("ATTACK SIMULATION")
        self._log.info(
            f"Target: PDU 0x{pdu_id:03X} | "
            f"Payload: {payload.hex().upper()}"
        )

        results = []

        # 1. First establish a legitimate frame
        self._log.subsection("Baseline: Legitimate Frame")
        legit_result = self._attack_legitimate(pdu_id, payload)
        results.append(legit_result)
        self._log.attack_result(legit_result)

        # 2. Replay attack
        self._log.subsection("Attack 1: Replay")
        replay_result = self._attack_replay(pdu_id, payload)
        results.append(replay_result)
        self._log.attack_result(replay_result)

        # 3. Spoofing attack
        self._log.subsection("Attack 2: Spoofing (Wrong Key)")
        spoof_result = self._attack_spoofing(pdu_id, payload)
        results.append(spoof_result)
        self._log.attack_result(spoof_result)

        # 4. Tampering attack
        self._log.subsection("Attack 3: Bit-Flip Tampering")
        tamper_result = self._attack_tampering(pdu_id, payload)
        results.append(tamper_result)
        self._log.attack_result(tamper_result)

        # 5. Fuzzing attack (multiple rounds)
        self._log.subsection("Attack 4: Random Fuzzing")
        for i in range(3):
            fuzz_result = self._attack_fuzzing(pdu_id, len(payload), round_num=i + 1)
            results.append(fuzz_result)
            self._log.attack_result(fuzz_result)

        # Summary
        self._log.subsection("Attack Summary")
        total = len(results)
        detected = sum(1 for r in results if r.attack_type != AttackType.REPLAY or r.detected)
        # Don't count the legitimate frame as an "attack"
        attacks_only = [r for r in results if r.attack_type != AttackType.REPLAY or r.description != "Legitimate frame"]
        attacks_detected = sum(1 for r in results[1:] if r.detected)
        self._log.info(
            f"Results: {attacks_detected}/{len(results) - 1} attacks detected"
        )

        return results

    def _attack_legitimate(
        self,
        pdu_id: int,
        payload: bytes,
    ) -> AttackResult:
        """Send a correctly authenticated frame (should pass)."""
        secured = self._builder.build_secured_pdu(pdu_id, payload)
        result = self._builder.verify_secured_pdu(
            pdu_id, secured.secured_payload
        )

        return AttackResult(
            attack_type=AttackType.REPLAY,  # categorized for baseline
            pdu_id=pdu_id,
            description="Legitimate frame (baseline — should verify OK)",
            verification=result,
            original_payload=payload,
        )

    def _attack_replay(
        self,
        pdu_id: int,
        payload: bytes,
    ) -> AttackResult:
        """
        Replay Attack: Capture a valid frame and resend it.

        The freshness counter should reject the replayed frame because
        the receiver has already advanced past this freshness value.
        """
        # Build a valid frame (this advances the TX counter)
        secured = self._builder.build_secured_pdu(pdu_id, payload)

        # First verification succeeds (advances RX counter)
        self._builder.verify_secured_pdu(pdu_id, secured.secured_payload)

        # REPLAY: send the exact same frame again
        # The RX counter has advanced, so this should fail
        replay_result = self._builder.verify_secured_pdu(
            pdu_id, secured.secured_payload
        )

        return AttackResult(
            attack_type=AttackType.REPLAY,
            pdu_id=pdu_id,
            description=(
                f"Replayed frame with freshness={secured.freshness_value} "
                f"(receiver expects higher)"
            ),
            verification=replay_result,
            original_payload=payload,
        )

    def _attack_spoofing(
        self,
        pdu_id: int,
        payload: bytes,
    ) -> AttackResult:
        """
        Spoofing Attack: Generate a MAC with the wrong key.

        An attacker without the correct key computes a MAC that
        won't match the receiver's expected value.
        """
        # Use a random key to compute MAC
        fake_key = os.urandom(16)
        fake_crypto = CryptoEngine(
            algorithm=MACAlgorithm.CMAC_AES128,
            key=fake_key,
        )

        # Get a valid freshness value
        freshness = self._freshness.get_tx_freshness(pdu_id)
        profile = self._builder._get_profile(pdu_id)

        truncated_mac, full_mac = fake_crypto.compute_truncated_mac(
            pdu_id=pdu_id,
            authentic_payload=payload,
            freshness_value=freshness,
            freshness_bits=profile.freshness_bits,
            truncated_bits=profile.truncated_mac_bits,
        )

        # Build spoofed secured payload
        fv_bytes = freshness.to_bytes(profile.freshness_bytes, byteorder="big")
        spoofed_payload = payload + fv_bytes + truncated_mac

        result = self._builder.verify_secured_pdu(pdu_id, spoofed_payload)

        return AttackResult(
            attack_type=AttackType.SPOOFING,
            pdu_id=pdu_id,
            description=f"Forged MAC using random key ({fake_key[:4].hex().upper()}...)",
            verification=result,
            original_payload=payload,
        )

    def _attack_tampering(
        self,
        pdu_id: int,
        payload: bytes,
    ) -> AttackResult:
        """
        Tampering Attack: Flip bits in the payload after MAC generation.

        The MAC was computed over the original payload, so modifying
        even a single bit should cause verification failure.
        """
        # Generate a valid secured frame
        secured = self._builder.build_secured_pdu(pdu_id, payload)

        # Tamper with the payload by flipping the first byte's LSB
        tampered = bytearray(secured.secured_payload)
        tampered[0] ^= 0x01  # flip one bit
        tampered_bytes = bytes(tampered)

        result = self._builder.verify_secured_pdu(pdu_id, tampered_bytes)

        return AttackResult(
            attack_type=AttackType.TAMPERING,
            pdu_id=pdu_id,
            description=(
                f"Flipped bit in payload byte[0]: "
                f"0x{payload[0]:02X} → 0x{tampered[0]:02X}"
            ),
            verification=result,
            original_payload=payload,
            tampered_payload=tampered_bytes[:len(payload)],
        )

    def _attack_fuzzing(
        self,
        pdu_id: int,
        payload_length: int,
        round_num: int = 1,
    ) -> AttackResult:
        """
        Fuzzing Attack: Send completely random payload and MAC.

        Brute-force attempt with random data — extremely unlikely
        to match the expected MAC.
        """
        profile = self._builder._get_profile(pdu_id)

        # Generate random payload
        random_payload = os.urandom(payload_length)

        # Generate random freshness and MAC
        freshness = self._freshness.get_tx_freshness(pdu_id)
        fv_bytes = freshness.to_bytes(profile.freshness_bytes, byteorder="big")
        random_mac = os.urandom(profile.truncated_mac_bytes)

        fuzzed_frame = random_payload + fv_bytes + random_mac

        result = self._builder.verify_secured_pdu(pdu_id, fuzzed_frame)

        return AttackResult(
            attack_type=AttackType.FUZZING,
            pdu_id=pdu_id,
            description=(
                f"Fuzz round {round_num}: random payload "
                f"{random_payload.hex().upper()}, "
                f"random MAC {random_mac.hex().upper()}"
            ),
            verification=result,
            original_payload=random_payload,
        )
