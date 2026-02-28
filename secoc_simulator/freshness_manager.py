"""
freshness_manager.py — Freshness Value Management for SecOC.

Implements monotonic counter-based freshness values per AUTOSAR SecOC.
Each PDU ID maintains its own independent counter on both the sender
and receiver side.

Receiver-side verification supports a configurable acceptance window
(max_delta) to tolerate minor counter gaps caused by lost frames.
"""

from __future__ import annotations

import threading
from typing import Optional


class FreshnessManager:
    """
    Manages per-PDU freshness counters for SecOC message authentication.

    Thread-safe: all counter operations are protected by a lock, allowing
    concurrent use from multiple simulated ECU threads.
    """

    def __init__(
        self,
        freshness_bits: int = 32,
        max_delta: int = 5,
        initial_value: int = 0,
    ) -> None:
        """
        Initialize the freshness manager.

        Args:
            freshness_bits: Bit-width of the freshness counter.
            max_delta: Maximum allowed gap between received and expected
                       freshness values (receiver-side tolerance).
            initial_value: Starting counter value for all new PDU IDs.
        """
        if freshness_bits < 1 or freshness_bits > 64:
            raise ValueError(
                f"freshness_bits must be 1-64, got {freshness_bits}"
            )
        self._freshness_bits = freshness_bits
        self._max_value = (1 << freshness_bits) - 1
        self._max_delta = max_delta
        self._initial_value = initial_value

        # Separate counters for sender (tx) and receiver (rx)
        self._tx_counters: dict[int, int] = {}
        self._rx_counters: dict[int, int] = {}
        self._lock = threading.Lock()

    @property
    def freshness_bits(self) -> int:
        return self._freshness_bits

    @property
    def max_value(self) -> int:
        return self._max_value

    def get_tx_freshness(self, pdu_id: int) -> int:
        """
        Get the current TX freshness value for a PDU and increment it.

        Used on the sender side when constructing a Secured I-PDU.

        Args:
            pdu_id: PDU identifier.

        Returns:
            Current freshness value (before increment).

        Raises:
            OverflowError: If counter has reached its maximum value.
        """
        with self._lock:
            if pdu_id not in self._tx_counters:
                self._tx_counters[pdu_id] = self._initial_value

            current = self._tx_counters[pdu_id]
            if current > self._max_value:
                raise OverflowError(
                    f"TX freshness counter overflow for PDU 0x{pdu_id:03X} "
                    f"(max={self._max_value})"
                )

            self._tx_counters[pdu_id] = current + 1
            return current

    def get_rx_freshness(self, pdu_id: int) -> int:
        """
        Get the current expected RX freshness value for a PDU.

        Args:
            pdu_id: PDU identifier.

        Returns:
            Current expected freshness value on the receiver side.
        """
        with self._lock:
            return self._rx_counters.get(pdu_id, self._initial_value)

    def verify_freshness(
        self,
        pdu_id: int,
        received_freshness: int,
    ) -> tuple[bool, str]:
        """
        Verify a received freshness value against the expected counter.

        Accepts the value if:
          expected <= received <= expected + max_delta

        On success, advances the RX counter to received + 1.

        Args:
            pdu_id: PDU identifier.
            received_freshness: Freshness value extracted from the frame.

        Returns:
            Tuple of (is_valid, detail_message).
        """
        with self._lock:
            if pdu_id not in self._rx_counters:
                self._rx_counters[pdu_id] = self._initial_value

            expected = self._rx_counters[pdu_id]

            if received_freshness < expected:
                return False, (
                    f"Freshness behind: received={received_freshness}, "
                    f"expected>={expected} (possible replay)"
                )

            delta = received_freshness - expected
            if delta > self._max_delta:
                return False, (
                    f"Freshness gap too large: received={received_freshness}, "
                    f"expected={expected}, delta={delta}, "
                    f"max_delta={self._max_delta}"
                )

            # Accept and advance counter
            self._rx_counters[pdu_id] = received_freshness + 1
            return True, (
                f"Freshness OK: received={received_freshness}, "
                f"expected={expected}, delta={delta}"
            )

    def reset(self, pdu_id: Optional[int] = None) -> None:
        """
        Reset freshness counters.

        Args:
            pdu_id: If provided, reset only this PDU's counters.
                    If None, reset all counters.
        """
        with self._lock:
            if pdu_id is not None:
                self._tx_counters.pop(pdu_id, None)
                self._rx_counters.pop(pdu_id, None)
            else:
                self._tx_counters.clear()
                self._rx_counters.clear()

    def peek_tx(self, pdu_id: int) -> int:
        """Peek at the current TX counter without incrementing."""
        with self._lock:
            return self._tx_counters.get(pdu_id, self._initial_value)

    def peek_rx(self, pdu_id: int) -> int:
        """Peek at the current RX counter without incrementing."""
        with self._lock:
            return self._rx_counters.get(pdu_id, self._initial_value)

    def force_set_tx(self, pdu_id: int, value: int) -> None:
        """Force-set a TX counter value (for testing/attack simulation)."""
        with self._lock:
            self._tx_counters[pdu_id] = value

    def force_set_rx(self, pdu_id: int, value: int) -> None:
        """Force-set an RX counter value (for testing/attack simulation)."""
        with self._lock:
            self._rx_counters[pdu_id] = value

    def get_state_snapshot(self) -> dict:
        """Return a snapshot of all counters (for debugging)."""
        with self._lock:
            return {
                "tx_counters": dict(self._tx_counters),
                "rx_counters": dict(self._rx_counters),
            }
