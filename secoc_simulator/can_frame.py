"""
can_frame.py — CAN Frame Encoding and Decoding.

Handles packing Secured I-PDUs into CAN 2.0 frames (8-byte max)
and CAN FD frames (64-byte max), and unpacking them back.

CAN Frame Structure:
  ┌──────────────┬────────┬───────────────────────┐
  │ Arbitration  │  DLC   │     Data Field         │
  │   ID (11/29) │ (4bit) │  (0-8 or 0-64 bytes)  │
  └──────────────┴────────┴───────────────────────┘

The Data Field contains the Secured I-PDU payload.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from .types import SecuredPDU


# CAN DLC to actual data length mapping for CAN FD
CAN_FD_DLC_MAP = {
    0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8,
    9: 12, 10: 16, 11: 20, 12: 24, 13: 32, 14: 48, 15: 64,
}

# Reverse map: data length to DLC
CAN_FD_LEN_TO_DLC = {v: k for k, v in CAN_FD_DLC_MAP.items()}


@dataclass(frozen=True)
class CANFrame:
    """
    Represents a CAN or CAN FD frame.

    Attributes:
        arbitration_id: CAN arbitration ID (11-bit standard or 29-bit extended).
        data: Frame data payload bytes.
        is_extended: Whether this is an extended (29-bit) frame.
        is_fd: Whether this is a CAN FD frame.
        timestamp: Optional frame timestamp (seconds).
    """
    arbitration_id: int
    data: bytes
    is_extended: bool = False
    is_fd: bool = False
    timestamp: Optional[float] = None

    @property
    def dlc(self) -> int:
        """Data Length Code."""
        data_len = len(self.data)
        if not self.is_fd:
            return min(data_len, 8)
        # CAN FD: find the smallest DLC that fits
        for dlc, length in sorted(CAN_FD_DLC_MAP.items()):
            if length >= data_len:
                return dlc
        return 15  # max DLC

    @property
    def data_length(self) -> int:
        return len(self.data)

    def to_hex_string(self) -> str:
        """Format as a human-readable CAN frame string."""
        id_str = f"0x{self.arbitration_id:03X}"
        if self.is_extended:
            id_str = f"0x{self.arbitration_id:08X}"
        data_hex = " ".join(f"{b:02X}" for b in self.data)
        fd_flag = " [FD]" if self.is_fd else ""
        ts_str = ""
        if self.timestamp is not None:
            ts_str = f" @{self.timestamp:.6f}"
        return f"{id_str} [{self.dlc}]{fd_flag} {data_hex}{ts_str}"

    def to_raw_bytes(self) -> bytes:
        """
        Serialize frame to raw bytes.

        Format: [4-byte ID][1-byte flags][1-byte DLC][N-byte data]
        Flags: bit0=is_extended, bit1=is_fd
        """
        flags = (int(self.is_extended) << 0) | (int(self.is_fd) << 1)
        header = struct.pack(
            ">IBB",
            self.arbitration_id,
            flags,
            self.dlc,
        )
        return header + self.data

    @classmethod
    def from_raw_bytes(cls, raw: bytes) -> "CANFrame":
        """Deserialize a CANFrame from raw bytes."""
        if len(raw) < 6:
            raise ValueError(
                f"Raw frame too short: {len(raw)} bytes (minimum 6)"
            )
        arb_id, flags, dlc = struct.unpack(">IBB", raw[:6])
        is_extended = bool(flags & 0x01)
        is_fd = bool(flags & 0x02)
        data = raw[6:]
        return cls(
            arbitration_id=arb_id,
            data=data,
            is_extended=is_extended,
            is_fd=is_fd,
        )


class CANFrameCodec:
    """
    Encodes Secured I-PDUs into CAN frames and decodes them back.
    """

    # Classic CAN max payload
    CAN_MAX_DATA = 8
    # CAN FD max payload
    CAN_FD_MAX_DATA = 64

    @classmethod
    def encode(
        cls,
        secured_pdu: SecuredPDU,
        is_extended: bool = False,
        is_fd: bool = False,
    ) -> CANFrame:
        """
        Encode a Secured I-PDU into a CAN frame.

        Args:
            secured_pdu: The authenticated PDU to pack.
            is_extended: Use 29-bit extended ID.
            is_fd: Use CAN FD framing (up to 64 bytes).

        Returns:
            CANFrame with the Secured PDU packed as data.

        Raises:
            ValueError: If the Secured PDU doesn't fit in the frame.
        """
        data = secured_pdu.secured_payload
        max_len = cls.CAN_FD_MAX_DATA if is_fd else cls.CAN_MAX_DATA

        if len(data) > max_len:
            frame_type = "CAN FD" if is_fd else "Classic CAN"
            raise ValueError(
                f"Secured PDU ({len(data)} bytes) exceeds {frame_type} "
                f"max payload ({max_len} bytes). "
                f"Consider reducing MAC truncation or payload size."
            )

        # Pad to valid CAN FD data length if needed
        if is_fd:
            padded_data = cls._pad_to_fd_length(data)
        else:
            padded_data = data

        return CANFrame(
            arbitration_id=secured_pdu.pdu_id,
            data=padded_data,
            is_extended=is_extended,
            is_fd=is_fd,
        )

    @classmethod
    def decode(
        cls,
        frame: CANFrame,
        payload_length: int,
        freshness_bytes: int,
        mac_bytes: int,
    ) -> tuple[bytes, int, bytes]:
        """
        Decode a CAN frame into Secured I-PDU components.

        Args:
            frame: Received CAN frame.
            payload_length: Expected authentic payload length.
            freshness_bytes: Expected freshness value byte count.
            mac_bytes: Expected truncated MAC byte count.

        Returns:
            Tuple of (authentic_payload, freshness_value, truncated_mac).
        """
        expected_total = payload_length + freshness_bytes + mac_bytes

        if len(frame.data) < expected_total:
            raise ValueError(
                f"Frame data ({len(frame.data)} bytes) shorter than "
                f"expected Secured PDU ({expected_total} bytes)"
            )

        # Extract components (ignore any FD padding)
        offset = 0
        authentic_payload = frame.data[offset: offset + payload_length]
        offset += payload_length

        freshness_raw = frame.data[offset: offset + freshness_bytes]
        freshness_value = int.from_bytes(freshness_raw, byteorder="big")
        offset += freshness_bytes

        truncated_mac = frame.data[offset: offset + mac_bytes]

        return authentic_payload, freshness_value, truncated_mac

    @staticmethod
    def _pad_to_fd_length(data: bytes) -> bytes:
        """
        Pad data to the next valid CAN FD data length.

        Valid CAN FD lengths: 0-8, 12, 16, 20, 24, 32, 48, 64
        """
        valid_lengths = sorted(CAN_FD_DLC_MAP.values())
        data_len = len(data)

        for vl in valid_lengths:
            if vl >= data_len:
                if vl == data_len:
                    return data
                return data + b"\xCC" * (vl - data_len)  # 0xCC = padding byte

        raise ValueError(
            f"Data length {data_len} exceeds CAN FD maximum (64 bytes)"
        )

    @classmethod
    def check_fit(
        cls,
        payload_length: int,
        freshness_bytes: int,
        mac_bytes: int,
        is_fd: bool = False,
    ) -> dict:
        """
        Check if a Secured I-PDU configuration fits in a CAN frame.

        Returns a dict with fit analysis.
        """
        total = payload_length + freshness_bytes + mac_bytes
        max_len = cls.CAN_FD_MAX_DATA if is_fd else cls.CAN_MAX_DATA
        fits = total <= max_len

        return {
            "fits": fits,
            "total_bytes": total,
            "max_bytes": max_len,
            "remaining": max_len - total,
            "frame_type": "CAN FD" if is_fd else "Classic CAN",
            "breakdown": {
                "payload": payload_length,
                "freshness": freshness_bytes,
                "mac": mac_bytes,
            },
        }
