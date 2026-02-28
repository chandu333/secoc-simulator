"""
logger.py — Rich Terminal Logger for SecOC Simulator.

Provides structured, color-coded terminal output for security-critical
information: MAC values, verification results, attack outcomes, and
detailed hex dumps.
"""

from __future__ import annotations

import sys
from typing import Optional

from colorama import init, Fore, Style, Back

# Initialize colorama for cross-platform color support
init(autoreset=True)


class SecOCLogger:
    """
    Structured logger for SecOC Simulator with color-coded output.
    """

    # Color scheme
    C_HEADER = Fore.CYAN + Style.BRIGHT
    C_SECTION = Fore.YELLOW + Style.BRIGHT
    C_SUBSEC = Fore.YELLOW
    C_SUCCESS = Fore.GREEN + Style.BRIGHT
    C_FAIL = Fore.RED + Style.BRIGHT
    C_WARN = Fore.YELLOW + Style.BRIGHT
    C_INFO = Fore.WHITE
    C_DIM = Fore.WHITE + Style.DIM
    C_HEX = Fore.MAGENTA
    C_KEY = Fore.CYAN
    C_VALUE = Fore.WHITE + Style.BRIGHT
    C_RESET = Style.RESET_ALL
    C_ATTACK = Fore.RED + Style.BRIGHT
    C_SHIELD = Fore.GREEN + Style.BRIGHT

    WIDTH = 72

    def __init__(self, verbose: bool = True, show_hex: bool = True) -> None:
        self.verbose = verbose
        self.show_hex = show_hex

    def banner(self) -> None:
        """Print the application banner."""
        lines = [
            "",
            "╔══════════════════════════════════════════════════════════════╗",
            "║           🔐  SecOC Simulator v1.0.0                       ║",
            "║           AUTOSAR Secure Onboard Communication             ║",
            "║           MAC-Authenticated CAN Frame Generator            ║",
            "╚══════════════════════════════════════════════════════════════╝",
            "",
        ]
        for line in lines:
            print(f"{self.C_HEADER}{line}{self.C_RESET}")

    def section(self, title: str) -> None:
        """Print a major section header."""
        bar = "═" * self.WIDTH
        print(f"\n{self.C_SECTION}╔{bar}╗")
        print(f"║  {title:<{self.WIDTH - 2}}║")
        print(f"╚{bar}╝{self.C_RESET}")

    def subsection(self, title: str) -> None:
        """Print a subsection header."""
        bar = "─" * self.WIDTH
        print(f"\n{self.C_SUBSEC}┌{bar}┐")
        print(f"│  {title:<{self.WIDTH - 2}}│")
        print(f"└{bar}┘{self.C_RESET}")

    def info(self, msg: str) -> None:
        """Print an info message."""
        print(f"  {self.C_INFO}{msg}{self.C_RESET}")

    def success(self, msg: str) -> None:
        """Print a success message."""
        print(f"  {self.C_SUCCESS}✅ {msg}{self.C_RESET}")

    def fail(self, msg: str) -> None:
        """Print a failure message."""
        print(f"  {self.C_FAIL}❌ {msg}{self.C_RESET}")

    def warn(self, msg: str) -> None:
        """Print a warning message."""
        print(f"  {self.C_WARN}⚠️  {msg}{self.C_RESET}")

    def kv(self, key: str, value: str, indent: int = 2) -> None:
        """Print a key-value pair."""
        pad = " " * indent
        print(f"{pad}{self.C_KEY}{key:.<30}{self.C_VALUE} {value}{self.C_RESET}")

    def hex_dump(self, label: str, data: bytes, indent: int = 4) -> None:
        """Print a hex dump of binary data."""
        if not self.show_hex:
            return
        pad = " " * indent
        hex_str = " ".join(f"{b:02X}" for b in data)
        ascii_str = "".join(
            chr(b) if 32 <= b < 127 else "." for b in data
        )
        print(
            f"{pad}{self.C_DIM}{label}: "
            f"{self.C_HEX}{hex_str}  "
            f"{self.C_DIM}|{ascii_str}|{self.C_RESET}"
        )

    def secured_pdu_detail(self, secured_pdu) -> None:
        """Print detailed info about a Secured I-PDU."""
        self.kv("PDU ID", f"0x{secured_pdu.pdu_id:03X}")
        self.kv("Payload", secured_pdu.authentic_payload.hex().upper())
        self.kv("Payload Length", f"{len(secured_pdu.authentic_payload)} bytes")
        self.kv("Freshness Value", str(secured_pdu.freshness_value))
        self.kv(
            "Freshness (hex)",
            secured_pdu.freshness_value.to_bytes(
                secured_pdu.freshness_bytes_len, "big"
            ).hex().upper(),
        )
        self.kv("Truncated MAC", secured_pdu.truncated_mac.hex().upper())
        self.kv("Full MAC", secured_pdu.full_mac.hex().upper())
        self.kv("Secured Payload", secured_pdu.to_hex())
        self.kv("Total Length", f"{secured_pdu.total_length} bytes")

        if self.show_hex:
            self.hex_dump("Auth Payload", secured_pdu.authentic_payload)
            self.hex_dump("Freshness   ", secured_pdu.freshness_value.to_bytes(
                secured_pdu.freshness_bytes_len, "big"
            ))
            self.hex_dump("Trunc MAC   ", secured_pdu.truncated_mac)
            self.hex_dump("Full Secured", secured_pdu.secured_payload)

    def verification_result(self, result) -> None:
        """Print a verification result."""
        if result.is_verified:
            self.success(result.summary())
        else:
            self.fail(result.summary())

        if self.verbose and result.detail:
            self.info(f"  Detail: {result.detail}")
        if result.expected_mac and result.received_mac:
            self.kv("Expected MAC", result.expected_mac.hex().upper(), indent=4)
            self.kv("Received MAC", result.received_mac.hex().upper(), indent=4)

    def attack_result(self, attack_result) -> None:
        """Print an attack simulation result."""
        if attack_result.detected:
            self.success(f"🛡️  DETECTED: {attack_result.description}")
        else:
            if "Legitimate" in attack_result.description:
                self.success(f"✅ BASELINE: {attack_result.description}")
            else:
                self.fail(f"⚠️  NOT DETECTED: {attack_result.description}")

        self.info(f"  Status: {attack_result.verification.status.value}")
        if attack_result.verification.detail:
            self.info(f"  Detail: {attack_result.verification.detail}")

    def can_frame(self, frame) -> None:
        """Print a CAN frame."""
        self.kv("CAN Frame", frame.to_hex_string())

    def config_summary(self, config) -> None:
        """Print configuration summary."""
        self.subsection("Configuration")
        self.kv("MAC Algorithm", config.mac_algorithm.name)
        self.kv("MAC Length", f"{config.mac_length_bits} bits")
        self.kv("Truncated MAC", f"{config.truncated_mac_bits} bits")
        self.kv("Freshness Bits", str(config.freshness_bits))
        self.kv("Max FV Delta", str(config.freshness_max_delta))
        self.kv("ECU Keys", str(len(config.keys)))
        self.kv("PDU Profiles", str(len(config.pdu_profiles)))

        for name, key in config.keys.items():
            self.info(
                f"    Key [{name}]: ID={key.key_id}, "
                f"{key.key_bytes.hex().upper()[:16]}... "
                f"({key.description})"
            )

        for pdu_id, profile in config.pdu_profiles.items():
            self.info(
                f"    PDU [0x{pdu_id:03X}]: {profile.name} "
                f"({profile.source_ecu} → {profile.dest_ecu}, "
                f"{profile.payload_length}B payload, "
                f"{profile.truncated_mac_bits}b MAC)"
            )
