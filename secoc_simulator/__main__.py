"""
__main__.py — CLI Entry Point for SecOC Simulator.

Usage:
  python -m secoc_simulator                           # Full demo
  python -m secoc_simulator --mode generate           # Generate frames
  python -m secoc_simulator --mode verify             # Verify a frame
  python -m secoc_simulator --mode attack             # Attack simulation
  python -m secoc_simulator --config custom.yaml      # Custom config
  python -m secoc_simulator --algo HMAC-SHA256        # Override algorithm
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from .types import MACAlgorithm, SecOCConfig
from .config_loader import ConfigLoader, ConfigError
from .freshness_manager import FreshnessManager
from .secoc_pdu import SecOCPDUBuilder
from .can_frame import CANFrame, CANFrameCodec
from .attack_simulator import AttackSimulator
from .logger import SecOCLogger


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="secoc_simulator",
        description=(
            "SecOC Simulator — AUTOSAR Secure Onboard Communication "
            "MAC-authenticated CAN frame generator and verifier."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["demo", "generate", "verify", "attack"],
        default="demo",
        help="Operating mode (default: demo)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--pdu-id",
        type=lambda x: int(x, 0),
        default=None,
        help="PDU ID (hex or decimal, e.g. 0x123)",
    )
    parser.add_argument(
        "--payload",
        type=str,
        default=None,
        help="Payload as hex string (e.g. DEADBEEF)",
    )
    parser.add_argument(
        "--frame",
        type=str,
        default=None,
        help="Hex-encoded secured frame for verification",
    )
    parser.add_argument(
        "--algo",
        choices=["CMAC-AES128", "HMAC-SHA256"],
        default=None,
        help="Override MAC algorithm",
    )
    parser.add_argument(
        "--attack-type",
        choices=["replay", "spoofing", "tampering", "fuzzing", "all"],
        default="all",
        help="Attack type for attack mode (default: all)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce output verbosity",
    )
    parser.add_argument(
        "--no-hex",
        action="store_true",
        help="Disable hex dump output",
    )
    return parser.parse_args()


def load_config(args: argparse.Namespace, log: SecOCLogger) -> SecOCConfig:
    """Load configuration from file or defaults."""
    try:
        if args.config:
            config = ConfigLoader.load(args.config)
            log.info(f"Loaded config from: {args.config}")
        else:
            try:
                config = ConfigLoader.load()
                log.info(f"Loaded config from: config.yaml")
            except FileNotFoundError:
                config = ConfigLoader.get_default_config()
                log.warn("No config.yaml found — using default configuration")
    except ConfigError as e:
        log.fail(f"Configuration error: {e}")
        sys.exit(1)

    # Apply CLI overrides
    if args.algo:
        config.mac_algorithm = MACAlgorithm.from_string(args.algo)
        log.info(f"Algorithm override: {args.algo}")

    return config


def run_demo(
    config: SecOCConfig,
    freshness: FreshnessManager,
    builder: SecOCPDUBuilder,
    log: SecOCLogger,
) -> None:
    """Run the full demonstration."""
    log.section("DEMO: SecOC Frame Generation & Verification")

    # Demo payloads for each configured PDU
    demo_payloads = {
        0x123: bytes.fromhex("DEADBEEF"),
        0x234: bytes.fromhex("C0FFEE"),
        0x345: bytes.fromhex("BAADF00D"),
        0x456: bytes.fromhex("FACE"),
    }

    for pdu_id, profile in config.pdu_profiles.items():
        log.subsection(f"PDU 0x{pdu_id:03X}: {profile.name}")
        log.info(f"  {profile.description}")
        log.info(
            f"  Route: {profile.source_ecu} → {profile.dest_ecu}"
        )

        # Get or generate payload
        payload = demo_payloads.get(pdu_id)
        if payload is None or len(payload) != profile.payload_length:
            payload = bytes(range(1, profile.payload_length + 1))

        # Check CAN frame fit
        fit = CANFrameCodec.check_fit(
            profile.payload_length,
            profile.freshness_bytes,
            profile.truncated_mac_bytes,
        )
        fit_status = "✅ FITS" if fit["fits"] else "❌ TOO LARGE"
        log.kv(
            "CAN Frame Fit",
            f"{fit_status} ({fit['total_bytes']}/{fit['max_bytes']} bytes)"
        )

        # Build Secured I-PDU
        log.info("")
        log.info("  Building Secured I-PDU...")
        secured = builder.build_secured_pdu(pdu_id, payload)
        log.secured_pdu_detail(secured)

        # Encode to CAN frame
        if fit["fits"]:
            can_frame = CANFrameCodec.encode(secured)
            log.info("")
            log.can_frame(can_frame)

        # Verify
        log.info("")
        log.info("  Verifying Secured I-PDU...")
        result = builder.verify_secured_pdu(pdu_id, secured.secured_payload)
        log.verification_result(result)

    # Run attack simulation on the first PDU
    first_pdu_id = next(iter(config.pdu_profiles))
    first_profile = config.pdu_profiles[first_pdu_id]
    payload = demo_payloads.get(first_pdu_id, bytes(first_profile.payload_length))

    # Reset freshness for clean attack test
    freshness.reset()

    attacker = AttackSimulator(builder, freshness, log)
    attacker.run_all_attacks(first_pdu_id, payload)


def run_generate(
    config: SecOCConfig,
    builder: SecOCPDUBuilder,
    args: argparse.Namespace,
    log: SecOCLogger,
) -> None:
    """Generate a single secured frame."""
    pdu_id = args.pdu_id
    if pdu_id is None:
        pdu_id = next(iter(config.pdu_profiles))
        log.info(f"No --pdu-id specified, using 0x{pdu_id:03X}")

    if pdu_id not in config.pdu_profiles:
        log.fail(f"PDU 0x{pdu_id:03X} not found in configuration")
        sys.exit(1)

    profile = config.pdu_profiles[pdu_id]

    if args.payload:
        try:
            payload = bytes.fromhex(args.payload.replace(" ", ""))
        except ValueError:
            log.fail(f"Invalid hex payload: {args.payload}")
            sys.exit(1)
    else:
        payload = bytes(range(1, profile.payload_length + 1))

    log.section(f"GENERATE: PDU 0x{pdu_id:03X} ({profile.name})")

    secured = builder.build_secured_pdu(pdu_id, payload)
    log.secured_pdu_detail(secured)

    fit = CANFrameCodec.check_fit(
        profile.payload_length,
        profile.freshness_bytes,
        profile.truncated_mac_bytes,
    )
    if fit["fits"]:
        can_frame = CANFrameCodec.encode(secured)
        log.info("")
        log.can_frame(can_frame)

    # Output raw hex for piping
    print(f"\nSecured payload (hex): {secured.to_hex()}")


def run_verify(
    config: SecOCConfig,
    builder: SecOCPDUBuilder,
    args: argparse.Namespace,
    log: SecOCLogger,
) -> None:
    """Verify a secured frame."""
    if not args.frame:
        log.fail("--frame required for verify mode")
        sys.exit(1)

    pdu_id = args.pdu_id
    if pdu_id is None:
        pdu_id = next(iter(config.pdu_profiles))

    try:
        frame_bytes = bytes.fromhex(args.frame.replace(" ", ""))
    except ValueError:
        log.fail(f"Invalid hex frame: {args.frame}")
        sys.exit(1)

    log.section(f"VERIFY: PDU 0x{pdu_id:03X}")
    log.hex_dump("Input Frame", frame_bytes, indent=2)

    result = builder.verify_secured_pdu(pdu_id, frame_bytes)
    log.verification_result(result)


def run_attack(
    config: SecOCConfig,
    freshness: FreshnessManager,
    builder: SecOCPDUBuilder,
    args: argparse.Namespace,
    log: SecOCLogger,
) -> None:
    """Run attack simulations."""
    pdu_id = args.pdu_id
    if pdu_id is None:
        pdu_id = next(iter(config.pdu_profiles))

    profile = config.pdu_profiles[pdu_id]

    if args.payload:
        payload = bytes.fromhex(args.payload.replace(" ", ""))
    else:
        payload = bytes(range(1, profile.payload_length + 1))

    attacker = AttackSimulator(builder, freshness, log)
    attacker.run_all_attacks(pdu_id, payload)


def main() -> None:
    """Main entry point."""
    args = parse_args()

    # Initialize logger
    log = SecOCLogger(
        verbose=not args.quiet,
        show_hex=not args.no_hex,
    )

    log.banner()

    # Load configuration
    config = load_config(args, log)
    log.config_summary(config)

    # Initialize freshness manager
    freshness = FreshnessManager(
        freshness_bits=config.freshness_bits,
        max_delta=config.freshness_max_delta,
    )

    # Initialize PDU builder
    builder = SecOCPDUBuilder(config, freshness)

    # Dispatch to mode handler
    if args.mode == "demo":
        run_demo(config, freshness, builder, log)
    elif args.mode == "generate":
        run_generate(config, builder, args, log)
    elif args.mode == "verify":
        run_verify(config, builder, args, log)
    elif args.mode == "attack":
        run_attack(config, freshness, builder, args, log)

    log.info("")
    log.info("Done. 🔐")


if __name__ == "__main__":
    main()
