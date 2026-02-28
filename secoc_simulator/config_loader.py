"""
config_loader.py — YAML Configuration Parser for SecOC Simulator.

Loads and validates the YAML configuration file, converting it into
strongly-typed SecOCConfig and related data structures.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

import yaml

from .types import (
    KeyEntry,
    MACAlgorithm,
    PDUProfile,
    SecOCConfig,
)


class ConfigError(Exception):
    """Configuration validation error."""
    pass


class ConfigLoader:
    """Loads and validates SecOC simulator configuration from YAML."""

    DEFAULT_CONFIG_NAME = "config.yaml"

    @classmethod
    def load(
        cls,
        config_path: Optional[Union[str, Path]] = None,
    ) -> SecOCConfig:
        """
        Load configuration from a YAML file.

        Args:
            config_path: Path to YAML config file. If None, searches for
                         config.yaml in the current directory and parent
                         directories.

        Returns:
            Parsed and validated SecOCConfig.

        Raises:
            ConfigError: If the config file is missing or invalid.
            FileNotFoundError: If the config file doesn't exist.
        """
        if config_path is None:
            config_path = cls._find_config()
        else:
            config_path = Path(config_path)

        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_path, "r") as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, dict):
            raise ConfigError("Config file must be a YAML mapping")

        return cls._parse_config(raw)

    @classmethod
    def load_from_string(cls, yaml_string: str) -> SecOCConfig:
        """Load configuration from a YAML string."""
        raw = yaml.safe_load(yaml_string)
        if not isinstance(raw, dict):
            raise ConfigError("Config must be a YAML mapping")
        return cls._parse_config(raw)

    @classmethod
    def get_default_config(cls) -> SecOCConfig:
        """Return a sensible default configuration (no YAML file needed)."""
        default_key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        key_entry = KeyEntry(
            ecu_name="ecu_default",
            key_id=1,
            key_bytes=default_key,
            description="Default key",
        )
        profile = PDUProfile(
            pdu_id=0x123,
            name="DefaultPDU",
            source_ecu="ecu_default",
            dest_ecu="ecu_default",
            payload_length=4,
            freshness_bits=32,
            truncated_mac_bits=24,
        )
        return SecOCConfig(
            mac_algorithm=MACAlgorithm.CMAC_AES128,
            mac_length_bits=128,
            truncated_mac_bits=24,
            freshness_bits=32,
            freshness_max_delta=5,
            keys={"ecu_default": key_entry},
            pdu_profiles={0x123: profile},
        )

    @classmethod
    def _find_config(cls) -> Path:
        """Search for config.yaml in CWD and parent directories."""
        current = Path.cwd()
        for _ in range(5):  # max 5 levels up
            candidate = current / cls.DEFAULT_CONFIG_NAME
            if candidate.exists():
                return candidate
            parent = current.parent
            if parent == current:
                break
            current = parent
        raise FileNotFoundError(
            f"Could not find {cls.DEFAULT_CONFIG_NAME} in current "
            f"or parent directories. Use --config to specify a path."
        )

    @classmethod
    def _parse_config(cls, raw: dict) -> SecOCConfig:
        """Parse raw YAML dict into SecOCConfig."""
        # Parse SecOC section
        secoc_raw = raw.get("secoc", {})
        mac_algo_str = secoc_raw.get("mac_algorithm", "CMAC-AES128")
        mac_algorithm = MACAlgorithm.from_string(mac_algo_str)

        mac_length_bits = int(secoc_raw.get("mac_length_bits", 128))
        truncated_mac_bits = int(secoc_raw.get("truncated_mac_bits", 24))
        freshness_bits = int(secoc_raw.get("freshness_bits", 32))
        freshness_max_delta = int(secoc_raw.get("freshness_max_delta", 5))

        # Parse keys
        keys: dict[str, KeyEntry] = {}
        keys_raw = raw.get("keys", {})
        for ecu_name, key_data in keys_raw.items():
            key_hex = key_data.get("key_hex", "")
            try:
                key_bytes = bytes.fromhex(key_hex.replace(" ", ""))
            except ValueError as e:
                raise ConfigError(
                    f"Invalid key hex for ECU '{ecu_name}': {e}"
                )

            keys[ecu_name] = KeyEntry(
                ecu_name=ecu_name,
                key_id=int(key_data.get("key_id", 0)),
                key_bytes=key_bytes,
                description=key_data.get("description", ""),
            )

        # Parse PDU profiles
        pdu_profiles: dict[int, PDUProfile] = {}
        profiles_raw = raw.get("pdu_profiles", [])
        for profile_data in profiles_raw:
            pdu_id_raw = profile_data.get("pdu_id", 0)
            # Handle hex strings like "0x123" or integers
            if isinstance(pdu_id_raw, str):
                pdu_id = int(pdu_id_raw, 0)
            else:
                pdu_id = int(pdu_id_raw)

            source_ecu = profile_data.get("source_ecu", "")
            if source_ecu and source_ecu not in keys:
                raise ConfigError(
                    f"PDU 0x{pdu_id:03X}: source_ecu '{source_ecu}' "
                    f"not found in keys config"
                )

            profile = PDUProfile(
                pdu_id=pdu_id,
                name=profile_data.get("name", f"PDU_0x{pdu_id:03X}"),
                source_ecu=source_ecu,
                dest_ecu=profile_data.get("dest_ecu", ""),
                payload_length=int(profile_data.get("payload_length", 4)),
                freshness_bits=int(
                    profile_data.get("freshness_bits", freshness_bits)
                ),
                truncated_mac_bits=int(
                    profile_data.get("truncated_mac_bits", truncated_mac_bits)
                ),
                description=profile_data.get("description", ""),
            )
            pdu_profiles[pdu_id] = profile

        return SecOCConfig(
            mac_algorithm=mac_algorithm,
            mac_length_bits=mac_length_bits,
            truncated_mac_bits=truncated_mac_bits,
            freshness_bits=freshness_bits,
            freshness_max_delta=freshness_max_delta,
            keys=keys,
            pdu_profiles=pdu_profiles,
        )
