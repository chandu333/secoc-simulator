<div align="center">

# 🔐 SecOC Simulator

**AUTOSAR Secure Onboard Communication — MAC-Authenticated CAN Frame Simulator**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![AUTOSAR](https://img.shields.io/badge/AUTOSAR-SecOC-orange.svg)](https://www.autosar.org/)
[![Flask Dashboard](https://img.shields.io/badge/Dashboard-Flask-red.svg)](#-web-dashboard)

A production-grade Python tool for generating, verifying, and attack-testing MAC-authenticated CAN frames per the AUTOSAR SecOC specification. Built for automotive cybersecurity engineers, penetration testers, and AUTOSAR developers.

[Quick Start](#-quick-start) •
[Web Dashboard](#-web-dashboard) •
[CLI Usage](#-cli-usage) •
[Attack Simulator](#-attack-scenarios) •
[Configuration](#%EF%B8%8F-configuration) •
[API Reference](#-api-reference)

</div>

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  SecOC Simulator                     │
├──────────┬──────────┬───────────┬───────────────────┤
│  Crypto  │ Freshness│  SecOC    │   CAN Frame       │
│  Engine  │ Manager  │  PDU      │   Builder         │
│  (MAC)   │ (Counter)│  Builder  │   (Encode/Decode) │
├──────────┴──────────┴───────────┴───────────────────┤
│              Attack Simulator                        │
│  (Replay / Spoofing / Tampering / Fuzzing)          │
├─────────────────────────────────────────────────────┤
│         Flask Web Dashboard + REST API              │
├─────────────────────────────────────────────────────┤
│              CLI Interface & Logger                  │
└─────────────────────────────────────────────────────┘
```

## ✨ Features

- **CMAC-AES128 & HMAC-SHA256** — dual MAC algorithm support per AUTOSAR SecOC
- **Freshness Value Management** — monotonic counters with configurable acceptance window
- **MAC Truncation** — configurable truncated MAC length for CAN 8-byte constraint
- **Secured I-PDU Construction** — Authentic I-PDU + Freshness + Truncated MAC
- **CAN Frame Encoding/Decoding** — Classic CAN & CAN FD support with DLC mapping
- **Attack Simulation** — replay, spoofing, bit-flip tampering, and random fuzzing
- **Flask Web Dashboard** — 9-page visual control panel with live hex visualization
- **REST API** — 8 JSON endpoints for integration
- **YAML Configuration** — ECU keys, PDU profiles, and global parameters
- **Colored CLI** — rich terminal output with hex dumps
- **Zero Hardware Dependencies** — pure Python, no CAN interface required

## 📦 Quick Start

```bash
# Clone
git clone https://github.com/chandu333/secoc-simulator.git
cd secoc-simulator

# Install dependencies
pip install -r requirements.txt

# Run CLI demo
python -m secoc_simulator

# Launch Web Dashboard
python run_dashboard.py
# → Open http://localhost:5000
```

## 🌐 Web Dashboard

The web dashboard provides a full visual interface with 9 pages:

| Page | Description |
|------|-------------|
| **Overview** | Stats, ECU network topology, PDU routing table |
| **Generate Frame** | Build Secured I-PDU with color-coded hex byte-map |
| **Verify Frame** | Verify any secured frame hex |
| **Attack Simulator** | One-click replay/spoofing/tampering/fuzzing with detection bar |
| **Batch Generate** | Generate up to 50 consecutive frames |
| **SecOC Config** | Live-edit algorithm, truncation, freshness settings |
| **ECU Keys** | View symmetric key store |
| **PDU Profiles** | Message authentication profiles |
| **Freshness State** | Real-time TX/RX counter monitoring |

```bash
# Start dashboard
python run_dashboard.py

# Custom port
python run_dashboard.py --port 8080

# With custom config
python run_dashboard.py --config my_config.yaml
```

## 💻 CLI Usage

```bash
# Full demo (generate + verify + attack all PDUs)
python -m secoc_simulator

# Generate a single secured frame
python -m secoc_simulator --mode generate --pdu-id 0x123 --payload "DEADBEEF"

# Verify a secured frame
python -m secoc_simulator --mode verify --pdu-id 0x123 --frame "DEADBEEF00000000B69770"

# Run attack simulations
python -m secoc_simulator --mode attack --pdu-id 0x123 --payload "DEADBEEF"

# Use HMAC-SHA256 instead of CMAC
python -m secoc_simulator --algo HMAC-SHA256

# Quiet mode (minimal output)
python -m secoc_simulator --quiet --no-hex
```

## 🛡️ Attack Scenarios

| Attack | Method | Expected Result |
|--------|--------|-----------------|
| **Replay** | Resend a previously valid frame | ❌ Freshness counter rejects stale value |
| **Spoofing** | Forge MAC with wrong key | ❌ MAC mismatch |
| **Tampering** | Flip bits in payload after MAC generation | ❌ MAC mismatch |
| **Fuzzing** | Random payloads with random MACs | ❌ MAC mismatch |
| **Legitimate** | Correctly authenticated frame | ✅ Verified |

## ⚙️ Configuration

Edit `config.yaml`:

```yaml
secoc:
  mac_algorithm: "CMAC-AES128"   # or "HMAC-SHA256"
  truncated_mac_bits: 24
  freshness_bits: 32
  freshness_max_delta: 5

keys:
  ecu_gateway:
    key_id: 1
    key_hex: "000102030405060708090A0B0C0D0E0F"
  ecu_brake:
    key_id: 2
    key_hex: "1F1E1D1C1B1A19181716151413121110"

pdu_profiles:
  - pdu_id: 0x123
    name: "BrakeCommand"
    source_ecu: "ecu_gateway"
    dest_ecu: "ecu_brake"
    payload_length: 4
    truncated_mac_bits: 24
```

## 🔌 API Reference

All endpoints return JSON. Base URL: `http://localhost:5000/api`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/config` | Get current configuration |
| `PUT` | `/api/config` | Update configuration live |
| `POST` | `/api/generate` | Generate a Secured I-PDU |
| `POST` | `/api/verify` | Verify a secured frame |
| `POST` | `/api/attack` | Run all attack simulations |
| `POST` | `/api/batch` | Generate multiple frames |
| `GET` | `/api/freshness` | Get freshness counter state |
| `POST` | `/api/freshness/reset` | Reset all counters |
| `POST` | `/api/fit-check` | Check CAN frame fit |

**Example — Generate:**
```bash
curl -X POST http://localhost:5000/api/generate \
  -H "Content-Type: application/json" \
  -d '{"pdu_id": 291, "payload": "DEADBEEF"}'
```

## 📂 Project Structure

```
secoc-simulator/
├── secoc_simulator/
│   ├── __init__.py          # Package init
│   ├── __main__.py          # CLI entry point
│   ├── crypto_engine.py     # CMAC-AES128 & HMAC-SHA256
│   ├── freshness_manager.py # Thread-safe freshness counters
│   ├── secoc_pdu.py         # Secured I-PDU builder & verifier
│   ├── can_frame.py         # CAN/CAN FD frame codec
│   ├── attack_simulator.py  # Replay, spoof, tamper, fuzz
│   ├── config_loader.py     # YAML config parser
│   ├── logger.py            # Colored terminal logger
│   ├── types.py             # Type definitions & data structures
│   └── web_api.py           # Flask REST API + Dashboard
├── config.yaml              # Default configuration
├── run_dashboard.py         # Web dashboard launcher
├── setup.py                 # pip install support
├── requirements.txt
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

## 🔧 Requirements

- Python 3.9+
- `cryptography` — AES-128-CMAC implementation
- `pyyaml` — Configuration parsing
- `colorama` — Terminal colors
- `flask` — Web dashboard

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

<div align="center">

**Built with 🔒 for automotive security engineers**

[Report Bug](https://github.com/chandu333/secoc-simulator/issues) •
[Request Feature](https://github.com/chandu333/secoc-simulator/issues)

</div>
