"""
web_api.py — Flask REST API for SecOC Simulator Dashboard.

Exposes all simulator capabilities via JSON endpoints:
  /api/config          — GET/PUT configuration
  /api/generate        — POST generate a secured frame
  /api/verify          — POST verify a secured frame
  /api/attack          — POST run attack simulations
  /api/batch           — POST generate multiple frames
  /api/freshness       — GET freshness counter state
  /api/freshness/reset — POST reset counters
  /api/fit-check       — POST check CAN frame fit
"""

from __future__ import annotations

import json
import os
import traceback
from typing import Any

from flask import Flask, request, jsonify, render_template_string

from .types import (
    MACAlgorithm,
    SecOCConfig,
    KeyEntry,
    PDUProfile,
    VerificationStatus,
)
from .crypto_engine import CryptoEngine
from .freshness_manager import FreshnessManager
from .secoc_pdu import SecOCPDUBuilder
from .can_frame import CANFrameCodec
from .attack_simulator import AttackSimulator
from .config_loader import ConfigLoader
from .logger import SecOCLogger


def create_app(config: SecOCConfig | None = None) -> Flask:
    """Create and configure the Flask application."""

    app = Flask(__name__, static_folder=None)
    app.config["JSON_SORT_KEYS"] = False

    # Initialize simulator state
    if config is None:
        try:
            config = ConfigLoader.load()
        except FileNotFoundError:
            config = ConfigLoader.get_default_config()

    state = {
        "config": config,
        "freshness": FreshnessManager(
            freshness_bits=config.freshness_bits,
            max_delta=config.freshness_max_delta,
        ),
    }

    def get_builder() -> SecOCPDUBuilder:
        return SecOCPDUBuilder(state["config"], state["freshness"])

    def config_to_dict(cfg: SecOCConfig) -> dict:
        return {
            "mac_algorithm": cfg.mac_algorithm.name,
            "mac_length_bits": cfg.mac_length_bits,
            "truncated_mac_bits": cfg.truncated_mac_bits,
            "freshness_bits": cfg.freshness_bits,
            "freshness_max_delta": cfg.freshness_max_delta,
            "keys": {
                name: {
                    "ecu_name": k.ecu_name,
                    "key_id": k.key_id,
                    "key_hex": k.key_bytes.hex().upper(),
                    "description": k.description,
                }
                for name, k in cfg.keys.items()
            },
            "pdu_profiles": {
                hex(pid): {
                    "pdu_id": hex(p.pdu_id),
                    "pdu_id_int": p.pdu_id,
                    "name": p.name,
                    "source_ecu": p.source_ecu,
                    "dest_ecu": p.dest_ecu,
                    "payload_length": p.payload_length,
                    "freshness_bits": p.freshness_bits,
                    "truncated_mac_bits": p.truncated_mac_bits,
                    "description": p.description,
                }
                for pid, p in cfg.pdu_profiles.items()
            },
        }

    # ─── Dashboard HTML ───────────────────────────────────────────────
    @app.route("/")
    def dashboard():
        return render_template_string(DASHBOARD_HTML)

    # ─── API: Configuration ───────────────────────────────────────────
    @app.route("/api/config", methods=["GET"])
    def get_config():
        return jsonify(config_to_dict(state["config"]))

    @app.route("/api/config", methods=["PUT"])
    def update_config():
        try:
            data = request.get_json(force=True)

            # Rebuild config from submitted data
            mac_algo = MACAlgorithm.from_string(
                data.get("mac_algorithm", "CMAC-AES128")
            )

            keys = {}
            for name, kd in data.get("keys", {}).items():
                key_hex = kd.get("key_hex", "").replace(" ", "")
                keys[name] = KeyEntry(
                    ecu_name=name,
                    key_id=int(kd.get("key_id", 0)),
                    key_bytes=bytes.fromhex(key_hex),
                    description=kd.get("description", ""),
                )

            profiles = {}
            for _, pd in data.get("pdu_profiles", {}).items():
                pid_raw = pd.get("pdu_id", "0x0")
                pid = int(pid_raw, 0) if isinstance(pid_raw, str) else int(pid_raw)
                profiles[pid] = PDUProfile(
                    pdu_id=pid,
                    name=pd.get("name", ""),
                    source_ecu=pd.get("source_ecu", ""),
                    dest_ecu=pd.get("dest_ecu", ""),
                    payload_length=int(pd.get("payload_length", 4)),
                    freshness_bits=int(pd.get("freshness_bits", 32)),
                    truncated_mac_bits=int(pd.get("truncated_mac_bits", 24)),
                    description=pd.get("description", ""),
                )

            new_config = SecOCConfig(
                mac_algorithm=mac_algo,
                mac_length_bits=int(data.get("mac_length_bits", 128)),
                truncated_mac_bits=int(data.get("truncated_mac_bits", 24)),
                freshness_bits=int(data.get("freshness_bits", 32)),
                freshness_max_delta=int(data.get("freshness_max_delta", 5)),
                keys=keys,
                pdu_profiles=profiles,
            )

            state["config"] = new_config
            state["freshness"] = FreshnessManager(
                freshness_bits=new_config.freshness_bits,
                max_delta=new_config.freshness_max_delta,
            )

            return jsonify({"status": "ok", "config": config_to_dict(new_config)})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 400

    # ─── API: Generate Secured Frame ──────────────────────────────────
    @app.route("/api/generate", methods=["POST"])
    def generate_frame():
        try:
            data = request.get_json(force=True)
            pdu_id = int(data.get("pdu_id", "0"), 0) if isinstance(
                data.get("pdu_id"), str
            ) else int(data.get("pdu_id", 0))
            payload_hex = data.get("payload", "").replace(" ", "")
            payload = bytes.fromhex(payload_hex)

            builder = get_builder()
            secured = builder.build_secured_pdu(pdu_id, payload)

            profile = state["config"].pdu_profiles[pdu_id]
            fit = CANFrameCodec.check_fit(
                profile.payload_length,
                profile.freshness_bytes,
                profile.truncated_mac_bytes,
            )

            can_frame_str = None
            if fit["fits"]:
                frame = CANFrameCodec.encode(secured)
                can_frame_str = frame.to_hex_string()

            return jsonify({
                "status": "ok",
                "secured_pdu": {
                    "pdu_id": hex(secured.pdu_id),
                    "authentic_payload": secured.authentic_payload.hex().upper(),
                    "freshness_value": secured.freshness_value,
                    "freshness_hex": secured.freshness_value.to_bytes(
                        secured.freshness_bytes_len, "big"
                    ).hex().upper(),
                    "truncated_mac": secured.truncated_mac.hex().upper(),
                    "full_mac": secured.full_mac.hex().upper(),
                    "secured_payload": secured.to_hex(),
                    "total_length": secured.total_length,
                },
                "can_frame": can_frame_str,
                "fit_check": fit,
            })
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 400

    # ─── API: Verify Secured Frame ────────────────────────────────────
    @app.route("/api/verify", methods=["POST"])
    def verify_frame():
        try:
            data = request.get_json(force=True)
            pdu_id = int(data.get("pdu_id", "0"), 0) if isinstance(
                data.get("pdu_id"), str
            ) else int(data.get("pdu_id", 0))
            frame_hex = data.get("frame", "").replace(" ", "")
            frame_bytes = bytes.fromhex(frame_hex)

            builder = get_builder()
            result = builder.verify_secured_pdu(pdu_id, frame_bytes)

            return jsonify({
                "status": "ok",
                "verification": {
                    "is_verified": result.is_verified,
                    "status": result.status.value,
                    "pdu_id": hex(result.pdu_id),
                    "expected_mac": result.expected_mac.hex().upper() if result.expected_mac else None,
                    "received_mac": result.received_mac.hex().upper() if result.received_mac else None,
                    "freshness_received": result.freshness_received,
                    "freshness_expected": result.freshness_expected,
                    "detail": result.detail,
                    "summary": result.summary(),
                },
            })
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 400

    # ─── API: Attack Simulation ───────────────────────────────────────
    @app.route("/api/attack", methods=["POST"])
    def run_attacks():
        try:
            data = request.get_json(force=True)
            pdu_id = int(data.get("pdu_id", "0"), 0) if isinstance(
                data.get("pdu_id"), str
            ) else int(data.get("pdu_id", 0))
            payload_hex = data.get("payload", "").replace(" ", "")
            payload = bytes.fromhex(payload_hex)

            # Reset freshness for clean attack run
            state["freshness"].reset()

            builder = get_builder()
            logger = SecOCLogger(verbose=False, show_hex=False)
            attacker = AttackSimulator(builder, state["freshness"], logger)
            results = attacker.run_all_attacks(pdu_id, payload)

            attack_results = []
            for r in results:
                attack_results.append({
                    "attack_type": r.attack_type.value,
                    "detected": r.detected,
                    "description": r.description,
                    "pdu_id": hex(r.pdu_id),
                    "verification_status": r.verification.status.value,
                    "detail": r.verification.detail,
                    "original_payload": r.original_payload.hex().upper() if r.original_payload else None,
                    "tampered_payload": r.tampered_payload.hex().upper() if r.tampered_payload else None,
                    "expected_mac": r.verification.expected_mac.hex().upper() if r.verification.expected_mac else None,
                    "received_mac": r.verification.received_mac.hex().upper() if r.verification.received_mac else None,
                })

            total_attacks = len(results) - 1  # exclude baseline
            detected_count = sum(1 for r in results[1:] if r.detected)

            return jsonify({
                "status": "ok",
                "results": attack_results,
                "summary": {
                    "total_attacks": total_attacks,
                    "detected": detected_count,
                    "bypassed": total_attacks - detected_count,
                    "detection_rate": f"{(detected_count / total_attacks * 100):.0f}%" if total_attacks > 0 else "N/A",
                },
            })
        except Exception as e:
            return jsonify({"status": "error", "message": str(e), "trace": traceback.format_exc()}), 400

    # ─── API: Batch Generate ──────────────────────────────────────────
    @app.route("/api/batch", methods=["POST"])
    def batch_generate():
        try:
            data = request.get_json(force=True)
            pdu_id = int(data.get("pdu_id", "0"), 0) if isinstance(
                data.get("pdu_id"), str
            ) else int(data.get("pdu_id", 0))
            payload_hex = data.get("payload", "").replace(" ", "")
            payload = bytes.fromhex(payload_hex)
            count = min(int(data.get("count", 5)), 50)

            builder = get_builder()
            frames = []
            for i in range(count):
                secured = builder.build_secured_pdu(pdu_id, payload)
                frames.append({
                    "index": i,
                    "freshness_value": secured.freshness_value,
                    "truncated_mac": secured.truncated_mac.hex().upper(),
                    "secured_payload": secured.to_hex(),
                    "total_length": secured.total_length,
                })

            return jsonify({"status": "ok", "frames": frames, "count": len(frames)})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 400

    # ─── API: Freshness State ─────────────────────────────────────────
    @app.route("/api/freshness", methods=["GET"])
    def get_freshness():
        snapshot = state["freshness"].get_state_snapshot()
        return jsonify({
            "status": "ok",
            "tx_counters": {hex(k): v for k, v in snapshot["tx_counters"].items()},
            "rx_counters": {hex(k): v for k, v in snapshot["rx_counters"].items()},
        })

    @app.route("/api/freshness/reset", methods=["POST"])
    def reset_freshness():
        state["freshness"].reset()
        return jsonify({"status": "ok", "message": "All freshness counters reset"})

    # ─── API: CAN Frame Fit Check ─────────────────────────────────────
    @app.route("/api/fit-check", methods=["POST"])
    def fit_check():
        try:
            data = request.get_json(force=True)
            payload_len = int(data.get("payload_length", 4))
            freshness_bits = int(data.get("freshness_bits", 32))
            mac_bits = int(data.get("truncated_mac_bits", 24))
            is_fd = bool(data.get("is_fd", False))

            freshness_bytes = (freshness_bits + 7) // 8
            mac_bytes = (mac_bits + 7) // 8

            fit = CANFrameCodec.check_fit(payload_len, freshness_bytes, mac_bytes, is_fd)
            return jsonify({"status": "ok", "fit": fit})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 400

    return app


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Dashboard HTML — embedded as a string for zero-dependency deployment
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecOC Simulator — Dashboard</title>
<style>
/* ═══════════════════════════════════════════════════════════════════
   DESIGN SYSTEM — Dark industrial automotive HUD aesthetic
   ═══════════════════════════════════════════════════════════════════ */

@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Outfit:wght@300;400;500;600;700;800&display=swap');

:root {
  --bg-deep:      #07090d;
  --bg-panel:     #0d1117;
  --bg-card:      #131920;
  --bg-input:     #0d1117;
  --bg-hover:     #1a2233;
  --border:       #1e2a3a;
  --border-focus: #2d6adf;
  --border-glow:  #2d6adf33;

  --text-primary:   #e2e8f0;
  --text-secondary: #8899aa;
  --text-dim:       #556677;

  --accent:       #2d6adf;
  --accent-glow:  #2d6adf44;
  --green:        #10b981;
  --green-glow:   #10b98133;
  --red:          #ef4444;
  --red-glow:     #ef444433;
  --amber:        #f59e0b;
  --amber-glow:   #f59e0b33;
  --cyan:         #06b6d4;
  --cyan-glow:    #06b6d433;
  --purple:       #8b5cf6;
  --purple-glow:  #8b5cf633;

  --font-mono:    'JetBrains Mono', 'Fira Code', monospace;
  --font-display: 'Outfit', system-ui, sans-serif;

  --radius:       8px;
  --radius-lg:    12px;
  --transition:   all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  font-family: var(--font-mono);
  background: var(--bg-deep);
  color: var(--text-primary);
  min-height: 100vh;
  font-size: 13px;
  line-height: 1.6;
}

/* ═══ Scrollbar ═══ */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-deep); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-dim); }

/* ═══ Header ═══ */
.header {
  background: var(--bg-panel);
  border-bottom: 1px solid var(--border);
  padding: 16px 32px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  z-index: 100;
  backdrop-filter: blur(12px);
}

.header-brand {
  display: flex;
  align-items: center;
  gap: 16px;
}

.header-logo {
  width: 40px;
  height: 40px;
  background: linear-gradient(135deg, var(--accent), var(--cyan));
  border-radius: var(--radius);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
  box-shadow: 0 0 20px var(--accent-glow);
}

.header h1 {
  font-family: var(--font-display);
  font-size: 20px;
  font-weight: 700;
  letter-spacing: -0.5px;
}

.header h1 span {
  color: var(--text-dim);
  font-weight: 400;
  font-size: 13px;
  margin-left: 8px;
}

.header-status {
  display: flex;
  align-items: center;
  gap: 12px;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--green);
  box-shadow: 0 0 8px var(--green-glow);
  animation: pulse 2s infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

/* ═══ Layout ═══ */
.app-layout {
  display: grid;
  grid-template-columns: 300px 1fr;
  min-height: calc(100vh - 73px);
}

/* ═══ Sidebar ═══ */
.sidebar {
  background: var(--bg-panel);
  border-right: 1px solid var(--border);
  padding: 20px 16px;
  overflow-y: auto;
  max-height: calc(100vh - 73px);
}

.sidebar-section {
  margin-bottom: 24px;
}

.sidebar-title {
  font-family: var(--font-display);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--text-dim);
  margin-bottom: 12px;
  padding-left: 4px;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border-radius: var(--radius);
  cursor: pointer;
  transition: var(--transition);
  color: var(--text-secondary);
  font-size: 13px;
  border: 1px solid transparent;
}

.nav-item:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.nav-item.active {
  background: var(--accent-glow);
  color: var(--accent);
  border-color: var(--accent);
  font-weight: 500;
}

.nav-icon {
  font-size: 16px;
  width: 24px;
  text-align: center;
}

/* ═══ Main Content ═══ */
.main-content {
  padding: 24px 32px;
  overflow-y: auto;
  max-height: calc(100vh - 73px);
}

.page { display: none; }
.page.active { display: block; }

.page-header {
  margin-bottom: 24px;
}

.page-header h2 {
  font-family: var(--font-display);
  font-size: 24px;
  font-weight: 700;
  letter-spacing: -0.5px;
  margin-bottom: 4px;
}

.page-header p {
  color: var(--text-secondary);
  font-size: 13px;
}

/* ═══ Cards ═══ */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 20px;
  margin-bottom: 16px;
  transition: var(--transition);
}

.card:hover {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 1px var(--border-glow);
}

.card-title {
  font-family: var(--font-display);
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 16px;
}

/* ═══ Stat Cards (Overview) ═══ */
.stat-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 24px;
}

.stat-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 20px;
  position: relative;
  overflow: hidden;
}

.stat-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
}

.stat-card.blue::before { background: var(--accent); box-shadow: 0 0 12px var(--accent-glow); }
.stat-card.green::before { background: var(--green); box-shadow: 0 0 12px var(--green-glow); }
.stat-card.amber::before { background: var(--amber); box-shadow: 0 0 12px var(--amber-glow); }
.stat-card.purple::before { background: var(--purple); box-shadow: 0 0 12px var(--purple-glow); }

.stat-label {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-dim);
  margin-bottom: 8px;
}

.stat-value {
  font-family: var(--font-display);
  font-size: 28px;
  font-weight: 700;
}

.stat-card.blue .stat-value { color: var(--accent); }
.stat-card.green .stat-value { color: var(--green); }
.stat-card.amber .stat-value { color: var(--amber); }
.stat-card.purple .stat-value { color: var(--purple); }

.stat-sub {
  font-size: 11px;
  color: var(--text-dim);
  margin-top: 4px;
}

/* ═══ Forms ═══ */
.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-bottom: 12px;
}

.form-row.full {
  grid-template-columns: 1fr;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.form-group label {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-dim);
}

.form-group input,
.form-group select {
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 8px 12px;
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--text-primary);
  transition: var(--transition);
  outline: none;
}

.form-group input:focus,
.form-group select:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-glow);
}

.form-group select {
  cursor: pointer;
  appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23556677' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 12px center;
  padding-right: 32px;
}

/* ═══ Buttons ═══ */
.btn {
  font-family: var(--font-mono);
  font-size: 13px;
  font-weight: 500;
  padding: 10px 20px;
  border-radius: 6px;
  border: 1px solid transparent;
  cursor: pointer;
  transition: var(--transition);
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

.btn-primary {
  background: var(--accent);
  color: white;
  border-color: var(--accent);
}

.btn-primary:hover {
  background: #3b7bf5;
  box-shadow: 0 0 20px var(--accent-glow);
}

.btn-danger {
  background: transparent;
  color: var(--red);
  border-color: var(--red);
}

.btn-danger:hover {
  background: var(--red-glow);
}

.btn-ghost {
  background: transparent;
  color: var(--text-secondary);
  border-color: var(--border);
}

.btn-ghost:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.btn-group {
  display: flex;
  gap: 8px;
  margin-top: 16px;
}

/* ═══ Result Panels ═══ */
.result-panel {
  background: var(--bg-deep);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px;
  margin-top: 16px;
  font-family: var(--font-mono);
  font-size: 12px;
  max-height: 400px;
  overflow-y: auto;
}

.result-line {
  padding: 6px 0;
  border-bottom: 1px solid #111820;
  display: flex;
  align-items: flex-start;
  gap: 12px;
}

.result-line:last-child { border-bottom: none; }

.result-key {
  color: var(--cyan);
  min-width: 160px;
  flex-shrink: 0;
}

.result-value {
  color: var(--text-primary);
  word-break: break-all;
}

.result-hex {
  color: var(--purple);
  font-weight: 500;
}

.result-success {
  color: var(--green);
  font-weight: 600;
}

.result-fail {
  color: var(--red);
  font-weight: 600;
}

/* ═══ Attack Results ═══ */
.attack-card {
  background: var(--bg-deep);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px;
  margin-bottom: 10px;
  transition: var(--transition);
  border-left: 3px solid transparent;
}

.attack-card.detected {
  border-left-color: var(--green);
}

.attack-card.bypassed {
  border-left-color: var(--red);
}

.attack-card.baseline {
  border-left-color: var(--accent);
}

.attack-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.attack-type {
  font-weight: 600;
  text-transform: uppercase;
  font-size: 11px;
  letter-spacing: 1px;
}

.attack-badge {
  padding: 2px 10px;
  border-radius: 20px;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.badge-detected {
  background: var(--green-glow);
  color: var(--green);
  border: 1px solid var(--green);
}

.badge-bypassed {
  background: var(--red-glow);
  color: var(--red);
  border: 1px solid var(--red);
}

.badge-baseline {
  background: var(--accent-glow);
  color: var(--accent);
  border: 1px solid var(--accent);
}

.attack-detail {
  color: var(--text-secondary);
  font-size: 12px;
  line-height: 1.5;
}

.attack-mac-compare {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
  margin-top: 8px;
  font-size: 11px;
}

.mac-label { color: var(--text-dim); }
.mac-value { color: var(--purple); font-weight: 500; }

/* ═══ Summary Bar ═══ */
.summary-bar {
  display: flex;
  align-items: center;
  gap: 24px;
  padding: 16px 20px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  margin-bottom: 16px;
}

.summary-stat {
  text-align: center;
}

.summary-stat .num {
  font-family: var(--font-display);
  font-size: 32px;
  font-weight: 700;
}

.summary-stat .lbl {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-dim);
}

.summary-stat.green .num { color: var(--green); }
.summary-stat.red .num { color: var(--red); }
.summary-stat.blue .num { color: var(--accent); }

.detection-bar-track {
  flex: 1;
  height: 8px;
  background: var(--bg-deep);
  border-radius: 4px;
  overflow: hidden;
}

.detection-bar-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--green), var(--cyan));
  border-radius: 4px;
  transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
}

/* ═══ Config Table ═══ */
.config-table {
  width: 100%;
  border-collapse: collapse;
}

.config-table th, .config-table td {
  text-align: left;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
}

.config-table th {
  color: var(--text-dim);
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 1px;
  font-weight: 600;
}

.config-table td {
  color: var(--text-primary);
}

.config-table .hex {
  color: var(--purple);
  font-weight: 500;
}

.config-table .tag {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
}

.tag-blue { background: var(--accent-glow); color: var(--accent); }
.tag-green { background: var(--green-glow); color: var(--green); }
.tag-amber { background: var(--amber-glow); color: var(--amber); }

/* ═══ Hex Visualizer ═══ */
.hex-visual {
  display: flex;
  gap: 2px;
  flex-wrap: wrap;
  padding: 12px;
  background: var(--bg-deep);
  border-radius: var(--radius);
  margin-top: 12px;
  border: 1px solid var(--border);
}

.hex-byte {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 4px 6px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
  min-width: 32px;
}

.hex-byte .label {
  font-size: 8px;
  color: var(--text-dim);
  margin-top: 2px;
}

.hex-byte.payload { background: var(--accent-glow); color: var(--accent); }
.hex-byte.freshness { background: var(--amber-glow); color: var(--amber); }
.hex-byte.mac { background: var(--green-glow); color: var(--green); }

.hex-legend {
  display: flex;
  gap: 16px;
  margin-top: 8px;
  font-size: 11px;
}

.hex-legend-item {
  display: flex;
  align-items: center;
  gap: 6px;
}

.hex-legend-dot {
  width: 10px;
  height: 10px;
  border-radius: 3px;
}

.hex-legend-dot.payload { background: var(--accent); }
.hex-legend-dot.freshness { background: var(--amber); }
.hex-legend-dot.mac { background: var(--green); }

/* ═══ Batch table ═══ */
.batch-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}

.batch-table th, .batch-table td {
  padding: 8px 12px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}

.batch-table th {
  color: var(--text-dim);
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.batch-table td.mono {
  color: var(--purple);
  font-weight: 500;
}

/* ═══ Loader ═══ */
.loader {
  display: none;
  width: 16px;
  height: 16px;
  border: 2px solid var(--border);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
}

.loading .loader { display: inline-block; }

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* ═══ ECU Network Diagram ═══ */
.ecu-network {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 20px;
  flex-wrap: wrap;
}

.ecu-node {
  background: var(--bg-deep);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 16px;
  text-align: center;
  min-width: 120px;
  transition: var(--transition);
}

.ecu-node:hover {
  border-color: var(--cyan);
  box-shadow: 0 0 12px var(--cyan-glow);
}

.ecu-node .ecu-name {
  font-weight: 600;
  font-size: 12px;
  color: var(--cyan);
}

.ecu-node .ecu-key-id {
  font-size: 10px;
  color: var(--text-dim);
  margin-top: 2px;
}

.ecu-arrow {
  color: var(--text-dim);
  font-size: 18px;
}

/* ═══ Toast notifications ═══ */
.toast-container {
  position: fixed;
  bottom: 24px;
  right: 24px;
  z-index: 9999;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.toast {
  padding: 12px 20px;
  border-radius: var(--radius);
  font-size: 12px;
  font-family: var(--font-mono);
  animation: slideIn 0.3s ease-out;
  max-width: 400px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.4);
}

.toast-success {
  background: var(--green-glow);
  color: var(--green);
  border: 1px solid var(--green);
}

.toast-error {
  background: var(--red-glow);
  color: var(--red);
  border: 1px solid var(--red);
}

@keyframes slideIn {
  from { transform: translateX(100%); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}

/* ═══ Responsive ═══ */
@media (max-width: 900px) {
  .app-layout { grid-template-columns: 1fr; }
  .sidebar { display: none; }
  .stat-grid { grid-template-columns: repeat(2, 1fr); }
}
</style>
</head>
<body>

<!-- ═══ Header ═══ -->
<header class="header">
  <div class="header-brand">
    <div class="header-logo">🔐</div>
    <h1>SecOC Simulator <span>v1.0.0</span></h1>
  </div>
  <div class="header-status">
    <div class="status-dot"></div>
    <span style="color:var(--text-dim);font-size:12px;" id="statusText">Engine Ready</span>
  </div>
</header>

<!-- ═══ Layout ═══ -->
<div class="app-layout">
  <!-- Sidebar -->
  <nav class="sidebar">
    <div class="sidebar-section">
      <div class="sidebar-title">Operations</div>
      <div class="nav-item active" data-page="overview" onclick="showPage('overview')">
        <span class="nav-icon">📊</span> Overview
      </div>
      <div class="nav-item" data-page="generate" onclick="showPage('generate')">
        <span class="nav-icon">🔒</span> Generate Frame
      </div>
      <div class="nav-item" data-page="verify" onclick="showPage('verify')">
        <span class="nav-icon">✅</span> Verify Frame
      </div>
      <div class="nav-item" data-page="attack" onclick="showPage('attack')">
        <span class="nav-icon">⚔️</span> Attack Simulator
      </div>
      <div class="nav-item" data-page="batch" onclick="showPage('batch')">
        <span class="nav-icon">📦</span> Batch Generate
      </div>
    </div>
    <div class="sidebar-section">
      <div class="sidebar-title">Configuration</div>
      <div class="nav-item" data-page="config" onclick="showPage('config')">
        <span class="nav-icon">⚙️</span> SecOC Config
      </div>
      <div class="nav-item" data-page="keys" onclick="showPage('keys')">
        <span class="nav-icon">🔑</span> ECU Keys
      </div>
      <div class="nav-item" data-page="pdus" onclick="showPage('pdus')">
        <span class="nav-icon">📡</span> PDU Profiles
      </div>
    </div>
    <div class="sidebar-section">
      <div class="sidebar-title">Diagnostics</div>
      <div class="nav-item" data-page="freshness" onclick="showPage('freshness')">
        <span class="nav-icon">🔄</span> Freshness State
      </div>
    </div>
  </nav>

  <!-- Main Content -->
  <main class="main-content">

    <!-- ═══ Page: Overview ═══ -->
    <div id="page-overview" class="page active">
      <div class="page-header">
        <h2>Dashboard Overview</h2>
        <p>AUTOSAR SecOC Secure Onboard Communication Simulator</p>
      </div>

      <div class="stat-grid" id="overviewStats">
        <div class="stat-card blue">
          <div class="stat-label">MAC Algorithm</div>
          <div class="stat-value" id="ov-algo">—</div>
          <div class="stat-sub">Authentication engine</div>
        </div>
        <div class="stat-card green">
          <div class="stat-label">ECU Keys</div>
          <div class="stat-value" id="ov-keys">—</div>
          <div class="stat-sub">Configured endpoints</div>
        </div>
        <div class="stat-card amber">
          <div class="stat-label">PDU Profiles</div>
          <div class="stat-value" id="ov-pdus">—</div>
          <div class="stat-sub">Message definitions</div>
        </div>
        <div class="stat-card purple">
          <div class="stat-label">Truncated MAC</div>
          <div class="stat-value" id="ov-macbits">—</div>
          <div class="stat-sub">bits per frame</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">🌐 ECU Network Topology</div>
        <div class="ecu-network" id="ecuNetwork"></div>
      </div>

      <div class="card">
        <div class="card-title">📡 PDU Routing Table</div>
        <div style="overflow-x:auto">
          <table class="config-table" id="pduOverviewTable">
            <thead>
              <tr>
                <th>PDU ID</th>
                <th>Name</th>
                <th>Route</th>
                <th>Payload</th>
                <th>Freshness</th>
                <th>MAC Bits</th>
                <th>CAN Fit</th>
              </tr>
            </thead>
            <tbody></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ═══ Page: Generate ═══ -->
    <div id="page-generate" class="page">
      <div class="page-header">
        <h2>Generate Secured Frame</h2>
        <p>Build an authenticated Secured I-PDU from an Authentic payload</p>
      </div>

      <div class="card">
        <div class="card-title">🔒 Frame Parameters</div>
        <div class="form-row">
          <div class="form-group">
            <label>PDU Profile</label>
            <select id="gen-pdu-select" onchange="onGenPduChange()"></select>
          </div>
          <div class="form-group">
            <label>Payload (Hex)</label>
            <input type="text" id="gen-payload" placeholder="DEADBEEF" spellcheck="false">
          </div>
        </div>
        <div id="gen-pdu-info" style="color:var(--text-dim);font-size:11px;margin-bottom:12px;"></div>
        <div class="btn-group">
          <button class="btn btn-primary" onclick="doGenerate()">
            <span>🔐</span> Generate Secured Frame
            <div class="loader" id="gen-loader"></div>
          </button>
        </div>
      </div>

      <div id="gen-result" style="display:none">
        <div class="card">
          <div class="card-title">📋 Secured I-PDU Result</div>
          <div class="result-panel" id="gen-result-panel"></div>
          <div id="gen-hex-visual"></div>
          <div class="hex-legend">
            <div class="hex-legend-item"><div class="hex-legend-dot payload"></div> Payload</div>
            <div class="hex-legend-item"><div class="hex-legend-dot freshness"></div> Freshness</div>
            <div class="hex-legend-item"><div class="hex-legend-dot mac"></div> Truncated MAC</div>
          </div>
        </div>
      </div>
    </div>

    <!-- ═══ Page: Verify ═══ -->
    <div id="page-verify" class="page">
      <div class="page-header">
        <h2>Verify Secured Frame</h2>
        <p>Authenticate a received Secured I-PDU against the expected MAC</p>
      </div>

      <div class="card">
        <div class="card-title">✅ Verification Input</div>
        <div class="form-row">
          <div class="form-group">
            <label>PDU Profile</label>
            <select id="ver-pdu-select"></select>
          </div>
          <div class="form-group">
            <label>Secured Frame (Hex)</label>
            <input type="text" id="ver-frame" placeholder="DEADBEEF00000000B69770" spellcheck="false">
          </div>
        </div>
        <div class="btn-group">
          <button class="btn btn-primary" onclick="doVerify()">
            <span>🔍</span> Verify Frame
            <div class="loader" id="ver-loader"></div>
          </button>
        </div>
      </div>

      <div id="ver-result" style="display:none">
        <div class="card">
          <div class="card-title">📋 Verification Result</div>
          <div class="result-panel" id="ver-result-panel"></div>
        </div>
      </div>
    </div>

    <!-- ═══ Page: Attack ═══ -->
    <div id="page-attack" class="page">
      <div class="page-header">
        <h2>Attack Simulator</h2>
        <p>Run replay, spoofing, tampering, and fuzzing attacks against SecOC</p>
      </div>

      <div class="card">
        <div class="card-title">⚔️ Attack Configuration</div>
        <div class="form-row">
          <div class="form-group">
            <label>Target PDU</label>
            <select id="atk-pdu-select" onchange="onAtkPduChange()"></select>
          </div>
          <div class="form-group">
            <label>Payload (Hex)</label>
            <input type="text" id="atk-payload" placeholder="DEADBEEF" spellcheck="false">
          </div>
        </div>
        <div class="btn-group">
          <button class="btn btn-danger" onclick="doAttack()">
            <span>🛡️</span> Launch All Attacks
            <div class="loader" id="atk-loader"></div>
          </button>
        </div>
      </div>

      <div id="atk-result" style="display:none">
        <div id="atk-summary"></div>
        <div id="atk-results-list"></div>
      </div>
    </div>

    <!-- ═══ Page: Batch ═══ -->
    <div id="page-batch" class="page">
      <div class="page-header">
        <h2>Batch Generate</h2>
        <p>Generate multiple consecutive secured frames with incrementing freshness</p>
      </div>

      <div class="card">
        <div class="card-title">📦 Batch Parameters</div>
        <div class="form-row">
          <div class="form-group">
            <label>PDU Profile</label>
            <select id="batch-pdu-select"></select>
          </div>
          <div class="form-group">
            <label>Payload (Hex)</label>
            <input type="text" id="batch-payload" placeholder="DEADBEEF" spellcheck="false">
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Frame Count</label>
            <input type="number" id="batch-count" value="10" min="1" max="50">
          </div>
        </div>
        <div class="btn-group">
          <button class="btn btn-primary" onclick="doBatch()">
            <span>⚡</span> Generate Batch
            <div class="loader" id="batch-loader"></div>
          </button>
        </div>
      </div>

      <div id="batch-result" style="display:none">
        <div class="card">
          <div class="card-title">📋 Generated Frames</div>
          <div style="overflow-x:auto">
            <table class="batch-table" id="batchTable">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Freshness</th>
                  <th>Truncated MAC</th>
                  <th>Secured Payload</th>
                  <th>Length</th>
                </tr>
              </thead>
              <tbody></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- ═══ Page: Config ═══ -->
    <div id="page-config" class="page">
      <div class="page-header">
        <h2>SecOC Configuration</h2>
        <p>Global authentication parameters</p>
      </div>

      <div class="card">
        <div class="card-title">⚙️ Global Parameters</div>
        <div class="form-row">
          <div class="form-group">
            <label>MAC Algorithm</label>
            <select id="cfg-algo">
              <option value="CMAC-AES128">CMAC-AES128</option>
              <option value="HMAC-SHA256">HMAC-SHA256</option>
            </select>
          </div>
          <div class="form-group">
            <label>MAC Length (bits)</label>
            <input type="number" id="cfg-mac-len" value="128">
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Truncated MAC (bits)</label>
            <input type="number" id="cfg-trunc-mac" value="24">
          </div>
          <div class="form-group">
            <label>Freshness Bits</label>
            <input type="number" id="cfg-fresh-bits" value="32">
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Max Freshness Delta</label>
            <input type="number" id="cfg-max-delta" value="5">
          </div>
        </div>
        <div class="btn-group">
          <button class="btn btn-primary" onclick="saveConfig()">
            <span>💾</span> Save Configuration
          </button>
          <button class="btn btn-ghost" onclick="loadConfig()">
            <span>🔄</span> Reload
          </button>
        </div>
      </div>
    </div>

    <!-- ═══ Page: Keys ═══ -->
    <div id="page-keys" class="page">
      <div class="page-header">
        <h2>ECU Keys</h2>
        <p>Symmetric key configuration per ECU endpoint</p>
      </div>

      <div class="card">
        <div class="card-title">🔑 Key Store</div>
        <div style="overflow-x:auto">
          <table class="config-table" id="keysTable">
            <thead>
              <tr>
                <th>ECU Name</th>
                <th>Key ID</th>
                <th>Key (Hex)</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ═══ Page: PDUs ═══ -->
    <div id="page-pdus" class="page">
      <div class="page-header">
        <h2>PDU Profiles</h2>
        <p>Message authentication profile definitions</p>
      </div>

      <div class="card">
        <div class="card-title">📡 Profile Table</div>
        <div style="overflow-x:auto">
          <table class="config-table" id="pdusTable">
            <thead>
              <tr>
                <th>PDU ID</th>
                <th>Name</th>
                <th>Source ECU</th>
                <th>Dest ECU</th>
                <th>Payload</th>
                <th>Freshness</th>
                <th>MAC Bits</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ═══ Page: Freshness ═══ -->
    <div id="page-freshness" class="page">
      <div class="page-header">
        <h2>Freshness Counter State</h2>
        <p>Monitor TX/RX freshness counters per PDU</p>
      </div>

      <div class="card">
        <div class="card-title">🔄 Counter State</div>
        <div class="btn-group" style="margin-top:0;margin-bottom:16px;">
          <button class="btn btn-primary" onclick="loadFreshness()">
            <span>🔄</span> Refresh
          </button>
          <button class="btn btn-danger" onclick="resetFreshness()">
            <span>🗑️</span> Reset All
          </button>
        </div>
        <div class="card-grid">
          <div>
            <h4 style="color:var(--cyan);margin-bottom:8px;font-size:12px;">TX Counters (Sender)</h4>
            <div class="result-panel" id="fresh-tx" style="max-height:200px;">
              <span style="color:var(--text-dim)">No data — generate some frames first</span>
            </div>
          </div>
          <div>
            <h4 style="color:var(--amber);margin-bottom:8px;font-size:12px;">RX Counters (Receiver)</h4>
            <div class="result-panel" id="fresh-rx" style="max-height:200px;">
              <span style="color:var(--text-dim)">No data — verify some frames first</span>
            </div>
          </div>
        </div>
      </div>
    </div>

  </main>
</div>

<!-- Toast container -->
<div class="toast-container" id="toasts"></div>

<script>
// ═══════════════════════════════════════════════════════════════════
//  SecOC Dashboard — Frontend Logic
// ═══════════════════════════════════════════════════════════════════

let CONFIG = null;

// ─── Navigation ──────────────────────────────────────────────────
function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  document.querySelector(`.nav-item[data-page="${name}"]`).classList.add('active');

  // Load data for specific pages
  if (name === 'freshness') loadFreshness();
  if (name === 'config') populateConfigForm();
}

// ─── Toast ───────────────────────────────────────────────────────
function toast(msg, type = 'success') {
  const container = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ─── API Helper ──────────────────────────────────────────────────
async function api(endpoint, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(endpoint, opts);
  const data = await res.json();
  if (data.status === 'error') throw new Error(data.message);
  return data;
}

// ─── Load Config & Populate ──────────────────────────────────────
async function loadConfig() {
  try {
    CONFIG = await api('/api/config');
    populateOverview();
    populateSelects();
    populateKeysTable();
    populatePdusTable();
    populateConfigForm();
    toast('Configuration loaded');
  } catch (e) {
    toast('Failed to load config: ' + e.message, 'error');
  }
}

function populateOverview() {
  if (!CONFIG) return;
  document.getElementById('ov-algo').textContent = CONFIG.mac_algorithm;
  document.getElementById('ov-keys').textContent = Object.keys(CONFIG.keys).length;
  document.getElementById('ov-pdus').textContent = Object.keys(CONFIG.pdu_profiles).length;
  document.getElementById('ov-macbits').textContent = CONFIG.truncated_mac_bits;

  // ECU Network
  const ecus = Object.keys(CONFIG.keys);
  const net = document.getElementById('ecuNetwork');
  net.innerHTML = ecus.map((name, i) => {
    const k = CONFIG.keys[name];
    return (i > 0 ? '<div class="ecu-arrow">⟷</div>' : '') +
      `<div class="ecu-node">
        <div class="ecu-name">${name}</div>
        <div class="ecu-key-id">Key ID: ${k.key_id}</div>
      </div>`;
  }).join('');

  // PDU Overview Table
  const tbody = document.querySelector('#pduOverviewTable tbody');
  tbody.innerHTML = '';
  for (const [_, p] of Object.entries(CONFIG.pdu_profiles)) {
    const payloadBytes = p.payload_length;
    const freshBytes = Math.ceil(p.freshness_bits / 8);
    const macBytes = Math.ceil(p.truncated_mac_bits / 8);
    const total = payloadBytes + freshBytes + macBytes;
    const fits = total <= 8;
    const fitsFd = total <= 64;
    let fitTag;
    if (fits) fitTag = '<span class="tag tag-green">CAN ✓</span>';
    else if (fitsFd) fitTag = '<span class="tag tag-amber">FD only</span>';
    else fitTag = '<span class="tag tag-blue">Too large</span>';

    tbody.innerHTML += `<tr>
      <td class="hex">${p.pdu_id}</td>
      <td>${p.name}</td>
      <td>${p.source_ecu} → ${p.dest_ecu}</td>
      <td>${p.payload_length}B</td>
      <td>${p.freshness_bits}b</td>
      <td>${p.truncated_mac_bits}b</td>
      <td>${fitTag} <span style="color:var(--text-dim)">${total}/8B</span></td>
    </tr>`;
  }
}

function populateSelects() {
  if (!CONFIG) return;
  const profiles = Object.values(CONFIG.pdu_profiles);
  const html = profiles.map(p =>
    `<option value="${p.pdu_id_int}">${p.pdu_id} — ${p.name}</option>`
  ).join('');

  ['gen-pdu-select', 'ver-pdu-select', 'atk-pdu-select', 'batch-pdu-select'].forEach(id => {
    document.getElementById(id).innerHTML = html;
  });

  onGenPduChange();
  onAtkPduChange();
}

function populateKeysTable() {
  if (!CONFIG) return;
  const tbody = document.querySelector('#keysTable tbody');
  tbody.innerHTML = '';
  for (const [name, k] of Object.entries(CONFIG.keys)) {
    tbody.innerHTML += `<tr>
      <td style="font-weight:600;color:var(--cyan)">${name}</td>
      <td>${k.key_id}</td>
      <td class="hex">${k.key_hex}</td>
      <td style="color:var(--text-dim)">${k.description}</td>
    </tr>`;
  }
}

function populatePdusTable() {
  if (!CONFIG) return;
  const tbody = document.querySelector('#pdusTable tbody');
  tbody.innerHTML = '';
  for (const [_, p] of Object.entries(CONFIG.pdu_profiles)) {
    tbody.innerHTML += `<tr>
      <td class="hex">${p.pdu_id}</td>
      <td style="font-weight:600">${p.name}</td>
      <td style="color:var(--cyan)">${p.source_ecu}</td>
      <td style="color:var(--amber)">${p.dest_ecu}</td>
      <td>${p.payload_length}B</td>
      <td>${p.freshness_bits}b</td>
      <td>${p.truncated_mac_bits}b</td>
      <td style="color:var(--text-dim)">${p.description}</td>
    </tr>`;
  }
}

function populateConfigForm() {
  if (!CONFIG) return;
  const algoMap = { 'CMAC_AES128': 'CMAC-AES128', 'HMAC_SHA256': 'HMAC-SHA256' };
  document.getElementById('cfg-algo').value = algoMap[CONFIG.mac_algorithm] || CONFIG.mac_algorithm;
  document.getElementById('cfg-mac-len').value = CONFIG.mac_length_bits;
  document.getElementById('cfg-trunc-mac').value = CONFIG.truncated_mac_bits;
  document.getElementById('cfg-fresh-bits').value = CONFIG.freshness_bits;
  document.getElementById('cfg-max-delta').value = CONFIG.freshness_max_delta;
}

function onGenPduChange() {
  const sel = document.getElementById('gen-pdu-select');
  const pid = sel.value;
  const profile = Object.values(CONFIG.pdu_profiles).find(p => p.pdu_id_int == pid);
  if (profile) {
    document.getElementById('gen-pdu-info').textContent =
      `${profile.description} | ${profile.payload_length}B payload | ` +
      `${profile.freshness_bits}b freshness | ${profile.truncated_mac_bits}b MAC`;
  }
}

function onAtkPduChange() {
  const sel = document.getElementById('atk-pdu-select');
  const pid = sel.value;
  const profile = Object.values(CONFIG.pdu_profiles).find(p => p.pdu_id_int == pid);
  if (profile) {
    const payHex = Array.from({length: profile.payload_length}, (_, i) =>
      ((i + 1) * 17).toString(16).padStart(2, '0')).join('').toUpperCase();
    document.getElementById('atk-payload').placeholder = payHex;
  }
}

// ─── Generate ────────────────────────────────────────────────────
async function doGenerate() {
  try {
    const pduId = document.getElementById('gen-pdu-select').value;
    const payload = document.getElementById('gen-payload').value.replace(/\s/g, '');
    if (!payload) { toast('Enter a hex payload', 'error'); return; }

    const data = await api('/api/generate', 'POST', {
      pdu_id: parseInt(pduId),
      payload: payload,
    });

    const s = data.secured_pdu;
    const panel = document.getElementById('gen-result-panel');
    panel.innerHTML = [
      line('PDU ID', s.pdu_id),
      line('Authentic Payload', s.authentic_payload, 'hex'),
      line('Freshness Value', s.freshness_value),
      line('Freshness (hex)', s.freshness_hex, 'hex'),
      line('Truncated MAC', s.truncated_mac, 'hex'),
      line('Full MAC', s.full_mac, 'hex'),
      line('Secured Payload', s.secured_payload, 'hex'),
      line('Total Length', s.total_length + ' bytes'),
      data.can_frame ? line('CAN Frame', data.can_frame) : line('CAN Frame', 'Does not fit Classic CAN', 'fail'),
      line('CAN Fit', data.fit_check.fits ? `✅ ${data.fit_check.total_bytes}/${data.fit_check.max_bytes}B` : `❌ ${data.fit_check.total_bytes}/${data.fit_check.max_bytes}B`,
        data.fit_check.fits ? 'success' : 'fail'),
    ].join('');

    // Hex visualizer
    renderHexVisual(s, document.getElementById('gen-hex-visual'));

    document.getElementById('gen-result').style.display = 'block';
    toast('Secured frame generated');
  } catch (e) {
    toast(e.message, 'error');
  }
}

function renderHexVisual(s, container) {
  const payloadBytes = hexToBytes(s.authentic_payload);
  const freshBytes = hexToBytes(s.freshness_hex);
  const macBytes = hexToBytes(s.truncated_mac);

  let html = '<div class="hex-visual">';
  payloadBytes.forEach((b, i) => {
    html += `<div class="hex-byte payload"><span>${b}</span><span class="label">P${i}</span></div>`;
  });
  freshBytes.forEach((b, i) => {
    html += `<div class="hex-byte freshness"><span>${b}</span><span class="label">F${i}</span></div>`;
  });
  macBytes.forEach((b, i) => {
    html += `<div class="hex-byte mac"><span>${b}</span><span class="label">M${i}</span></div>`;
  });
  html += '</div>';
  container.innerHTML = html;
}

function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(hex.substr(i, 2));
  }
  return bytes;
}

// ─── Verify ──────────────────────────────────────────────────────
async function doVerify() {
  try {
    const pduId = document.getElementById('ver-pdu-select').value;
    const frame = document.getElementById('ver-frame').value.replace(/\s/g, '');
    if (!frame) { toast('Enter a hex frame', 'error'); return; }

    const data = await api('/api/verify', 'POST', {
      pdu_id: parseInt(pduId),
      frame: frame,
    });

    const v = data.verification;
    const panel = document.getElementById('ver-result-panel');
    panel.innerHTML = [
      line('Status', v.is_verified ? '✅ VERIFIED' : '❌ ' + v.status, v.is_verified ? 'success' : 'fail'),
      line('PDU ID', v.pdu_id),
      v.expected_mac ? line('Expected MAC', v.expected_mac, 'hex') : '',
      v.received_mac ? line('Received MAC', v.received_mac, 'hex') : '',
      v.freshness_received !== null ? line('Freshness Received', v.freshness_received) : '',
      v.freshness_expected !== null ? line('Freshness Expected', v.freshness_expected) : '',
      line('Detail', v.detail),
    ].join('');

    document.getElementById('ver-result').style.display = 'block';
    toast(v.is_verified ? 'Frame verified!' : 'Verification failed', v.is_verified ? 'success' : 'error');
  } catch (e) {
    toast(e.message, 'error');
  }
}

// ─── Attack ──────────────────────────────────────────────────────
async function doAttack() {
  try {
    const pduId = document.getElementById('atk-pdu-select').value;
    let payload = document.getElementById('atk-payload').value.replace(/\s/g, '');

    if (!payload) {
      const profile = Object.values(CONFIG.pdu_profiles).find(p => p.pdu_id_int == pduId);
      payload = Array.from({length: profile.payload_length}, (_, i) =>
        ((i + 1) * 17).toString(16).padStart(2, '0')).join('');
    }

    const data = await api('/api/attack', 'POST', {
      pdu_id: parseInt(pduId),
      payload: payload,
    });

    const sum = data.summary;
    const pct = sum.total_attacks > 0
      ? (sum.detected / sum.total_attacks * 100).toFixed(0) : 0;

    document.getElementById('atk-summary').innerHTML = `
      <div class="summary-bar">
        <div class="summary-stat green">
          <div class="num">${sum.detected}</div>
          <div class="lbl">Detected</div>
        </div>
        <div class="summary-stat red">
          <div class="num">${sum.bypassed}</div>
          <div class="lbl">Bypassed</div>
        </div>
        <div class="detection-bar-track">
          <div class="detection-bar-fill" style="width:${pct}%"></div>
        </div>
        <div class="summary-stat blue">
          <div class="num">${pct}%</div>
          <div class="lbl">Detection</div>
        </div>
      </div>`;

    const list = document.getElementById('atk-results-list');
    list.innerHTML = data.results.map((r, i) => {
      const isBaseline = i === 0;
      const cls = isBaseline ? 'baseline' : (r.detected ? 'detected' : 'bypassed');
      const badgeCls = isBaseline ? 'badge-baseline' : (r.detected ? 'badge-detected' : 'badge-bypassed');
      const badgeText = isBaseline ? 'BASELINE' : (r.detected ? 'DETECTED' : 'BYPASSED');
      const icon = isBaseline ? '📊' : (r.detected ? '🛡️' : '⚠️');

      let macHtml = '';
      if (r.expected_mac && r.received_mac && r.expected_mac !== r.received_mac) {
        macHtml = `<div class="attack-mac-compare">
          <div><span class="mac-label">Expected: </span><span class="mac-value">${r.expected_mac}</span></div>
          <div><span class="mac-label">Received: </span><span class="mac-value">${r.received_mac}</span></div>
        </div>`;
      }

      return `<div class="attack-card ${cls}">
        <div class="attack-header">
          <span class="attack-type">${icon} ${r.attack_type}</span>
          <span class="attack-badge ${badgeCls}">${badgeText}</span>
        </div>
        <div class="attack-detail">${r.description}</div>
        <div class="attack-detail" style="margin-top:4px;color:var(--text-dim)">${r.verification_status}: ${r.detail}</div>
        ${macHtml}
      </div>`;
    }).join('');

    document.getElementById('atk-result').style.display = 'block';
    toast(`Attack simulation complete — ${sum.detected}/${sum.total_attacks} detected`);
  } catch (e) {
    toast(e.message, 'error');
  }
}

// ─── Batch ───────────────────────────────────────────────────────
async function doBatch() {
  try {
    const pduId = document.getElementById('batch-pdu-select').value;
    const payload = document.getElementById('batch-payload').value.replace(/\s/g, '');
    const count = document.getElementById('batch-count').value;
    if (!payload) { toast('Enter a hex payload', 'error'); return; }

    const data = await api('/api/batch', 'POST', {
      pdu_id: parseInt(pduId),
      payload: payload,
      count: parseInt(count),
    });

    const tbody = document.querySelector('#batchTable tbody');
    tbody.innerHTML = data.frames.map(f => `<tr>
      <td>${f.index}</td>
      <td>${f.freshness_value}</td>
      <td class="mono">${f.truncated_mac}</td>
      <td class="mono">${f.secured_payload}</td>
      <td>${f.total_length}B</td>
    </tr>`).join('');

    document.getElementById('batch-result').style.display = 'block';
    toast(`Generated ${data.count} frames`);
  } catch (e) {
    toast(e.message, 'error');
  }
}

// ─── Config Save ─────────────────────────────────────────────────
async function saveConfig() {
  try {
    const updatedConfig = {
      mac_algorithm: document.getElementById('cfg-algo').value,
      mac_length_bits: parseInt(document.getElementById('cfg-mac-len').value),
      truncated_mac_bits: parseInt(document.getElementById('cfg-trunc-mac').value),
      freshness_bits: parseInt(document.getElementById('cfg-fresh-bits').value),
      freshness_max_delta: parseInt(document.getElementById('cfg-max-delta').value),
      keys: CONFIG.keys,
      pdu_profiles: CONFIG.pdu_profiles,
    };

    await api('/api/config', 'PUT', updatedConfig);
    await loadConfig();
    toast('Configuration saved');
  } catch (e) {
    toast(e.message, 'error');
  }
}

// ─── Freshness ───────────────────────────────────────────────────
async function loadFreshness() {
  try {
    const data = await api('/api/freshness');
    const txEl = document.getElementById('fresh-tx');
    const rxEl = document.getElementById('fresh-rx');

    const txEntries = Object.entries(data.tx_counters);
    const rxEntries = Object.entries(data.rx_counters);

    txEl.innerHTML = txEntries.length
      ? txEntries.map(([k, v]) => `<div class="result-line">
          <span class="result-key">${k}</span>
          <span class="result-value">${v}</span>
        </div>`).join('')
      : '<span style="color:var(--text-dim)">No TX counters active</span>';

    rxEl.innerHTML = rxEntries.length
      ? rxEntries.map(([k, v]) => `<div class="result-line">
          <span class="result-key">${k}</span>
          <span class="result-value">${v}</span>
        </div>`).join('')
      : '<span style="color:var(--text-dim)">No RX counters active</span>';
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function resetFreshness() {
  try {
    await api('/api/freshness/reset', 'POST');
    await loadFreshness();
    toast('Freshness counters reset');
  } catch (e) {
    toast(e.message, 'error');
  }
}

// ─── Helpers ─────────────────────────────────────────────────────
function line(key, value, style = '') {
  let cls = 'result-value';
  if (style === 'hex') cls = 'result-value result-hex';
  if (style === 'success') cls = 'result-value result-success';
  if (style === 'fail') cls = 'result-value result-fail';
  return `<div class="result-line">
    <span class="result-key">${key}</span>
    <span class="${cls}">${value}</span>
  </div>`;
}

// ─── Init ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', loadConfig);
</script>
</body>
</html>
"""
