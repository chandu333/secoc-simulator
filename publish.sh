#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  SecOC Simulator — GitHub Publish Script
#  Repository: https://github.com/chandu333/secoc-simulator
# ═══════════════════════════════════════════════════════════════

set -e

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🔐 SecOC Simulator — Publishing to GitHub                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Step 1: Initialize git ─────────────────────────────────────
echo "📌 Step 1: Initializing git repository..."
git init
git branch -M main

# ─── Step 2: Add all files ──────────────────────────────────────
echo "📌 Step 2: Staging files..."
git add .
git status

# ─── Step 3: Initial commit ─────────────────────────────────────
echo "📌 Step 3: Creating initial commit..."
git commit -m "🔐 Initial release — SecOC Simulator v1.0.0

AUTOSAR Secure Onboard Communication MAC-authenticated CAN frame simulator.

Features:
- CMAC-AES128 & HMAC-SHA256 MAC generation/verification
- Freshness value management with configurable acceptance window
- Secured I-PDU construction per AUTOSAR SecOC spec
- CAN 2.0 / CAN FD frame encoding and decoding
- Attack simulator (replay, spoofing, tampering, fuzzing)
- Flask web dashboard with 9 interactive pages
- REST API with 8 JSON endpoints
- YAML-based ECU keys and PDU profile configuration
- Rich colored CLI with hex dumps
- Zero hardware dependencies"

# ─── Step 4: Add remote ─────────────────────────────────────────
echo "📌 Step 4: Adding GitHub remote..."
git remote add origin https://github.com/chandu333/secoc-simulator.git

# ─── Step 5: Push ───────────────────────────────────────────────
echo "📌 Step 5: Pushing to GitHub..."
git push -u origin main

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ✅ Published to: https://github.com/chandu333/secoc-simulator"
echo "═══════════════════════════════════════════════════════════════"
echo ""
