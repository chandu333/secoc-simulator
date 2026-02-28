#!/usr/bin/env python3
"""
run_dashboard.py — Launch the SecOC Simulator Web Dashboard.

Usage:
  python run_dashboard.py                  # Default: localhost:5000
  python run_dashboard.py --port 8080      # Custom port
  python run_dashboard.py --host 0.0.0.0   # Bind to all interfaces
"""

import argparse
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secoc_simulator.web_api import create_app
from secoc_simulator.config_loader import ConfigLoader


def main():
    parser = argparse.ArgumentParser(description="SecOC Simulator Web Dashboard")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--config", default=None, help="Path to config.yaml")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    # Load config
    config = None
    if args.config:
        config = ConfigLoader.load(args.config)
    else:
        try:
            config = ConfigLoader.load()
        except FileNotFoundError:
            config = ConfigLoader.get_default_config()

    app = create_app(config)

    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║           🔐  SecOC Simulator — Web Dashboard              ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    print(f"  Dashboard: http://{args.host}:{args.port}")
    print(f"  API Base:  http://{args.host}:{args.port}/api")
    print(f"  Config:    {'custom' if args.config else 'default'}")
    print()

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
