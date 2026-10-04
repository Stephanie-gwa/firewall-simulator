#!/usr/bin/env python3
"""
run.py — start the firewall simulator dashboard.

    python run.py

Environment variables:
    HOST     default 127.0.0.1
    PORT     default 5050
    DB_PATH  default firewall_sim.db (created in the current directory)
"""
from firewall_sim.webapp import create_app
import os

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5050"))
    db_path = os.environ.get("DB_PATH", "firewall_sim.db")
    app = create_app(db_path)
    print(f"Firewall simulator dashboard running at http://{host}:{port}")
    print("Simulation only — no real firewall or network configuration is touched.")
    app.run(host=host, port=port, debug=False)
