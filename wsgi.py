"""
wsgi.py — production entry point for gunicorn.

    gunicorn wsgi:app

Render (and any host with an ephemeral filesystem) will reset the
database on every restart/deploy — fine for a demo, since sample_data.py
reseeds the default rules automatically.
"""
from firewall_sim.webapp import create_app

app = create_app()
