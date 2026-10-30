"""The Ferry gateway: an OpenAI-compatible inference API behind a default-deny
policy, plus the admin API and console (assembled in gateway/app.py).

Shared process state lives in `state.GatewayState` at `app.state.ferry`.
"""
