"""Offline policy simulation, NOT an authenticator or live ingestion gateway.

Authentication outcomes are test doubles. Never accept these assertions from a
collector in production. No credentials, environment access, network or storage.
"""
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "collector_trust_handoff", Path(__file__).with_name("to_soc_alerts.py"))
handoff = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(handoff)

FIELDS = {"mode", "collector_id", "credential_status", "transport_status"}
STATUSES = ("valid", "missing", "invalid", "expired", "revoked", "unavailable")
TRANSPORTS = ("verified", "invalid_certificate", "redirect", "timeout", "unavailable")


class Refused(ValueError):
    """Fixed, sanitized rejection; never interpolate untrusted input."""


class OfflineTrustSession:
    """Single-process synthetic replay rehearsal; state is lost on restart.

    Code-owned identity/scope bind test observations to one synthetic collector.
    They do not prove that an upstream Windows/AWS event is authentic.
    """

    def __init__(self):
        self._seen = set()

    def accept(self, assertion, raw):
        if (type(assertion) is not dict or set(assertion) != FIELDS or
            any(type(v) is not str for v in assertion.values()) or
            assertion["mode"] != "synthetic_offline_only"):
            raise Refused("invalid_simulation_assertion")
        if assertion["collector_id"] != "lab-collector-01":
            raise Refused("unknown_collector")
        if assertion["credential_status"] not in STATUSES:
            raise Refused("invalid_simulation_assertion")
        if assertion["credential_status"] != "valid":
            raise Refused("authentication_refused")
        if assertion["transport_status"] not in TRANSPORTS:
            raise Refused("invalid_simulation_assertion")
        if assertion["transport_status"] != "verified":
            raise Refused("transport_refused")
        # Scope is code-owned, not an allowlist supplied by the source payload.
        try:
            alerts = handoff.build(raw)
        except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
            raise Refused("source_validation_refused") from None
        if any(a["source"]["system"] not in ("windows", "aws_cloudtrail") for a in alerts):
            raise Refused("source_scope_refused")
        identities = {(a["source"]["system"], a["source"]["record_id"]) for a in alerts}
        if identities & self._seen:
            raise Refused("replay_refused")
        # Update only after the entire batch passed; failures cannot poison state.
        self._seen.update(identities)
        return {"mode": "synthetic_offline_only", "policy_result": "accepted_simulation",
                "live_collector_authenticated": False, "live_source_verified": False,
                "alerts": alerts}
