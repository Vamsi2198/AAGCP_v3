"""
aagcp/govern/telemetry.py

Governance telemetry: a single semantic convention for every decision the
control plane makes about personal data, emitted BOTH to the in-UI request
span view AND to OpenTelemetry (so Phoenix / Langfuse / any OTEL backend can
ingest it). Turning on OTEL requires no code change here — set the env vars
(see add_phoenix() docstring) and spans flow.

Design principle: a span is emitted at every governance boundary, and the
span's attributes ARE the compliance evidence. One request => one trace whose
children read top-to-bottom as "everything that happened to personal data, and
every authorization decision made."

Semantic convention (attribute namespace `aagcp.*`):
  aagcp.op                  detect | mask | reembed | rehydrate | erase |
                            role_transition | injection_scan
  aagcp.subject             subject identity (name/id) when applicable
  aagcp.role                effective caller role
  aagcp.jurisdictions       e.g. ["IN","US","EU"]  (DPDP/HIPAA/GDPR)
  aagcp.pii_types           entity types touched
  aagcp.revealed            fields revealed to this role
  aagcp.withheld            fields withheld
  aagcp.withheld_reason     policy | partial_mask | erased_tombstone | injection
  aagcp.tokens_destroyed    (erasure) count
  aagcp.tokens_retained     (erasure, reference-counted) count
  aagcp.injection_risk      0.0–1.0
  aagcp.decision            allow | downgrade | block
"""
from __future__ import annotations
import os
from urllib.parse import urlsplit, urlunsplit
from typing import Optional

# OTEL is optional: if not installed / not configured, everything still runs.
_OTEL = False
_tracer = None
try:
    from opentelemetry import trace as _ot_trace
    _tracer = _ot_trace.get_tracer("aagcp.governance")
    _OTEL = True
except Exception:
    _OTEL = False


def otel_enabled() -> bool:
    return _OTEL and bool(os.environ.get("AAGCP_OTEL", "")) or (
        _OTEL and bool(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")))


def emit_otel(name: str, attrs: dict, duration_ms: float = 0.0, error: Optional[str] = None):
    """Fire-and-forget OTEL span mirroring an in-UI governance span."""
    if not (_OTEL and _tracer):
        return
    try:
        with _tracer.start_as_current_span(name) as sp:
            for k, v in (attrs or {}).items():
                try:
                    sp.set_attribute(f"aagcp.{k}" if not k.startswith("aagcp.") else k,
                                     v if isinstance(v, (str, int, float, bool)) else str(v))
                except Exception:
                    pass
            if error:
                sp.set_attribute("aagcp.error", str(error))
    except Exception:
        pass


def _normalize_otel_http_endpoint(raw: str) -> str:
    """Normalize an OTLP HTTP endpoint to the traces ingest path.

    Accepts either a base URL (https://host) or a full traces URL
    (https://host/v1/traces) and returns a clean traces URL.
    """
    value = (raw or "").strip().strip("\"'")
    if not value:
        return ""
    parts = urlsplit(value)
    path = (parts.path or "").rstrip("/")
    if not path:
        path = "/v1/traces"
    elif path != "/v1/traces":
        path = f"{path}/v1/traces"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _resolve_otel_endpoint() -> str:
    """Resolve exporter endpoint from standard env vars.

    Preference order:
    1) OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
    2) OTEL_EXPORTER_OTLP_ENDPOINT
    """
    traces_ep = os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    base_ep = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    endpoint = _normalize_otel_http_endpoint(traces_ep or base_ep or "")
    if endpoint:
        # Keep both vars aligned so OTEL libs and app code behave consistently.
        os.environ["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] = endpoint
        os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = endpoint
    return endpoint


def add_phoenix() -> str:
    """
    One-call Phoenix wiring. Returns a status string.

    Local self-host (open source, free, Elastic License 2.0):
        pip install arize-phoenix opentelemetry-sdk opentelemetry-exporter-otlp
        python -c "import phoenix as px; px.launch_app()"   # UI at :6006
    Then set:
        export AAGCP_OTEL=1
        export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:6006/v1/traces
    and call add_phoenix() once at server startup.
    """
    if not _OTEL:
        return "OTEL libraries not installed — pip install opentelemetry-sdk opentelemetry-exporter-otlp arize-phoenix"
    endpoint = _resolve_otel_endpoint()
    if not endpoint:
        return (
            "Set OTEL_EXPORTER_OTLP_TRACES_ENDPOINT or "
            "OTEL_EXPORTER_OTLP_ENDPOINT "
            "(e.g. http://localhost:6006/v1/traces) to export to Phoenix."
        )
    try:
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        provider = TracerProvider(resource=Resource.create({"service.name": "aagcp-vector-governance"}))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        _ot_trace.set_tracer_provider(provider)
        return f"Phoenix/OTEL export enabled -> {endpoint}"
    except Exception as e:
        return f"OTEL wiring failed: {type(e).__name__}: {e}"
