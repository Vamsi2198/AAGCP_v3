#!/usr/bin/env python3
"""
AAGCP-Vector PRO — deployable server (Python standard library only).

No FastAPI, no torch. Dependency footprint: numpy, pyyaml, reportlab (+ openai
only if you set OPENAI_API_KEY, + langsmith only if you set LANGSMITH_API_KEY).
That is why it deploys on the smallest free tier where torch-based apps run
out of memory.

Tracing: set LANGSMITH_API_KEY (and optionally LANGSMITH_PROJECT /
LANGSMITH_ENDPOINT) to send traces to LangSmith. Every top-level engine
operation (connect/scan/scan_last_pdf/upload_pdf/clean/erase/query, plus the
LLM answer-generation step) is wrapped in `@workflow(...)`, which becomes
`langsmith.traceable(...)` once a key is present, so each of those becomes a
root run in your LangSmith project and shows up in the "Recent LangSmith
Traces" panel — not just queries. LLM calls made through the `openai` client
during answer generation get picked up automatically by LangSmith's OpenAI
wrapper if you swap `from openai import OpenAI` for
`from langsmith.wrappers import wrap_openai` + `wrap_openai(OpenAI())`. The
custom TraceCollector/_Span machinery below is unrelated to LangSmith — it
powers the "Live Trace" panel in the UI and keeps working regardless of
which tracing backend is configured.

Simulates a connected production index (seedable, arbitrary size) so the whole
detect -> scan -> clean -> govern flow is live and clickable. Swap in a real
connector (Pinecone/Qdrant/pgvector) from aagcp.store.connectors for production
— the endpoints don't change. See SMOKE_TEST.md.
"""
from __future__ import annotations
import base64, io, json, os, random, re, string, tempfile, logging
import importlib
import itertools
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlsplit, urlunsplit, quote
from urllib.request import Request, urlopen
from dotenv import load_dotenv
from pinecone import Pinecone
from datetime import datetime

from aagcp.detect.detector import PIIDetector
from aagcp.embed.embedders import auto_embedder
from aagcp.store.connectors import PineconeConnector, VectorRecord
from aagcp.vault import PseudonymVault
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('aagcp_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
from aagcp.scan.scanner import Scanner
from aagcp.migrate.migrator import Migrator
from aagcp.retrieve.retriever import GovernedRetriever
from aagcp.report.pdf import build_audit_pdf


class TraceCollector:
    """Collect nested request-local spans so the frontend can render them."""

    def __init__(self):
        self._local = threading.local()

    def start(self):
        self._local.spans = []
        self._local.stack = []
        self._local.counter = itertools.count(1)

    def span(self, name: str, **attrs):
        if not hasattr(self._local, "counter"):
            return _NullSpan()
        return _Span(self, name, attrs)

    def collect(self) -> list[dict]:
        spans = list(getattr(self._local, "spans", []))
        spans.sort(key=lambda item: (item["start_ms"], item["id"]))
        return spans

    def _push(self, span):
        self._local.stack.append(span)

    def _pop(self, span):
        self._local.stack.pop()
        self._local.spans.append(span.to_dict())


class _NullSpan:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _Span:
    def __init__(self, collector: TraceCollector, name: str, attrs: dict):
        self.collector = collector
        self.name = name
        self.attrs = attrs
        self.id = next(collector._local.counter)
        self.parent_id = collector._local.stack[-1].id if collector._local.stack else None

    def __enter__(self):
        self.start = time.time()
        self.collector._push(self)
        return self

    def __exit__(self, exc_type, exc, tb):
        self.end = time.time()
        self.error = str(exc) if exc else None
        self.collector._pop(self)
        # Mirror to OpenTelemetry (Phoenix/Langfuse/any OTEL backend) — no-op
        # unless OTEL is installed & configured. Governance spans thus land in
        # both the in-UI trace view and the observability backend at once.
        try:
            from aagcp.govern.telemetry import emit_otel
            emit_otel(self.name, self.attrs,
                      round((self.end - self.start) * 1000, 2), self.error)
        except Exception:
            pass
        return False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "parent_id": self.parent_id,
            "name": self.name,
            "start_ms": round(self.start * 1000),
            "duration_ms": round((self.end - self.start) * 1000, 2),
            "attrs": self.attrs,
            "error": self.error,
        }


TRACE = TraceCollector()


RECORD_HEADER_PATTERNS = [
    ("hash_id", re.compile(r"(?=#\d{3,6}\s*(?:Name)?:?)")),
    ("subj_id", re.compile(r"(?=Subj\s+\d{3,6}\b)")),
    ("row_id", re.compile(r"(?=Row\s+\d{3,6}\b)")),
]
JSON_LINE_PATTERN = re.compile(r"^\s*\{.*\}\s*,?\s*$")


def looks_like_json_lines(text: str) -> bool:
    """Detect if text is JSON-lines format, handling multi-line JSON records from PDFs."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return False
    
    # Reconstruct JSON objects that span multiple lines
    # If a line doesn't start with {, it's a continuation of the previous record
    reconstructed = []
    current = ""
    for line in lines:
        if current and not line.startswith("{"):
            # Continuation of previous JSON record (split across PDF text operations)
            current += " " + line
            if line.endswith("}") or line.endswith("},"):
                reconstructed.append(current)
                current = ""
        else:
            if current:
                reconstructed.append(current)
            current = line
    if current:
        reconstructed.append(current)
    
    # Now check how many look like complete JSON
    json_like = sum(1 for line in reconstructed if JSON_LINE_PATTERN.match(line))
    is_jsonl = json_like >= max(1, len(reconstructed) // 2) if reconstructed else False
    return is_jsonl


def chunk_json_lines(text: str, doc_name: str, page_num: int):
    """Extract JSON-line records, reconstructing those split across PDF text operations."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    
    # Reconstruct JSON objects that span multiple lines
    # If a line doesn't start with {, it's a continuation of the previous record
    reconstructed = []
    current = ""
    for line in lines:
        if current and not line.startswith("{"):
            # Continuation of previous JSON record
            current += " " + line
            if line.endswith("}") or line.endswith("},"):
                reconstructed.append(current)
                current = ""
        else:
            if current:
                reconstructed.append(current)
            current = line
    if current:
        reconstructed.append(current)
    
    chunks = []
    for line in reconstructed:
        line = line.strip().rstrip(",")
        if not line or not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        record_id = obj.get("user_id") or obj.get("id")
        chunks.append({
            "doc": doc_name,
            "page": page_num,
            "chunk_type": "json_line",
            "record_id": record_id,
            "text": line,
        })
    return chunks


def chunk_by_header_pattern(text: str, doc_name: str, page_num: int):
    for pattern_name, pattern in RECORD_HEADER_PATTERNS:
        pieces = pattern.split(text)
        pieces = [piece.strip() for piece in pieces if piece.strip()]
        if len(pieces) > 1:
            chunks = []
            for piece in pieces:
                id_match = re.match(r"#?(\d{3,6})", piece)
                chunks.append({
                    "doc": doc_name,
                    "page": page_num,
                    "chunk_type": f"header:{pattern_name}",
                    "record_id": id_match.group(1) if id_match else None,
                    "text": piece,
                })
            return chunks
    return None


def chunk_table_rows(page, doc_name: str, page_num: int):
    tables = page.extract_tables()
    if not tables:
        return None
    all_chunks = []
    for t_idx, table in enumerate(tables):
        if not table or len(table) < 2:
            continue
        header = [(c or "").strip() for c in table[0]]
        for r_idx, row in enumerate(table[1:], start=1):
            row = [(c or "").strip() for c in row]
            if not any(row):
                continue
            pairs = [f"{h}: {v}" for h, v in zip(header, row) if v]
            row_text = " | ".join(pairs)
            all_chunks.append({
                "doc": doc_name,
                "page": page_num,
                "chunk_type": "table_row",
                "record_id": f"table{t_idx}_row{r_idx}",
                "text": row_text,
            })
    return all_chunks or None


def _coalesce_chunks(chunks: list[dict], max_chunks: int, page_num: int, strategy: str) -> list[dict]:
    """Reduce per-page chunk explosions by merging neighboring chunks.

    This keeps ingestion memory/CPU predictable on small instances.
    """
    if not chunks or len(chunks) <= max_chunks:
        return chunks

    step = max(1, (len(chunks) + max_chunks - 1) // max_chunks)
    merged: list[dict] = []

    for i in range(0, len(chunks), step):
        group = chunks[i:i + step]
        first = group[0]
        last = group[-1]
        first_id = first.get("record_id")
        last_id = last.get("record_id")
        if first_id and last_id and first_id != last_id:
            merged_id = f"{first_id}_{last_id}"
        else:
            merged_id = first_id or last_id

        merged.append({
            "doc": first.get("doc"),
            "page": first.get("page"),
            "chunk_type": f"{first.get('chunk_type', 'chunk')}+merged",
            "record_id": merged_id,
            "text": "\n".join([(g.get("text") or "").strip() for g in group if (g.get("text") or "").strip()]),
        })

    logger.info(
        f"[CHUNKING] Page {page_num}: {strategy} reduced {len(chunks)} -> {len(merged)} "
        f"(max_per_page={max_chunks})"
    )
    return merged


def chunk_page(page, doc_name: str, page_num: int):
    max_chunks_per_page = max(1, int(os.getenv("AAGCP_MAX_CHUNKS_PER_PAGE", "12")))
    text = page.extract_text() or ""
    if looks_like_json_lines(text):
        chunks = chunk_json_lines(text, doc_name, page_num)
        if chunks:
            chunks = _coalesce_chunks(chunks, max_chunks_per_page, page_num, "JSON-lines strategy")
            logger.info(f"[CHUNKING] Page {page_num}: JSON-lines strategy -> {len(chunks)} chunks")
            return chunks

    chunks = chunk_by_header_pattern(text, doc_name, page_num)
    if chunks:
        chunks = _coalesce_chunks(chunks, max_chunks_per_page, page_num, "Header-marker strategy")
        logger.info(f"[CHUNKING] Page {page_num}: Header-marker strategy -> {len(chunks)} chunks")
        return chunks

    chunks = chunk_table_rows(page, doc_name, page_num)
    if chunks:
        chunks = _coalesce_chunks(chunks, max_chunks_per_page, page_num, "Table-row strategy")
        logger.info(f"[CHUNKING] Page {page_num}: Table-row strategy -> {len(chunks)} chunks")
        return chunks

    if text.strip():
        logger.info(f"[CHUNKING] Page {page_num}: full_page_fallback (1 chunk, {len(text)} chars)")
        return [{
            "doc": doc_name,
            "page": page_num,
            "chunk_type": "full_page_fallback",
            "record_id": None,
            "text": text.strip(),
        }]
    return []


def chunk_pdf_bytes(data: bytes, filename: str):
    return list(iter_pdf_chunks(data, filename))


def iter_pdf_chunks(data: bytes, filename: str):
    doc_name = Path(filename).name
    import pdfplumber
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        for page_num, page in enumerate(pdf.pages, start=1):
            for chunk in chunk_page(page, doc_name, page_num):
                yield chunk

# Load environment variables from .env file
load_dotenv()


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def workflow(name=None, process_inputs=None):
    """Fallback no-op decorator. Rebound to LangSmith's `traceable` below
    once we know a valid API key / SDK is available.

    `process_inputs`, when supplied, is forwarded to `langsmith.traceable`
    once tracing is live — it lets a caller strip/redact arguments (e.g. raw
    PDF bytes) before they're sent to LangSmith as run inputs. It is a no-op
    while tracing is disabled."""
    def decorator(func):
        return func
    return decorator


def _init_langsmith() -> bool:
    """Initialize LangSmith tracing. LangSmith's SDK reads its config from
    the LANGCHAIN_*/LANGSMITH_* env vars, so init here just means: confirm
    the SDK is installed, confirm we have an API key, and normalize env vars
    (LANGSMITH_* -> LANGCHAIN_*) so the SDK picks them up regardless of which
    convention was used to set them."""
    try:
        importlib.import_module("langsmith")
    except ImportError:
        logger.info("[TRACING] langsmith not installed; LangSmith tracing disabled")
        return False

    api_key = os.getenv("LANGSMITH_API_KEY") or os.getenv("LANGCHAIN_API_KEY")
    if not api_key:
        logger.info("[TRACING] No LANGSMITH_API_KEY/LANGCHAIN_API_KEY set; LangSmith tracing disabled")
        return False

    # LangSmith's SDK looks for the LANGCHAIN_* names by default.
    os.environ.setdefault("LANGCHAIN_API_KEY", api_key)
    os.environ["LANGCHAIN_TRACING_V2"] = "true"
    os.environ.setdefault(
        "LANGCHAIN_PROJECT",
        os.getenv("LANGSMITH_PROJECT", os.getenv("OTEL_SERVICE_NAME", "aagcp-vector-pro")),
    )
    endpoint = os.getenv("LANGSMITH_ENDPOINT") or os.getenv("LANGCHAIN_ENDPOINT")
    if endpoint:
        os.environ["LANGCHAIN_ENDPOINT"] = endpoint

    global workflow
    try:
        langsmith_module = importlib.import_module("langsmith")
        _traceable = langsmith_module.traceable

        def workflow(name=None, process_inputs=None):
            def decorator(func):
                kwargs = {"name": name or func.__name__}
                if process_inputs is not None:
                    kwargs["process_inputs"] = process_inputs
                return _traceable(**kwargs)(func)
            return decorator
    except Exception as exc:
        logger.warning(f"[TRACING] Could not bind langsmith.traceable; falling back to no-op: {type(exc).__name__}: {exc}")

    logger.info(f"[TRACING] LangSmith initialized (project={os.environ.get('LANGCHAIN_PROJECT')})")
    return True


def _tracing_exporter_name() -> str | None:
    return "langsmith" if LANGSMITH_ENABLED else None


def _current_trace_info() -> dict:
    info = {
        "enabled": LANGSMITH_ENABLED,
        "exporter": _tracing_exporter_name(),
        "trace_id": None,
        "run_id": None,
        "url": None,
    }
    if not LANGSMITH_ENABLED:
        return info

    try:
        run_helpers = importlib.import_module("langsmith.run_helpers")
        run_tree = run_helpers.get_current_run_tree()
        if run_tree is not None:
            trace_id = getattr(run_tree, "trace_id", None)
            run_id = getattr(run_tree, "id", None)
            info["trace_id"] = str(trace_id) if trace_id else None
            info["run_id"] = str(run_id) if run_id else None
            try:
                info["url"] = run_tree.get_url()
            except Exception:
                pass
    except Exception as exc:
        logger.debug(f"[TRACING] Could not read current LangSmith run tree: {type(exc).__name__}: {exc}")
    return info


LANGSMITH_ENABLED = _init_langsmith()

_LANGSMITH_CLIENT = None


def _langsmith_client():
    """Lazily create (and cache) a langsmith.Client for read calls like
    list_runs(). Returns None if tracing isn't configured or the client
    can't be constructed."""
    global _LANGSMITH_CLIENT
    if not LANGSMITH_ENABLED:
        return None
    if _LANGSMITH_CLIENT is not None:
        return _LANGSMITH_CLIENT
    try:
        langsmith_module = importlib.import_module("langsmith")
        _LANGSMITH_CLIENT = langsmith_module.Client()
        return _LANGSMITH_CLIENT
    except Exception as exc:
        logger.warning(f"[TRACING] Could not create LangSmith client: {type(exc).__name__}: {exc}")
        return None


def list_recent_traces(limit: int = 25) -> dict:
    """Pull the most recent root runs (i.e. top-level traces — one per
    /query, /connect, /scan, /scan_last_pdf, /upload_pdf, /clean, or /erase
    call) for the configured project, for display in the frontend's trace
    list. Read-only — does not affect tracing itself."""
    project = os.environ.get("LANGCHAIN_PROJECT", "aagcp-vector-pro")
    result = {"enabled": LANGSMITH_ENABLED, "project": project, "traces": []}
    if not LANGSMITH_ENABLED:
        return result

    client = _langsmith_client()
    if client is None:
        result["error"] = "LangSmith client unavailable"
        return result

    try:
        runs = list(client.list_runs(project_name=project, is_root=True, limit=limit))
        traces = []
        for run in runs:
            try:
                url = client.get_run_url(run=run)
            except Exception:
                url = None
            start = getattr(run, "start_time", None)
            end = getattr(run, "end_time", None)
            latency_ms = None
            if start and end:
                try:
                    latency_ms = round((end - start).total_seconds() * 1000, 2)
                except Exception:
                    latency_ms = None
            if getattr(run, "error", None):
                status = "error"
            elif end is None:
                status = "running"
            else:
                status = "success"

            inputs = getattr(run, "inputs", None) or {}
            outputs = getattr(run, "outputs", None) or {}
            if not isinstance(inputs, dict):
                inputs = {}
            if not isinstance(outputs, dict):
                outputs = {}

            def _trim(value, max_len=140):
                if value is None:
                    return None
                text = str(value).strip()
                return (text[:max_len] + "…") if len(text) > max_len else text

            # Non-query runs (connect/scan/upload/clean/wipe/erase) don't have
            # a query/answer pair, so build a short generic summary from
            # whatever's in outputs (falling back to inputs) so the trace list
            # still shows something useful for them.
            summary = None
            if not outputs.get("answer"):
                payload = {k: v for k, v in outputs.items() if k != "self"} or \
                          {k: v for k, v in inputs.items() if k not in ("self", "content_b64")}
                try:
                    summary = _trim(json.dumps(payload, default=str), 160)
                except Exception:
                    summary = _trim(str(payload), 160)

            traces.append({
                "id": str(getattr(run, "id", "") or ""),
                "name": getattr(run, "name", None),
                "run_type": getattr(run, "run_type", None),
                "status": status,
                "error": _trim(getattr(run, "error", None), 200),
                "start_time": start.isoformat() if start else None,
                "latency_ms": latency_ms,
                "url": url,
                "role": inputs.get("role"),
                "query": _trim(inputs.get("query_text") or inputs.get("query")),
                "answer": _trim(outputs.get("answer")),
                "governed": outputs.get("governed"),
                "summary": summary,
            })
        traces.sort(key=lambda t: t["start_time"] or "", reverse=True)
        result["traces"] = traces
    except Exception as exc:
        logger.warning(f"[TRACING] Failed to list LangSmith runs: {type(exc).__name__}: {exc}")
        result["error"] = str(exc)
    return result


def _phoenix_ui_url() -> str | None:
    """Resolve the Phoenix UI base URL.

    Preference:
    1) PHOENIX_UI_URL (explicit override)
    2) OTEL exporter endpoint host derived from
       OTEL_EXPORTER_OTLP_TRACES_ENDPOINT / OTEL_EXPORTER_OTLP_ENDPOINT
    """
    explicit = (os.getenv("PHOENIX_UI_URL") or "").strip().strip("\"'")
    if explicit:
        return explicit.rstrip("/")

    endpoint = (
        os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        or ""
    ).strip().strip("\"'")
    if not endpoint:
        return None

    parts = urlsplit(endpoint)
    if not parts.scheme or not parts.netloc:
        return None
    return urlunsplit((parts.scheme, parts.netloc, "", "", "")).rstrip("/")


def trace_target_info() -> dict:
    """Return which trace backend UI should be shown in the frontend."""
    phoenix_url = _phoenix_ui_url()
    if phoenix_url:
        return {"provider": "phoenix", "url": phoenix_url}

    if LANGSMITH_ENABLED:
        return {
            "provider": "langsmith",
            "project": os.environ.get("LANGCHAIN_PROJECT", "aagcp-vector-pro"),
        }

    return {"provider": "none"}


def _parse_iso_utc(ts: str | None):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _http_get_json(url: str, timeout: float = 12.0) -> dict:
    req = Request(url, headers={"Accept": "application/json"})
    with urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    return json.loads(body)


def _phoenix_spans_for_traces(base: str, project: str, trace_ids: list[str]) -> dict[str, list[dict]]:
    """Fetch spans for many traces with batched requests.

    Phoenix supports repeated trace_id query params; using this avoids one request
    per trace (N+1 problem) and keeps UI refresh fast.
    """
    clean_ids = [tid for tid in trace_ids if tid]
    if not clean_ids:
        return {}

    grouped: dict[str, list[dict]] = {tid: [] for tid in clean_ids}
    project_q = quote(project, safe="")

    # Conservative chunk to avoid very long URLs while still minimizing calls.
    chunk_size = 20
    for i in range(0, len(clean_ids), chunk_size):
        chunk = clean_ids[i:i + chunk_size]
        trace_qs = "&".join([f"trace_id={quote(tid, safe='')}" for tid in chunk])
        url = f"{base}/v1/projects/{project_q}/spans?limit=1000&{trace_qs}"
        payload = _http_get_json(url, timeout=6.0)
        spans = payload.get("data") or []

        for span in spans:
            context = span.get("context") or {}
            tid = context.get("trace_id")
            if tid in grouped:
                grouped[tid].append(span)

    return grouped


def _aagcp_attrs_from_span(span: dict) -> dict:
    attrs = span.get("attributes") or {}
    if not isinstance(attrs, dict):
        return {}

    nested = attrs.get("aagcp")
    if isinstance(nested, dict):
        return nested

    # Some exporters flatten nested objects as aagcp.xxx keys.
    flat = {}
    for key, value in attrs.items():
        if isinstance(key, str) and key.startswith("aagcp."):
            flat[key.split(".", 1)[1]] = value
    return flat


def _trace_summary_from_spans(spans: list[dict]) -> str:
    """Build UI-friendly summary from span names + governance attributes."""
    if not spans:
        return "no spans"

    aagcp = {}
    for sp in spans:
        aagcp = _aagcp_attrs_from_span(sp)
        if aagcp:
            break

    parts = []
    op = aagcp.get("op")
    if op:
        parts.append(f"op={op}")

    pii_instances = aagcp.get("pii_instances")
    if pii_instances is not None:
        parts.append(f"pii={pii_instances}")

    detector = aagcp.get("detector")
    if detector:
        parts.append(f"detector={detector}")

    jurisdictions = aagcp.get("jurisdictions")
    if jurisdictions:
        parts.append(f"jurisdictions={jurisdictions}")

    pii_types = aagcp.get("pii_types")
    if pii_types:
        text = pii_types if isinstance(pii_types, str) else ",".join([str(x) for x in pii_types])
        parts.append(f"types={text[:90]}")

    # If no governance attrs exist on spans, show concise operation names.
    if not parts:
        names = []
        for sp in spans:
            nm = (sp.get("name") or "").strip()
            if nm and nm not in names:
                names.append(nm)
            if len(names) >= 4:
                break
        if names:
            parts.append("ops=" + ", ".join(names))

    parts.append(f"spans={len(spans)}")
    return " · ".join(parts)


def list_phoenix_traces(limit: int = 25, project: str = "default") -> dict:
    """Fetch traces directly from Phoenix REST API and normalize for the frontend."""
    base = _phoenix_ui_url()
    if not base:
        return {"enabled": False, "project": project, "traces": [], "error": "Phoenix URL not configured"}

    project_q = quote(project, safe="")
    url = (
        f"{base}/v1/projects/{project_q}/traces"
        f"?sort=start_time&order=desc&limit={max(1, min(limit, 200))}&include_spans=true"
    )

    try:
        payload = _http_get_json(url)
        items = payload.get("data") or []
        traces = []
        trace_ids = [it.get("trace_id") for it in items if it.get("trace_id")]

        # One batched enrichment fetch instead of one request per trace.
        try:
            enriched_spans_by_trace = _phoenix_spans_for_traces(base, project, trace_ids)
        except Exception:
            enriched_spans_by_trace = {}

        for item in items:
            start = item.get("start_time")
            end = item.get("end_time")
            start_dt = _parse_iso_utc(start)
            end_dt = _parse_iso_utc(end)
            latency_ms = None
            if start_dt and end_dt:
                try:
                    latency_ms = round((end_dt - start_dt).total_seconds() * 1000, 2)
                except Exception:
                    latency_ms = None

            spans = item.get("spans") or []
            trace_id = item.get("trace_id") or ""
            spans_for_ui = enriched_spans_by_trace.get(trace_id) or spans

            status = "success"
            if any((s.get("status_code") or "").upper() == "ERROR" for s in spans_for_ui):
                status = "error"

            root = None
            for s in spans_for_ui:
                if s.get("parent_id") in (None, "", "null"):
                    root = s
                    break
            name = (root or {}).get("name") or "trace"

            traces.append({
                "id": item.get("id") or item.get("trace_id") or "",
                "name": name,
                "run_type": "trace",
                "status": status,
                "error": None,
                "start_time": start,
                "latency_ms": latency_ms,
                "url": f"{base}/projects/{project_q}/spans?traceId={trace_id}",
                "role": None,
                "query": None,
                "answer": None,
                "governed": None,
                "summary": _trace_summary_from_spans(spans_for_ui),
            })

        return {
            "enabled": True,
            "provider": "phoenix",
            "project": project,
            "ui_url": base,
            "traces": traces,
        }
    except Exception as exc:
        return {
            "enabled": True,
            "provider": "phoenix",
            "project": project,
            "ui_url": base,
            "traces": [],
            "error": f"Phoenix API failed: {type(exc).__name__}: {exc}",
        }


ROOT = Path(__file__).parent
VAULT_STATE_FILE = ROOT / ".aagcp_vault_state.json"
SECRET = os.getenv("VAULT_SECRET", b"aagcp-vector-pro-demo-secret32b!").encode() if isinstance(os.getenv("VAULT_SECRET", ""), str) else os.getenv("VAULT_SECRET", b"aagcp-vector-pro-demo-secret32b!")
ANALYST_PARTIAL = {"AADHAAR": "last4", "IN_PHONE": "last4", "US_SSN": "last4",
                   "CREDIT_CARD": "last4", "US_PHONE": "last4"}

SAFE_METADATA_KEYS = {
    "chunk", "chunk_type", "doc", "governed", "ingested", "page",
    "pdf_filename", "record_id", "source", "pii_masked"
}

DEFAULT_CHAT_MODEL = os.getenv("OPENAI_CHAT_MODEL", "gpt-4o-mini")

FIRST = ["Ramesh","Priya","Arjun","Kavya","Vikram","Ananya","Meera","Sanjay",
         "Divya","Rahul","John","Emma","Liam","Olivia","Noah","Sophia","Aditya","Neha"]
LAST = ["Iyer","Sharma","Mehta","Nair","Reddy","Das","Kumar","Smith","Johnson",
        "Williams","Brown","Garcia","Patel","Rao","Bose"]
COND = ["Type 2 Diabetes","hypertension","atrial fibrillation","migraine with aura",
        "early nephropathy","peripheral neuropathy","asthma","hyperlipidemia"]


# Verhoeff check-digit generator so seeded Aadhaars are VALID and get detected
_VD = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
       [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
       [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
       [9,8,7,6,5,4,3,2,1,0]]
_VP = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
       [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
       [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_VINV = [0,4,3,2,1,5,6,7,8,9]

def _aadhaar():
    body = [random.randint(0,9) for _ in range(11)]
    c = 0
    for i, item in enumerate(reversed(body)):
        c = _VD[c][_VP[(i+1) % 8][item]]
    digits = body + [_VINV[c]]
    s = "".join(map(str, digits))
    return f"{s[0:4]} {s[4:8]} {s[8:12]}"

def _pan():
    return ("".join(random.choice(string.ascii_uppercase) for _ in range(5))
            + f"{random.randint(1000,9999)}" + random.choice(string.ascii_uppercase))


def _chunk_text(text: str, max_chars: int = 1200) -> list[str]:
    if len(text) <= max_chars:
        return [text]
    words = text.split()
    chunks = []
    cur = []
    cur_len = 0
    for w in words:
        if cur_len + len(w) + (1 if cur else 0) > max_chars:
            chunks.append(" ".join(cur))
            cur = [w]
            cur_len = len(w)
        else:
            cur.append(w)
            cur_len += len(w) + (1 if cur_len else 0)
    if cur:
        chunks.append(" ".join(cur))
    return chunks


def _safe_id_component(s: str) -> str:
    """Make a string safe for use in a Pinecone vector ID."""
    s = re.sub(r'\s+', '_', s.strip())
    s = re.sub(r'[^A-Za-z0-9_\-]', '', s)
    return s or "file"


def _sanitize_metadata_for_role(metadata: dict, role: str) -> dict:
    if role == "ANALYST_ROLE":
        return {}
    if role == "FINANCE":
        return {
            key: value for key, value in (metadata or {}).items()
            if key in SAFE_METADATA_KEYS and key not in {"source_text", "text"}
        }
    return dict(metadata or {})


def _fallback_answer(results: list[dict], role: str) -> str:
    if not results:
        return ""
    for item in results:
        candidate = (item.get("text") or item.get("source_text") or "").strip()
        if candidate:
            return candidate[:220]
    # Analyst role intentionally sees withheld chunks.
    return "[hidden]" if role == "ANALYST_ROLE" else ""


def _build_llm_context(results: list[dict], max_chunks: int = 5, max_chars: int = 4000) -> str:
    parts = []
    total = 0
    for idx, item in enumerate(results[:max_chunks], start=1):
        chunk_text = (item.get("text") or item.get("source_text") or "").strip()
        if not chunk_text:
            continue
        block = f"Chunk {idx} | id={item.get('id', '')} | score={item.get('score', 0)}\n{chunk_text}"
        if total + len(block) > max_chars:
            remaining = max_chars - total
            if remaining <= 0:
                break
            block = block[:remaining]
        parts.append(block)
        total += len(block)
        if total >= max_chars:
            break
    return "\n\n".join(parts)


def _drop_pdf_bytes(inputs: dict) -> dict:
    """process_inputs hook for the upload_pdf trace: keep filename/metadata,
    drop the raw base64 PDF bytes (and the bound `self`) so the document
    contents never get logged into LangSmith."""
    return {k: v for k, v in inputs.items() if k not in ("content_b64", "self")}


@workflow(name="governed_answer_generation")
def _generate_answer(query_text: str, role: str, governed: bool, results: list[dict]) -> tuple[str, str, str | None]:
    fallback = _fallback_answer(results, role)

    # Analyst role should never receive synthesized content from hidden chunks.
    if role == "ANALYST_ROLE":
        return (fallback or "[hidden]"), "policy_hidden", None

    context = _build_llm_context(results)
    if not context:
        return fallback, "top_chunk", None

    if not os.getenv("OPENAI_API_KEY"):
        return fallback, "top_chunk", None

    try:
        from openai import OpenAI

        client = OpenAI()
        with TRACE.span("openai_chat_completion", model=DEFAULT_CHAT_MODEL):
            response = client.chat.completions.create(
                model=DEFAULT_CHAT_MODEL,
                temperature=0,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "Answer the user using only the supplied retrieved chunks. "
                            "Do not use outside knowledge. If the chunks do not contain "
                            "enough information, say so briefly. Preserve governance: do "
                            "not infer or reveal anything beyond the provided context."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f"Role: {role}\n"
                            f"Governed retrieval active: {governed}\n"
                            f"Question: {query_text}\n\n"
                            f"Retrieved chunks:\n{context}\n\n"
                            "Write a concise answer grounded only in the chunks above."
                        ),
                    },
                ],
            )
        answer = (response.choices[0].message.content or "").strip()
        if answer:
            return answer, "llm", DEFAULT_CHAT_MODEL
    except Exception as exc:
        logger.warning(f"[QUERY] LLM answer generation failed: {type(exc).__name__}: {exc}")

    return fallback, "top_chunk", None


class Engine:
    def __init__(self):
        logger.info("[ENGINE] Initializing Engine...")
        self.embedder = auto_embedder(384)
        logger.info(f"[ENGINE] Embedder initialized: {self.embedder.name} (dim={self.embedder.dim})")
        
        self.detector = PIIDetector(use_presidio=None)
        logger.info(f"[ENGINE] Detector initialized, coverage: {self.detector.coverage()}")
        
        self._tmp = Path(tempfile.mkdtemp(prefix="aagcp_"))
        logger.info(f"[ENGINE] Temp directory: {self._tmp}")
        
        # Initialize Pinecone connection
        logger.info("[ENGINE] Connecting to Pinecone...")
        pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))
        index_name = os.getenv("PINECONE_INDEX", "ragpii-384")
        self._pinecone_index = pc.Index(name=index_name)
        logger.info(f"[ENGINE] Connected to Pinecone index: {index_name}")

        # Initialize the connector so the server can inspect the index without
        # immediately seeding it. Use /connect to populate the index only when
        # desired.
        self.store = PineconeConnector(self._pinecone_index)
        self.vault = PseudonymVault(path=str(VAULT_STATE_FILE), secret=SECRET)
        self.scanner = Scanner(self.detector)
        self._cleaned = False
        self.last_report = None
        self.last_uploaded_ids: list[str] = []
        self.last_uploaded_pdf_filename: str | None = None
        self._upload_jobs: dict[str, dict] = {}
        self._upload_jobs_lock = threading.Lock()

    def _set_upload_job(self, job_id: str, **fields):
        with self._upload_jobs_lock:
            cur = self._upload_jobs.get(job_id, {})
            cur.update(fields)
            self._upload_jobs[job_id] = cur

    @workflow(name="connect_index")
    def reset(self, seed: int = 1) -> dict:
        logger.info(f"[RESET] Resetting engine with seed={seed}")
        random.seed(7)
        self.store = PineconeConnector(self._pinecone_index)
        logger.info(f"[RESET] PineconeConnector initialized")
        
        self.vault = PseudonymVault(path=str(VAULT_STATE_FILE), secret=SECRET)
        self._cleaned = False
        self.last_report = None
        self.last_uploaded_ids = []
        self.last_uploaded_pdf_filename = None
        logger.info(f"[RESET] Vault initialized, cleaned=False")

        names = set()
        logger.info(f"[RESET] Starting to upsert {seed} vectors...")
        for i in range(1):
            fn, ln, cond = random.choice(FIRST), random.choice(LAST), random.choice(COND)
            names.add(f"{fn} {ln}")
            if i % 3 == 0:
                text = (f"Patient {fn} {ln}, Aadhaar {_aadhaar()}, phone +91 9{random.randint(100000000,999999999)}, "
                        f"MRN-{random.randint(100000,999999)}, diagnosed with {cond}.")
            elif i % 3 == 1:
                text = (f"Patient {fn} {ln}, PAN {_pan()}, email {fn.lower()}.{ln.lower()}@example.com, "
                        f"MRN-{random.randint(100000,999999)}, {cond}.")
            else:
                text = (f"Member {fn} {ln}, SSN {random.randint(100,899)}-{random.randint(10,99)}-{random.randint(1000,9999)}, "
                        f"card 4{random.randint(100000000000000,999999999999999)}, {cond}.")
            self.store.upsert([VectorRecord(f"vec_{i:04d}", self.embedder.embed(text),
                                            text, {"ingested": "legacy"})])
            if (i + 1) % 30 == 0:
                logger.info(f"[RESET] Upserted {i + 1}/{seed} vectors")
        
        logger.info(f"[RESET] Upsert complete")
        self.detector.person_lexicon = sorted(names, key=len, reverse=True)
        logger.info(f"[RESET] Person lexicon set with {len(names)} names")
        
        
        self.scanner = Scanner(self.detector)
        logger.info(f"[RESET] Scanner initialized")
        
        current_count = self.store.count()
        logger.info(f"[RESET] Complete - {current_count} vectors in index")
        if current_count:
            try:
                first_batch = next(self.store.iter_all(batch=5), [])
                if first_batch:
                    logger.info(
                        "[RESET] First Pinecone batch fetched",
                        extra={
                            "batch_size": len(first_batch),
                            "sample_ids": [r.id for r in first_batch[:5]],
                            "sample_text": [
                                (r.source_text or "")[:120] for r in first_batch[:2]
                            ],
                        }
                    )
                else:
                    logger.warning("[RESET] iter_all returned no records despite nonzero count")
            except Exception as exc:
                logger.exception("[RESET] Failed to fetch first batch from Pinecone", exc_info=exc)
        return {"success": True, "seeded": current_count,
                "embedder": self.embedder.name,
                "message": f"Connected to Pinecone index with {current_count} vectors. Embedder: {self.embedder.name}."}

    @workflow(name="scan_index")
    def scan(self) -> dict:
        logger.info("[SCAN] Starting scan operation")
        try:
            self.last_report = self.scanner.scan(self.store, batch=64)
            summary = self.last_report.summary()
            logger.info(f"[SCAN] Complete - {summary['total_vectors']} total, "
                       f"{summary['vectors_with_pii']} with PII, "
                       f"{summary['total_pii_instances']} PII instances")
            logger.info(f"[SCAN] PII by type: {summary['by_type']}")
            return summary
        except Exception as e:
            logger.error(f"[SCAN] Error: {type(e).__name__}: {e}")
            raise

    def pinecone_health(self) -> dict:
        logger.info("[HEALTH] Checking Pinecone connection and sample chunks directly from Pinecone")
        current_count = int(self._pinecone_index.describe_index_stats().get("total_vector_count", 0))
        ids = []
        namespace = self._pinecone_index.namespace if hasattr(self._pinecone_index, 'namespace') else os.getenv('PINECONE_NAMESPACE', '')
        try:
            list_gen = self._pinecone_index.list(namespace=namespace if namespace else None)
            for list_response in list_gen:
                if hasattr(list_response, 'vectors') and list_response.vectors:
                    for item in list_response.vectors:
                        if hasattr(item, 'id'):
                            ids.append(item.id)
                        elif isinstance(item, dict) and 'id' in item:
                            ids.append(item['id'])
                elif isinstance(list_response, dict) and list_response.get('vectors'):
                    for item in list_response.get('vectors'):
                        if isinstance(item, dict) and 'id' in item:
                            ids.append(item['id'])
        except Exception as exc:
            logger.exception("[HEALTH] Pinecone list() failed", exc_info=exc)
            return {"ok": False, "error": str(exc), "top_chunks": []}

        chunks = []
        for i in range(0, len(ids), 10):
            batch_ids = ids[i:i + 10]
            try:
                fetched = self._pinecone_index.fetch(ids=batch_ids, namespace=namespace if namespace else None)
                payload = None
                if hasattr(fetched, 'to_dict'):
                    payload = fetched.to_dict()
                elif isinstance(fetched, dict):
                    payload = fetched

                vectors = None
                if hasattr(fetched, 'vectors'):
                    vectors = fetched.vectors
                elif isinstance(payload, dict):
                    vectors = payload.get('vectors')

                if isinstance(vectors, dict):
                    for vid, item in vectors.items():
                        if len(chunks) >= 10:
                            break
                        meta = {}
                        if isinstance(item, dict):
                            meta = item.get('metadata') or item.get('meta') or {}
                        else:
                            meta = getattr(item, 'metadata', None) or getattr(item, 'meta', None) or {}
                        if hasattr(meta, 'to_dict'):
                            try:
                                meta = meta.to_dict()
                            except Exception:
                                meta = dict(meta or {})
                        chunks.append({
                            'id': vid,
                            'source_text': (meta.get('source_text') or meta.get('text') or '')[:220],
                            'metadata': meta or {}
                        })
                elif isinstance(vectors, list):
                    for rec in vectors:
                        if len(chunks) >= 10:
                            break
                        vid = None
                        meta = {}
                        if isinstance(rec, dict):
                            vid = rec.get('id')
                            meta = rec.get('metadata') or rec.get('meta') or {}
                        else:
                            vid = getattr(rec, 'id', None)
                            meta = getattr(rec, 'metadata', None) or getattr(rec, 'meta', None) or {}
                        if hasattr(meta, 'to_dict'):
                            try:
                                meta = meta.to_dict()
                            except Exception:
                                meta = dict(meta or {})
                        if vid is not None:
                            chunks.append({
                                'id': vid,
                                'source_text': (meta.get('source_text') or meta.get('text') or '')[:220],
                                'metadata': meta or {}
                            })
                if len(chunks) >= 10:
                    break
            except Exception as exc:
                logger.exception("[HEALTH] Pinecone fetch() failed", exc_info=exc)
                break

        return {"ok": True, "count": current_count, "top_chunks": chunks}

    @workflow(name="upload_pdf", process_inputs=_drop_pdf_bytes)
    def upload_pdf(self, filename: str, content_b64: str) -> dict:
        # Large PDF ingestion can exceed PaaS request timeouts. Start a
        # background job and let the client poll for completion.
        job_id = uuid.uuid4().hex
        with self._upload_jobs_lock:
            self._upload_jobs[job_id] = {
                "status": "running",
                "filename": filename,
                "created_at": datetime.utcnow().isoformat() + "Z",
            }

        worker = threading.Thread(
            target=self._upload_pdf_job_worker,
            args=(job_id, filename, content_b64),
            daemon=True,
        )
        worker.start()
        return {
            "accepted": True,
            "job_id": job_id,
            "status": "running",
            "message": f"Upload started for {filename}. Poll /upload_status?job_id={job_id}",
        }

    def upload_status(self, job_id: str) -> dict:
        with self._upload_jobs_lock:
            job = self._upload_jobs.get(job_id)
            if not job:
                return {"found": False, "status": "not_found", "job_id": job_id}
            return {"found": True, "job_id": job_id, **job}

    def _upload_pdf_job_worker(self, job_id: str, filename: str, content_b64: str):
        try:
            result = self._upload_pdf_impl(filename, content_b64, job_id=job_id)
            with self._upload_jobs_lock:
                self._upload_jobs[job_id] = {
                    "status": "done",
                    "filename": filename,
                    "finished_at": datetime.utcnow().isoformat() + "Z",
                    "result": result,
                }
        except Exception as exc:
            logger.error(f"[UPLOAD_JOB] job={job_id} failed: {type(exc).__name__}: {exc}", exc_info=True)
            with self._upload_jobs_lock:
                self._upload_jobs[job_id] = {
                    "status": "error",
                    "filename": filename,
                    "finished_at": datetime.utcnow().isoformat() + "Z",
                    "error": f"{type(exc).__name__}: {exc}",
                }

    def _upload_pdf_impl(self, filename: str, content_b64: str, job_id: str | None = None) -> dict:
        logger.info(f"[UPLOAD] Ingesting PDF file: {filename}")
        try:
            if job_id:
                self._set_upload_job(job_id, message="Decoding PDF payload…", phase="decode")
            data = base64.b64decode(content_b64)

            if job_id:
                self._set_upload_job(job_id, message="Extracting and chunking PDF text…", phase="chunk")

            safe_stem = _safe_id_component(Path(filename).stem)
            embed_batch_size = max(1, int(os.getenv("AAGCP_EMBED_BATCH", "8")))
            upsert_batch_size = max(1, int(os.getenv("AAGCP_UPSERT_BATCH", "25")))
            max_upload_chunks = max(1, int(os.getenv("AAGCP_MAX_UPLOAD_CHUNKS", "1200")))
            logger.info(
                f"[UPLOAD] Batch config: embed_batch_size={embed_batch_size}, "
                f"upsert_batch_size={upsert_batch_size}, "
                f"max_upload_chunks={max_upload_chunks}"
            )

            if job_id:
                self._set_upload_job(
                    job_id,
                    message="Preparing chunks for embedding…",
                    phase="prepare",
                    embedded=0,
                    upserted=0,
                )

            staged = []
            new_ids = []
            seen_chunks = 0
            embedded_count = 0
            upserted_count = 0
            record_seq = 0

            def flush_staged_batches():
                nonlocal staged, embedded_count, upserted_count
                if not staged:
                    return

                texts = [t for _, t, _ in staged]
                embeddings = self.embedder.embed_batch(texts)
                embedded_count += len(staged)

                vectors = []
                for (record_id, text, metadata), emb in zip(staged, embeddings):
                    vectors.append(VectorRecord(record_id, emb, text, metadata))

                for i in range(0, len(vectors), upsert_batch_size):
                    batch = vectors[i:i + upsert_batch_size]
                    self.store.upsert(batch)
                    upserted_count += len(batch)
                    if job_id:
                        self._set_upload_job(
                            job_id,
                            phase="upsert",
                            message=f"Upserting vectors… {upserted_count}",
                            embedded=embedded_count,
                            upserted=upserted_count,
                        )

                staged = []

            for chunk_item in iter_pdf_chunks(data, filename):
                seen_chunks += 1
                if seen_chunks > max_upload_chunks:
                    raise ValueError(
                        f"Upload exceeds max chunk limit ({max_upload_chunks}). "
                        f"Reduce document size or increase AAGCP_MAX_UPLOAD_CHUNKS."
                    )
                text = (chunk_item.get("text") or "").strip()
                if not text:
                    continue

                record_seq += 1
                record_id = (f"pdf:{safe_stem}:{chunk_item.get('page', 0):03d}:"
                             f"{record_seq:03d}:{chunk_item.get('chunk_type','chunk')}")
                metadata = {
                    "source": "pdf",
                    "pdf_filename": filename,
                    "page": chunk_item.get("page", 0),
                    "chunk_type": chunk_item.get("chunk_type", "full_page_fallback"),
                    "ingested": "pdf_upload"
                }
                rid = chunk_item.get("record_id")
                if rid is not None:
                    metadata["record_id"] = str(rid)
                docv = chunk_item.get("doc")
                if docv is not None:
                    metadata["doc"] = docv

                staged.append((record_id, text, metadata))
                new_ids.append(record_id)

                if job_id and seen_chunks % 25 == 0:
                    self._set_upload_job(
                        job_id,
                        phase="embed",
                        message=f"Chunked {seen_chunks} segments… embedding in batches",
                        seen_chunks=seen_chunks,
                        embedded=embedded_count,
                        upserted=upserted_count,
                    )

                if len(staged) >= embed_batch_size:
                    flush_staged_batches()

            flush_staged_batches()

            if not new_ids:
                return {"uploaded": 0, "message": "No text could be extracted from the PDF."}

            self.last_uploaded_ids = new_ids
            self.last_uploaded_pdf_filename = filename
            logger.info(f"[UPLOAD] Just upserted {len(new_ids)} ids, first 3: {new_ids[:3]}")

            logger.info(f"[UPLOAD] Inserted {len(new_ids)} PDF chunks into index")
            return {"uploaded": len(new_ids), "filename": filename,
                    "pdf_chunks": len(new_ids), "message": "PDF ingested successfully."}
        except Exception as e:
            logger.error(f"[UPLOAD] Error ingesting PDF: {type(e).__name__}: {e}")
            raise

    @workflow(name="scan_last_pdf")
    def scan_last_uploaded_pdf(self) -> dict:
        logger.info("[SCAN_LAST_PDF] Starting scan for the most recently uploaded PDF")
        if not self.last_uploaded_ids:
            return {"scanned_vectors": 0, "total_vectors": 0, "vectors_with_pii": 0,
                    "total_pii_instances": 0, "by_type": {}, "filename": None,
                    "message": "No PDF has been uploaded yet."}

        try:
            fetched_records = self.store.fetch(self.last_uploaded_ids)
            if not fetched_records:
                return {"scanned_vectors": 0, "total_vectors": 0, "vectors_with_pii": 0,
                        "total_pii_instances": 0, "by_type": {}, "filename": self.last_uploaded_pdf_filename,
                        "message": "The uploaded PDF vectors could not be fetched from the store."}

            report = self.scanner.scan_records(fetched_records)
            self.last_report = report
            summary = report.summary()
            summary["filename"] = self.last_uploaded_pdf_filename
            summary["message"] = f"Scanned {summary['scanned_vectors']} vectors from the last uploaded PDF."
            return summary
        except Exception as e:
            logger.error(f"[SCAN_LAST_PDF] Error: {type(e).__name__}: {e}")
            raise

    @workflow(name="wipe_index")
    def wipe_all(self) -> dict:
        logger.info("[WIPE] Wiping entire vector store")
        total = self.store.count()
        if total == 0:
            logger.info("[WIPE] Index already empty")
            self.last_report = None
            self._cleaned = False
            return {"deleted": 0, "message": "Index was already empty."}

        ids = []
        for batch in self.store.iter_all(batch=500):
            ids.extend([r.id for r in batch])
            if len(ids) >= 500:
                self.store.delete(ids)
                ids = []
        if ids:
            self.store.delete(ids)

        self.last_report = None
        self._cleaned = False
        logger.info(f"[WIPE] Deleted {total} vectors from index")
        return {"deleted": total, "message": f"Deleted {total} vectors from the index."}

    @workflow(name="query_request")
    def query(self, role: str, query_text: str) -> dict:
        logger.info(f"[QUERY] Starting query with role={role}")
        TRACE.start()
        try:
            with TRACE.span("query", role=role, query=query_text[:80]) as root:
                admin_roles = ("COMPLIANCE_OFFICER", "ADMIN", "DATA_STEWARD")
                is_admin = role in admin_roles
                is_finance = role == "FINANCE"
                reveal = {"ALL"} if is_admin else set()
                partial = {} if is_admin or is_finance else ANALYST_PARTIAL
                gov = self.last_report is not None and getattr(self, "_cleaned", False)

                # --- GOVERNANCE: prompt-injection scan wired into the reveal
                # decision. A risky query has its reveal downgraded or blocked,
                # and that decision is traced (op=injection_scan).
                from aagcp.govern import prompt_guard
                verdict = prompt_guard.scan(query_text)
                with TRACE.span("injection_scan", op="injection_scan",
                                injection_risk=verdict.risk, decision=verdict.decision,
                                signals=verdict.signals):
                    pass
                if verdict.decision == "block":
                    root.attrs["decision"] = "block"
                    return {"role": role, "governed": gov, "query": query_text,
                            "answer": "Request blocked: the query was flagged as a "
                                      "prompt-injection / exfiltration attempt.",
                            "answer_source": "governance_block", "llm_model": None,
                            "injection": verdict.to_attrs(),
                            "trace": _current_trace_info(), "spans": TRACE.collect(),
                            "results": []}
                if verdict.decision == "downgrade":
                    # force lowest-privilege reveal regardless of caller role
                    reveal, partial = set(), ANALYST_PARTIAL
                    root.attrs["decision"] = "downgrade_reveal"

                # --- GOVERNANCE: role transition. If the effective role differs
                # from the caller's last role this session, trace it — over-
                # privileged access is the #1 real-world PII breach vector.
                prev = getattr(self, "_last_role", None)
                if prev and prev != role:
                    with TRACE.span("role_transition", op="role_transition",
                                    from_role=prev, to_role=role,
                                    escalation=role in admin_roles and prev not in admin_roles):
                        pass
                self._last_role = role
                logger.info(f"[QUERY] Role reveal={reveal}, governed={gov}, has_report={self.last_report is not None}")

                with TRACE.span("setup_retriever", embedder=self.embedder.name, governed=gov):
                    ret = GovernedRetriever(
                        self.store,
                        self.embedder,
                        self.vault,
                        detector=self.detector if gov else None,
                    )

                with TRACE.span("vector_search", k=20, candidate_k=100, hybrid=True, dense_weight=0.45) as search_span:
                    hits = ret.query(
                        query_text,
                        reveal,
                        partial,
                        k=20,
                        hybrid=True,
                        candidate_k=100,
                        dense_weight=0.45,
                    )
                    search_span.attrs["hits"] = len(hits)
                logger.info(f"[QUERY] Retrieved {len(hits)} results")

                # withhold reason for this role, for the audit trail
                if role == "ANALYST_ROLE":
                    _reveal_mode, _reason = "tokens_only", "policy:analyst_no_reveal"
                elif is_finance:
                    _reveal_mode, _reason = "partial", "policy:finance_partial"
                elif is_admin:
                    _reveal_mode, _reason = "full", "policy:privileged_role"
                else:
                    _reveal_mode, _reason = "partial", "policy:default_partial"
                with TRACE.span("governance_filter", op="rehydrate", role=role,
                                governed=gov, reveal_mode=_reveal_mode,
                                withheld_reason=_reason,
                                downgraded=(root.attrs.get("decision") == "downgrade_reveal")):
                    results = []
                    for h in hits:
                        if role == "ANALYST_ROLE":
                            text = "[hidden]"
                            source_text = "[hidden]"
                        elif is_finance:
                            text = h.get("text") or ""
                            source_text = text
                        else:
                            text = h.get("text") or h.get("source_text") or ""
                            source_text = h.get("source_text") or text
                        results.append({
                            "id": h["id"],
                            "score": round(h.get("score", 0), 3),
                            "text": text[:220],
                            "source_text": source_text[:220],
                            "metadata": _sanitize_metadata_for_role(h.get("metadata") or {}, role)
                        })

                with TRACE.span("generate_answer") as answer_span:
                    answer, answer_source, llm_model = _generate_answer(query_text, role, gov, results)
                    answer_span.attrs["source"] = answer_source
                    if llm_model:
                        answer_span.attrs["model"] = llm_model

            trace = _current_trace_info()
            spans = TRACE.collect()
            logger.info(f"[QUERY] Complete")
            return {"role": role, "governed": gov, "query": query_text,
                    "answer": answer, "answer_source": answer_source,
                    "llm_model": llm_model, "trace": trace, "spans": spans,
                    "results": results}
        except Exception as e:
            logger.error(f"[QUERY] Error: {type(e).__name__}: {e}")
            raise

    @workflow(name="clean_index")
    def clean(self) -> dict:
        logger.info("[CLEAN] Starting clean operation")
        try:
            if not self.last_report:
                logger.info("[CLEAN] No previous report, running scan first")
                self.scan()
            
            logger.info(f"[CLEAN] Cleaning {self.last_report.total_vectors} vectors")
            pii_before = self.last_report.summary()["total_pii_instances"]
            _summ = self.last_report.summary()
            TRACE.start()
            with TRACE.span("clean_request", op="reembed"):
                with TRACE.span("pii_detect", op="detect",
                                pii_types=list(_summ.get("by_type", {}).keys()),
                                jurisdictions=list(_summ.get("by_jurisdiction", {}).keys()),
                                pii_instances=pii_before,
                                detector=self.detector.coverage().get("ner_backend", "regex")):
                    pass
                m = Migrator(self.detector, self.vault, self.embedder)
                with TRACE.span("pii_mask_reembed", op="reembed") as _ms:
                    rep = m.clean(self.store, self.last_report)
                    _ms.attrs["reembedded"] = rep.summary().get("reembedded", 0)
                    _ms.attrs["quarantined"] = rep.summary().get("quarantined", 0)
            _clean_spans = TRACE.collect()
            if self.vault.path:
                self.vault.save()
            self._cleaned = True
            
            logger.info("[CLEAN] Re-scanning after cleanup...")
            after = self.scanner.scan(self.store, batch=64)
            self.last_report = after
            
            pii_after = after.summary()["total_pii_instances"]
            logger.info(f"[CLEAN] Complete - PII before: {pii_before}, after: {pii_after}")
            
            return {**rep.summary(), "pii_before": pii_before, "pii_after": pii_after,
                    "spans": _clean_spans}
        except Exception as e:
            logger.error(f"[CLEAN] Error: {type(e).__name__}: {e}")
            raise

    @workflow(name="erase_subject")
    def erase(self, subject: str) -> dict:
        logger.info(f"[ERASE] Starting erase for subject='{subject}'")
        try:
            # Allow mixed inputs (e.g., "name + Aadhaar") by using the
            # query resolver when available.
            if hasattr(self.vault, "resolve_identities_by_query"):
                iids = self.vault.resolve_identities_by_query(subject)
            else:
                iids = self.vault.resolve_identities_by_name(subject)
            logger.info(f"[ERASE] Found {len(iids)} identity matches")
            
            if not iids:
                logger.warning(f"[ERASE] No vault identity matches '{subject}'")
                return {"executed": False, "subject": subject,
                        "message": f"No vault identity matches '{subject}' (name/identifier). "
                                   f"(Clean the index first so identities exist.)"}
            
            if len(iids) > 1:
                logger.warning(f"[ERASE] Ambiguous - {len(iids)} matches for '{subject}'")
                return {"executed": False, "subject": subject, "ambiguous": True,
                        "message": f"'{subject}' matches {len(iids)} subjects — specify an identifier."}
            
            logger.info(f"[ERASE] Shredding identity {iids[0]}...")
            TRACE.start()
            with TRACE.span("erase_request", op="erase", subject=subject):
                with TRACE.span("resolve_identity", identities=len(iids)):
                    pass
                res = self.vault.crypto_shred_identity(iids[0])
                with TRACE.span("crypto_shred", op="erase", subject=subject,
                                tokens_destroyed=len(res["tokens_destroyed"]),
                                tokens_retained=len(res["tokens_retained_shared"]),
                                method="reference_counted_crypto_shred",
                                article="GDPR Art.17 / DPDP Art.12"):
                    pass
            _erase_spans = TRACE.collect()
            logger.info(f"[ERASE] Complete - {len(res['tokens_destroyed'])} tokens destroyed, "
                       f"{len(res['tokens_retained_shared'])} retained")
            if self.vault.path:
                self.vault.save()
            
            return {"executed": True, "subject": subject,
                    "tokens_destroyed": len(res["tokens_destroyed"]),
                    "tokens_retained_shared": len(res["tokens_retained_shared"]),
                    "spans": _erase_spans,
                    "vectors_reembedded": 0, "vectors_deleted": 0,
                    "message": f"Erased '{subject}': {len(res['tokens_destroyed'])} tokens destroyed, "
                               f"{len(res['tokens_retained_shared'])} retained (shared)."}
        except Exception as e:
            logger.error(f"[ERASE] Error: {type(e).__name__}: {e}")
            raise

    def report_pdf(self) -> bytes:
        if not self.last_report:
            self.scan()
        return build_audit_pdf(self.last_report.summary(),
                               store_name="connected production index (demo)",
                               embedder_name=self.embedder.name,
                               detector_coverage=self.detector.coverage())


STATE = Engine()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    @staticmethod
    def _is_client_disconnect(exc: Exception) -> bool:
        return isinstance(exc, (BrokenPipeError, ConnectionResetError))

    def _send(self, code, payload, ctype="application/json"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, default=str).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(body)
            return True
        except Exception as exc:
            if self._is_client_disconnect(exc):
                logger.info(f"[HTTP] Client disconnected before response could be sent ({type(exc).__name__})")
                return False
            raise

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n: return {}
        try: return json.loads(self.rfile.read(n) or b"{}")
        except Exception: return {}

    def do_GET(self):
        if self.path == "/ready" or self.path == "/live":
            # Keep readiness extremely lightweight so platform health checks
            # can succeed even while background ingestion is active.
            return self._send(200, {"ok": True})
        if self.path in ("/", "/index.html"):
            return self._send(200, (ROOT / "index.html").read_bytes(), "text/html; charset=utf-8")
        if self.path == "/health":
            return self._send(200, {"ok": True, "embedder": STATE.embedder.name,
                                    "coverage": STATE.detector.coverage(),
                                    "tracing": {
                                        "enabled": LANGSMITH_ENABLED,
                                        "exporter": _tracing_exporter_name(),
                                    }})
        if self.path == "/pinecone_health":
            return self._send(200, STATE.pinecone_health())
        if self.path == "/traces" or self.path.startswith("/traces?"):
            qs = parse_qs(urlparse(self.path).query)
            try:
                limit = int(qs.get("limit", ["25"])[0])
            except ValueError:
                limit = 25
            limit = max(1, min(limit, 100))
            return self._send(200, list_recent_traces(limit))
        if self.path == "/upload_status" or self.path.startswith("/upload_status?"):
            qs = parse_qs(urlparse(self.path).query)
            job_id = (qs.get("job_id", [""])[0] or "").strip()
            if not job_id:
                return self._send(400, {"error": "job_id is required"})
            return self._send(200, STATE.upload_status(job_id))
        if self.path == "/phoenix_traces" or self.path.startswith("/phoenix_traces?"):
            qs = parse_qs(urlparse(self.path).query)
            try:
                limit = int(qs.get("limit", ["25"])[0])
            except ValueError:
                limit = 25
            project = (qs.get("project", ["default"])[0] or "default").strip()
            return self._send(200, list_phoenix_traces(limit=limit, project=project))
        if self.path == "/trace_target":
            return self._send(200, trace_target_info())
        if self.path == "/report.pdf":
            pdf = STATE.report_pdf()
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", "attachment; filename=aagcp_pii_audit.pdf")
            self.send_header("Content-Length", str(len(pdf)))
            self.end_headers()
            return self.wfile.write(pdf)
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        b = self._body()
        logger.info(f"[HTTP] POST {self.path} from {self.client_address[0]}")
        try:
            if self.path == "/connect":
                logger.info(f"[HTTP] /connect endpoint")
                return self._send(200, STATE.reset(int(b.get("size", 120))))
            if self.path == "/scan":
                logger.info(f"[HTTP] /scan endpoint")
                return self._send(200, STATE.scan())
            if self.path == "/scan_last_pdf":
                logger.info(f"[HTTP] /scan_last_pdf endpoint")
                return self._send(200, STATE.scan_last_uploaded_pdf())
            if self.path == "/query":
                role = b.get("role", "ANALYST_ROLE")
                query_text = b.get("query", "patients diagnosed with diabetes")
                logger.info(f"[HTTP] /query endpoint (role={role})")
                return self._send(200, STATE.query(role, query_text))
            if self.path == "/clean":
                logger.info(f"[HTTP] /clean endpoint")
                return self._send(200, STATE.clean())
            if self.path == "/erase":
                subject = (b.get("subject") or "").strip()
                logger.info(f"[HTTP] /erase endpoint (subject='{subject}')")
                return self._send(200, STATE.erase(subject))
            if self.path == "/upload_pdf":
                filename = b.get("filename", "uploaded.pdf")
                content = b.get("content", "")
                logger.info(f"[HTTP] /upload_pdf endpoint (filename={filename})")
                return self._send(200, STATE.upload_pdf(filename, content))
            if self.path == "/wipe":
                logger.info("[HTTP] /wipe endpoint")
                return self._send(200, STATE.wipe_all())
            logger.warning(f"[HTTP] 404 - {self.path} not found")
            return self._send(404, {"error": "not found"})
        except Exception as e:
            logger.error(f"[HTTP] 500 Error on {self.path}: {type(e).__name__}: {e}", exc_info=True)
            if self._is_client_disconnect(e):
                logger.info(f"[HTTP] Skipping error response because client already disconnected ({type(e).__name__})")
                return
            return self._send(500, {"error": type(e).__name__, "detail": str(e)})


class ResilientThreadingHTTPServer(ThreadingHTTPServer):
    # Avoid request pileups and prevent non-daemon workers from blocking
    # process lifecycle during platform-driven restarts.
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True
    request_queue_size = 128


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8002))
    logger.info(f"="*80)
    logger.info(f"AAGCP-Vector PRO SERVER STARTING")
    logger.info(f"Port: {port}")
    logger.info(f"Embedder: {STATE.embedder.name}")
    logger.info(f"PII Coverage: {STATE.detector.coverage()}")
    logger.info(f"Pinecone Index: {os.getenv('PINECONE_INDEX')}")
    logger.info(f"Vectors in index: {STATE.store.count()}")
    try:
        from aagcp.govern.telemetry import add_phoenix
        logger.info(f"[OTEL] {add_phoenix()}")
    except Exception as e:
        logger.warning(f"[OTEL] Phoenix setup skipped: {type(e).__name__}: {e}")
    logger.info(f"Log file: aagcp_server.log")
    logger.info(f"="*80)
    print(f"\n✓ AAGCP-Vector PRO on :{port}  (embedder={STATE.embedder.name})")
    print(f"✓ Log file: aagcp_server.log\n")
    ResilientThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()