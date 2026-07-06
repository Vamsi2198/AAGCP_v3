#!/usr/bin/env python3
"""
AAGCP-Vector PRO — deployable server (Python standard library only).

No FastAPI, no torch. Dependency footprint: numpy, pyyaml, reportlab (+ openai
only if you set OPENAI_API_KEY). That is why it deploys on the smallest free
tier where torch-based apps run out of memory.

Simulates a connected production index (seedable, arbitrary size) so the whole
detect -> scan -> clean -> govern flow is live and clickable. Swap in a real
connector (Pinecone/Qdrant/pgvector) from aagcp.store.connectors for production
— the endpoints don't change. See SMOKE_TEST.md.
"""
from __future__ import annotations
import base64, io, json, os, random, re, string, tempfile, logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from dotenv import load_dotenv
from pinecone import Pinecone
from datetime import datetime

from aagcp.detect.detector import PIIDetector
from aagcp.embed.embedders import auto_embedder
from aagcp.store.connectors import PineconeConnector, VectorRecord
from aagcp.vault import PseudonymVault

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

# Load environment variables from .env file
load_dotenv()

ROOT = Path(__file__).parent
SECRET = os.getenv("VAULT_SECRET", b"aagcp-vector-pro-demo-secret32b!").encode() if isinstance(os.getenv("VAULT_SECRET", ""), str) else os.getenv("VAULT_SECRET", b"aagcp-vector-pro-demo-secret32b!")
ANALYST_PARTIAL = {"AADHAAR": "last4", "IN_PHONE": "last4", "US_SSN": "last4",
                   "CREDIT_CARD": "last4", "US_PHONE": "last4"}

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
        self.vault = PseudonymVault(secret=SECRET)
        self.scanner = Scanner(self.detector)
        self._cleaned = False
        self.last_report = None

    def reset(self, seed: int = 120) -> dict:
        logger.info(f"[RESET] Resetting engine with seed={seed}")
        random.seed(7)
        self.store = PineconeConnector(self._pinecone_index)
        logger.info(f"[RESET] PineconeConnector initialized")
        
        self.vault = PseudonymVault(secret=SECRET)
        self._cleaned = False
        self.last_report = None
        logger.info(f"[RESET] Vault initialized, cleaned=False")

        names = set()
        logger.info(f"[RESET] Starting to upsert {seed} vectors...")
        for i in range(seed):
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

    def upload_pdf(self, filename: str, content_b64: str) -> dict:
        logger.info(f"[UPLOAD] Ingesting PDF file: {filename}")
        try:
            data = base64.b64decode(content_b64)
            import pdfplumber
            with pdfplumber.open(io.BytesIO(data)) as pdf:
                chunks = []
                for page_number, page in enumerate(pdf.pages, start=1):
                    page_text = page.extract_text() or ""
                    if not page_text.strip():
                        continue
                    paragraphs = [p.strip() for p in re.split(r"\n\s*\n+", page_text) if p.strip()]
                    for paragraph_index, paragraph in enumerate(paragraphs, start=1):
                        for chunk_index, chunk in enumerate(_chunk_text(paragraph), start=1):
                            chunks.append((page_number, paragraph_index, chunk_index, chunk))

            if not chunks:
                return {"uploaded": 0, "message": "No text could be extracted from the PDF."}

            records = []
            for page_number, paragraph_index, chunk_index, chunk in chunks:
                record_id = (f"pdf:{Path(filename).stem}:{page_number:03d}:"
                             f"{paragraph_index:03d}:{chunk_index:03d}")
                records.append(VectorRecord(
                    record_id,
                    self.embedder.embed(chunk),
                    chunk,
                    {"source": "pdf",
                     "pdf_filename": filename,
                     "page": page_number,
                     "paragraph": paragraph_index,
                     "chunk": chunk_index,
                     "ingested": "pdf_upload"}
                ))

            for i in range(0, len(records), 50):
                self.store.upsert(records[i:i+50])

            logger.info(f"[UPLOAD] Inserted {len(records)} PDF chunks into index")
            return {"uploaded": len(records), "filename": filename,
                    "pdf_chunks": len(records), "message": "PDF ingested successfully."}
        except Exception as e:
            logger.error(f"[UPLOAD] Error ingesting PDF: {type(e).__name__}: {e}")
            raise

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

    def query(self, role: str, query_text: str) -> dict:
        logger.info(f"[QUERY] Starting query with role={role}")
        try:
            admin_roles = ("COMPLIANCE_OFFICER", "ADMIN", "DATA_STEWARD")
            is_admin = role in admin_roles
            is_finance = role == "FINANCE"
            reveal = {"ALL"} if is_admin else set()
            partial = {} if is_admin or is_finance else ANALYST_PARTIAL
            gov = self.last_report is not None and getattr(self, "_cleaned", False)
            logger.info(f"[QUERY] Role reveal={reveal}, governed={gov}, has_report={self.last_report is not None}")
            
            ret = GovernedRetriever(self.store, self.embedder, self.vault,
                                    detector=self.detector if gov else None)
            hits = ret.query(query_text, reveal, partial, k=3)
            logger.info(f"[QUERY] Retrieved {len(hits)} results")

            results = []
            for h in hits:
                if role == "ANALYST_ROLE":
                    text = ""
                elif is_finance:
                    text = h.get("source_text") or ""
                else:
                    text = h.get("text") or h.get("source_text") or ""
                results.append({
                    "id": h["id"],
                    "score": round(h.get("score", 0), 3),
                    "text": text[:220],
                    "source_text": h.get("source_text") or "",
                    "metadata": h.get("metadata") or {}
                })

            answer = results[0]["text"] if results else ""
            logger.info(f"[QUERY] Complete")
            return {"role": role, "governed": gov, "query": query_text,
                    "answer": answer, "results": results}
        except Exception as e:
            logger.error(f"[QUERY] Error: {type(e).__name__}: {e}")
            raise

    def clean(self) -> dict:
        logger.info("[CLEAN] Starting clean operation")
        try:
            if not self.last_report:
                logger.info("[CLEAN] No previous report, running scan first")
                self.scan()
            
            logger.info(f"[CLEAN] Cleaning {self.last_report.total_vectors} vectors")
            pii_before = self.last_report.summary()["total_pii_instances"]
            m = Migrator(self.detector, self.vault, self.embedder)
            rep = m.clean(self.store, self.last_report)
            self._cleaned = True
            
            logger.info("[CLEAN] Re-scanning after cleanup...")
            after = self.scanner.scan(self.store, batch=64)
            self.last_report = after
            
            pii_after = after.summary()["total_pii_instances"]
            logger.info(f"[CLEAN] Complete - PII before: {pii_before}, after: {pii_after}")
            
            return {**rep.summary(), "pii_before": pii_before, "pii_after": pii_after}
        except Exception as e:
            logger.error(f"[CLEAN] Error: {type(e).__name__}: {e}")
            raise

    def erase(self, subject: str) -> dict:
        logger.info(f"[ERASE] Starting erase for subject='{subject}'")
        try:
            iids = self.vault.resolve_identities_by_name(subject)
            logger.info(f"[ERASE] Found {len(iids)} identity matches")
            
            if not iids:
                logger.warning(f"[ERASE] No vault identity matches '{subject}'")
                return {"executed": False, "subject": subject,
                        "message": f"No vault identity matches '{subject}'. "
                                   f"(Clean the index first so identities exist.)"}
            
            if len(iids) > 1:
                logger.warning(f"[ERASE] Ambiguous - {len(iids)} matches for '{subject}'")
                return {"executed": False, "subject": subject, "ambiguous": True,
                        "message": f"'{subject}' matches {len(iids)} subjects — specify an identifier."}
            
            logger.info(f"[ERASE] Shredding identity {iids[0]}...")
            res = self.vault.crypto_shred_identity(iids[0])
            logger.info(f"[ERASE] Complete - {len(res['tokens_destroyed'])} tokens destroyed, "
                       f"{len(res['tokens_retained_shared'])} retained")
            
            return {"executed": True, "subject": subject,
                    "tokens_destroyed": len(res["tokens_destroyed"]),
                    "tokens_retained_shared": len(res["tokens_retained_shared"]),
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

    def _send(self, code, payload, ctype="application/json"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n: return {}
        try: return json.loads(self.rfile.read(n) or b"{}")
        except Exception: return {}

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self._send(200, (ROOT / "index.html").read_bytes(), "text/html; charset=utf-8")
        if self.path == "/health":
            return self._send(200, {"ok": True, "embedder": STATE.embedder.name,
                                    "coverage": STATE.detector.coverage()})
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
            return self._send(500, {"error": type(e).__name__, "detail": str(e)})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8002))
    logger.info(f"="*80)
    logger.info(f"AAGCP-Vector PRO SERVER STARTING")
    logger.info(f"Port: {port}")
    logger.info(f"Embedder: {STATE.embedder.name}")
    logger.info(f"PII Coverage: {STATE.detector.coverage()}")
    logger.info(f"Pinecone Index: {os.getenv('PINECONE_INDEX')}")
    logger.info(f"Vectors in index: {STATE.store.count()}")
    logger.info(f"Log file: aagcp_server.log")
    logger.info(f"="*80)
    print(f"\n✓ AAGCP-Vector PRO on :{port}  (embedder={STATE.embedder.name})")
    print(f"✓ Log file: aagcp_server.log\n")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
