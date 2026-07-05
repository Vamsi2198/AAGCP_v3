# Smoke Test — enabling the real backends

The engine runs today on a dependency-free hashing embedder + in-memory store
(that is what `demo_brownfield.py` proves). To connect it to a REAL production
environment, install the backend(s) you need and swap the adapter. The engine
code does not change — only the adapter you pass in.

## 1. Global NER detection (Presidio)
    pip install presidio-analyzer presidio-anonymizer
    python -m spacy download en_core_web_lg

Then detection auto-upgrades — `PIIDetector()` detects Presidio and adds
PERSON / LOCATION / ADDRESS / ORG / medical entities on top of the 26 regex
types. Verify:
    python -c "from aagcp.detect.detector import PIIDetector; \
print(PIIDetector().coverage()['ner_backend'])"     # -> presidio

## 2. Real embeddings (sentence-transformers)
    pip install sentence-transformers
    python -c "from aagcp.embed.embedders import SentenceTransformerEmbedder as E; \
e=E('all-MiniLM-L6-v2'); print(e.dim)"               # -> 384

Swap in the demo/engine:
    from aagcp.embed.embedders import SentenceTransformerEmbedder
    emb = SentenceTransformerEmbedder("all-MiniLM-L6-v2")

## 3. Connect a real vector DB

### Pinecone
    pip install pinecone-client
    from pinecone import Pinecone
    from aagcp.store.connectors import PineconeConnector
    pc = Pinecone(api_key="..."); ix = pc.Index(host="...")
    store = PineconeConnector(ix, namespace="")

### Qdrant
    pip install qdrant-client
    from qdrant_client import QdrantClient
    from aagcp.store.connectors import QdrantConnector
    store = QdrantConnector(QdrantClient(url="...", api_key="..."), "my_collection")

### Postgres + pgvector
    pip install "psycopg[binary]" pgvector
    import psycopg
    from aagcp.store.connectors import PgVectorConnector
    store = PgVectorConnector(psycopg.connect("postgresql://..."), table="documents")

## 4. Run the real pipeline
    from aagcp.detect.detector import PIIDetector
    from aagcp.vault import PseudonymVault
    from aagcp.scan.scanner import Scanner
    from aagcp.migrate.migrator import Migrator

    det = PIIDetector()                      # Presidio auto-on if installed
    scanner = Scanner(det)
    report = scanner.scan(store)             # uncapped inventory of your index
    print(report.summary())

    vault = PseudonymVault(secret=<from KMS/env>)
    Migrator(det, vault, emb).clean(store, report)   # clean poisoned subset
    print(scanner.scan(store).summary())     # re-scan: PII now 0

## IMPORTANT — source text requirement
Cleaning re-embeds from each vector's `source_text`. If your index stores the
original text in payload/metadata (most do), cleaning works. If it does NOT,
those vectors can only be quarantined (deleted) — a poisoned vector cannot be
reconstructed without its source. The scan report tells you the split
(cleanable_by_reembed vs quarantine_only) up front.
