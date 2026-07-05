# AAGCP-Vector PRO

**Connect to a production vector database, find every piece of PII already
embedded in it, and clean it in place — without breaking retrieval.**

Most enterprises don't have a clean, greenfield RAG pipeline. They have an
existing vector index, already full of un-redacted PII, with models serving
from it right now. You cannot redact a vector after the fact — PII is
distributed across every dimension. So this engine does the only thing that
actually works: **connect → scan (uncapped) → re-embed the poisoned subset in
place → keep governing forward.**

## What it does

1. **Connect** to a real vector store (Pinecone, Qdrant, pgvector, FAISS) via a
   thin adapter — or the built-in in-memory store for testing.
2. **Scan, uncapped.** Streams *every* vector, runs global PII detection on each,
   and inventories the exposure: total instances, by type, by jurisdiction,
   which vectors are affected, and which are cleanable vs quarantine-only.
   No limit — 137 vectors or 137 million, it counts what's actually there.
3. **Clean.** For each PII-bearing vector that still has its source text:
   tokenize the PII (deterministic vault tokens) → re-embed the masked text →
   upsert to overwrite the poisoned vector. Only the affected subset is
   re-embedded, not the whole corpus.
4. **Govern forward.** Query-time role-gated rehydration, reference-counted
   crypto-shred erasure (GDPR/DPDP Art. 17), rectification (Art. 16), audit.

## Global detection

Two layers behind one interface:
- **Regex layer (always on, no deps):** 26 pattern-based identifiers across
  India (Aadhaar w/ Verhoeff, PAN, Voter ID, passport, DL, GSTIN), US
  (SSN, NPI, Medicare, EIN), UK/EU (NHS, NINO, VAT, IBAN, SWIFT), financial
  (credit card w/ Luhn), and pharma/healthcare (MRN, ICD-10, NCT trial IDs),
  plus email/phone/IP/DOB. Checksum validators keep precision high.
- **NER layer (Presidio):** person names, addresses, organizations,
  nationalities, medical conditions — the entities that have no regex shape.
  Auto-enabled when `presidio-analyzer` is installed.

## Run the demo (dependency-free)

    pip install numpy pyyaml
    python demo_brownfield.py

This builds a simulated dirty production index, scans it uncapped, shows an
analyst seeing raw PII, cleans the index in place, re-scans to prove PII is
gone, and shows retrieval still working with role-gated reveal — all on the
built-in hashing embedder so it runs anywhere.

## Go to production

The demo uses a stand-in embedder + store so it runs with zero setup. For real
use, install the backend(s) you need and pass the matching adapter — the engine
code is unchanged. **See `SMOKE_TEST.md`** for exact commands to enable
Presidio, sentence-transformers, and each vector-DB connector.

### What's proven here vs. what you smoke-test
- **Proven, runs now:** the full engine logic — uncapped scan, re-embed
  migration, quarantine fallback, hybrid retrieval, role-gated rehydration,
  reference-counted erasure — on the hashing embedder + in-memory store.
- **Written against real APIs, you smoke-test:** Presidio NER, sentence-
  transformers embeddings, and the Pinecone/Qdrant/pgvector connectors — these
  need `pip install` in your environment (the build sandbox has no network).
  `SMOKE_TEST.md` has the one-line verification for each.

## The honest boundary

Cleaning re-embeds from each vector's **source text**. If your index stored the
original text (most do, in payload/metadata), cleaning works. If it didn't,
those vectors can only be quarantined — a poisoned vector cannot be
reconstructed without its source. The scan report shows the split up front, so
you know before you start.

## Architecture

```
 production vector DB  ──adapter──▶  Scanner ──▶ exposure inventory (uncapped)
   (Pinecone/Qdrant/                    │
    pgvector/FAISS)                     ▼
                                     Migrator ──▶ tokenize + re-embed + upsert
                                        │            (clean in place)
                                        ▼
   query ──▶ GovernedRetriever ──▶ role-gated rehydration
   erase ──▶ Vault (reference-counted crypto-shred)
```

Detection, embedding, and storage are all swappable adapters. The governance
logic never changes when you swap a backend — that is what makes it
plug-and-play.
"# AAGCP_v3" 
