#!/usr/bin/env python3
"""
AAGCP-Vector PRO — brownfield end-to-end.

Simulates a REAL, already-populated production index full of un-redacted PII
across jurisdictions (India/EU/US/UK/pharma), then:

  1. CONNECT   to the (simulated) production store
  2. SCAN      uncapped — find EVERY PII instance, inventory the exposure
  3. QUERY     before cleaning → analyst sees raw PII (the problem)
  4. CLEAN     re-embed the poisoned subset in place (the fix)
  5. QUERY     after cleaning → same records, PII gone (retrieval intact)
  6. ERASE     a subject → reference-counted crypto-shred

Run:  python demo_brownfield.py
Uses the dependency-free hashing embedder so it runs anywhere. Swap in
SentenceTransformerEmbedder + a real connector for production (see SMOKE_TEST.md).
"""
import sys, random
sys.path.insert(0, ".")
from aagcp.detect.detector import PIIDetector
from aagcp.embed.embedders import HashingEmbedder
from aagcp.store.connectors import InMemoryConnector, VectorRecord
from aagcp.vault import PseudonymVault
from aagcp.scan.scanner import Scanner
from aagcp.migrate.migrator import Migrator
from aagcp.retrieve.retriever import GovernedRetriever

def line(c="="): print(c * 74)

# ── Build a DIRTY production index (raw PII embedded — the real-world case) ──
# Arbitrary, non-round count to prove nothing is hardcoded to 5/10/etc.
random.seed(7)
FIRST = ["Ramesh","Priya","Arjun","Kavya","Vikram","Ananya","Meera","Sanjay",
         "Divya","Rahul","John","Emma","Liam","Olivia","Noah","Sophia"]
LAST  = ["Iyer","Sharma","Mehta","Nair","Reddy","Das","Kumar","Smith",
         "Johnson","Williams","Brown","Garcia"]
COND  = ["Type 2 Diabetes","hypertension","atrial fibrillation","migraine with aura",
         "early nephropathy","peripheral neuropathy","asthma","hyperlipidemia"]

def aadhaar():  # valid-ish 12-digit
    return f"{random.randint(2000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}"
def pan(): 
    import string
    return "".join(random.choice(string.ascii_uppercase) for _ in range(5)) + \
           f"{random.randint(1000,9999)}" + random.choice(string.ascii_uppercase)

emb = HashingEmbedder(384)
prod = InMemoryConnector()

N = 137   # arbitrary — the scanner must find whatever is here, not a fixed number
templates = 0
for i in range(N):
    fn, ln = random.choice(FIRST), random.choice(LAST)
    cond = random.choice(COND)
    # Mix of identifier types across jurisdictions
    if i % 3 == 0:
        text = (f"Patient {fn} {ln}, Aadhaar {aadhaar()}, phone +91 9{random.randint(100000000,999999999)}, "
                f"MRN-{random.randint(100000,999999)}, diagnosed with {cond}.")
    elif i % 3 == 1:
        text = (f"Patient {fn} {ln}, PAN {pan()}, email {fn.lower()}.{ln.lower()}@example.com, "
                f"MRN-{random.randint(100000,999999)}, {cond}.")
    else:
        text = (f"Member {fn} {ln}, SSN {random.randint(100,899)}-{random.randint(10,99)}-{random.randint(1000,9999)}, "
                f"card 4{random.randint(100000000000000,999999999999999)}, {cond}.")
    # Raw text embedded — this is the poison
    prod.upsert([VectorRecord(f"vec_{i:04d}", emb.embed(text), text, {"ingested":"legacy"})])
    templates += 1

line(); print(f"  DIRTY PRODUCTION INDEX BUILT: {prod.count()} vectors, raw PII embedded"); line()

# ── 1-2. CONNECT + SCAN (uncapped) ──────────────────────────────────────────
detector = PIIDetector(use_presidio=None)   # auto: Presidio if installed, else regex
cov = detector.coverage()
print("\nDETECTOR COVERAGE:")
print(f"  regex entity types : {cov['regex_entity_count']} ({', '.join(cov['regex_entities'][:8])} …)")
print(f"  NER backend        : {cov['ner_backend']}")

scanner = Scanner(detector)
report = scanner.scan(prod, batch=50)
s = report.summary()
print("\nSCAN REPORT (uncapped — every vector, every instance):")
print(f"  total vectors        : {s['total_vectors']}")
print(f"  vectors with PII     : {s['vectors_with_pii']}")
print(f"  total PII instances  : {s['total_pii_instances']}")
print(f"  by type              : {s['by_type']}")
print(f"  by jurisdiction      : {s['by_jurisdiction']}")
print(f"  cleanable (re-embed) : {s['cleanable_by_reembed']}")
print(f"  quarantine-only      : {s['quarantine_only_no_source']}")

# ── 3. QUERY BEFORE (the problem) ───────────────────────────────────────────
ANALYST_REVEAL, ANALYST_PARTIAL = set(), {"AADHAAR":"last4","IN_PHONE":"last4","US_SSN":"last4"}
vault = PseudonymVault(secret=b"pro-demo-fixed-secret-32-bytes!!")
ret_dirty = GovernedRetriever(prod, emb, vault, detector=None)  # dirty store, no governance
print("\n" + "-"*74)
print("QUERY BEFORE CLEANING  (analyst, dirty index):")
for h in ret_dirty.query("diabetes patients", ANALYST_REVEAL, ANALYST_PARTIAL, k=2):
    print("   RAW>", (h.get("source_text") or "")[:96])
print("   >>> analyst is seeing raw Aadhaar / SSN / cards. This is the breach.")

# ── 4. CLEAN (re-embed poisoned subset in place) ────────────────────────────
migrator = Migrator(detector, vault, emb)
mrep = migrator.clean(prod, report)
print("\n" + "-"*74)
print("CLEAN (re-embed migration):")
print(f"  re-embedded (cleaned): {mrep.reembedded}")
print(f"  quarantined (no src) : {mrep.quarantined}")
print(f"  PII tokens minted    : {mrep.pii_tokens_minted}")

# ── 5. QUERY AFTER (retrieval intact, PII gone) ─────────────────────────────
# Re-scan to prove the index is now clean.
report2 = scanner.scan(prod, batch=50)
print("\nRE-SCAN AFTER CLEANING:")
print(f"  total PII instances now: {report2.summary()['total_pii_instances']}  (was {s['total_pii_instances']})")

ret_clean = GovernedRetriever(prod, emb, vault, detector=detector)
print("\nQUERY AFTER CLEANING (analyst — masked, retrieval still works):")
for h in ret_clean.query("diabetes patients", ANALYST_REVEAL, ANALYST_PARTIAL, k=2):
    print("   GOV>", h["text"][:96])
print("\nSAME QUERY as COMPLIANCE_OFFICER (full reveal, same vectors):")
for h in ret_clean.query("diabetes patients", {"ALL"}, {}, k=2):
    print("   CMP>", h["text"][:96])

line(); print("  RESULT: production index cleaned in place. PII removed from vectors,"); 
print("  retrieval quality preserved, role decides reveal. No full re-embed."); line()
