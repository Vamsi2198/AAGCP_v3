#!/usr/bin/env python3
"""
Diagnostic script focusing on the actual scan flow issues:
1. Verify PineconeConnector.iter_all() properly batches vectors
2. Verify source_text is being retrieved from metadata
3. Check if PII detection is finding patterns in fetched vectors
"""
import os
from dotenv import load_dotenv
from pinecone import Pinecone
from aagcp.store.connectors import PineconeConnector

load_dotenv()

print("=" * 80)
print("PINECONE SCAN FLOW DIAGNOSTIC")
print("=" * 80)

# Connect
pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))
index = pc.Index(name=os.getenv("PINECONE_INDEX", "ragpii-384"))
connector = PineconeConnector(index)

print(f"\n[1] Index Stats:")
stats = index.describe_index_stats()
total = int(stats.get("total_vector_count", 0))
dim = stats.get("dimension", "unknown")
print(f"  - Total vectors: {total}")
print(f"  - Dimension: {dim}")

print(f"\n[2] Testing iter_all() with batch=64:")
batch_count = 0
total_recs = 0
sample_recs = []

for batch in connector.iter_all(batch=64):
    batch_count += 1
    total_recs += len(batch)
    
    # Show first batch details
    if batch_count == 1:
        print(f"  - Batch 1 size: {len(batch)} records")
        for i, rec in enumerate(batch[:3]):
            print(f"    [{i+1}] ID: {rec.id}")
            print(f"        Source text exists: {bool(rec.source_text)}")
            print(f"        Source text length: {len(rec.source_text or '')}")
            print(f"        Metadata keys: {list(rec.metadata.keys())}")
            sample_recs.append(rec)

print(f"  - Total batches: {batch_count}")
print(f"  - Total records from iter_all: {total_recs}")
print(f"  - Expected count from stats: {total}")

print(f"\n[3] Checking source_text in metadata:")
if sample_recs:
    for rec in sample_recs[:2]:
        print(f"  - Vector {rec.id}:")
        if rec.source_text:
            preview = (rec.source_text[:80] + "...") if len(rec.source_text) > 80 else rec.source_text
            print(f"    ✓ Has source_text: {preview}")
        else:
            print(f"    ✗ NO source_text! Metadata: {rec.metadata}")

print(f"\n[4] Testing detector on sample vectors:")
from aagcp.detect.detector import PIIDetector
detector = PIIDetector(use_presidio=None)

if sample_recs:
    for rec in sample_recs[:2]:
        if rec.source_text:
            findings = detector.scan(rec.source_text)
            print(f"  - Vector {rec.id}:")
            print(f"    Text: {(rec.source_text[:60] + '...') if len(rec.source_text) > 60 else rec.source_text}")
            print(f"    PII found: {len(findings)} instances")
            for f in findings[:2]:
                print(f"      • {f.entity_type}: '{f.value}' (confidence: {f.confidence:.2f})")

print(f"\n" + "=" * 80)
print("✅ DIAGNOSTIC COMPLETE")
print("=" * 80)
