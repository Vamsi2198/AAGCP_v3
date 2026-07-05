#!/usr/bin/env python3
"""
Test script to verify the complete /scan flow with Pinecone:
1. Connect and seed data
2. Verify vectors are stored in Pinecone
3. Verify source_text is stored in metadata
4. Verify scan retrieves all vectors and detects PII
"""
import json
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment
load_dotenv()

from pinecone import Pinecone
from aagcp.store.connectors import PineconeConnector, VectorRecord
from aagcp.embed.embedders import auto_embedder
from aagcp.detect.detector import PIIDetector
from aagcp.scan.scanner import Scanner

print("=" * 80)
print("AAGCP PINECONE FLOW TEST")
print("=" * 80)

# ============================================================================
# 1. Initialize components
# ============================================================================
print("\n[1/5] Initializing components...")
embedder = auto_embedder(384)
detector = PIIDetector(use_presidio=None)
print(f"  ✓ Embedder: {embedder.name} (dim={embedder.dim})")
print(f"  ✓ Detector initialized")

# ============================================================================
# 2. Connect to Pinecone
# ============================================================================
print("\n[2/5] Connecting to Pinecone...")
pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))
index_name = os.getenv("PINECONE_INDEX", "ragpii-384")
print(f"  Connecting to index: {index_name}")
pinecone_index = pc.Index(name=index_name)

# Check index stats
stats = pinecone_index.describe_index_stats()
print(f"  Index stats: {stats}")
current_count = int(stats.get("total_vector_count", 0))
print(f"  ✓ Current vectors in index: {current_count}")

# ============================================================================
# 3. Upsert test vectors with source_text
# ============================================================================
print("\n[3/5] Upserting test vectors with source_text...")
connector = PineconeConnector(pinecone_index)

test_vectors = [
    VectorRecord(
        "test_001",
        embedder.embed("Patient John Smith, SSN 123-45-6789, diagnosed with diabetes."),
        "Patient John Smith, SSN 123-45-6789, diagnosed with diabetes.",
        {"type": "test", "ingested": "test_run"}
    ),
    VectorRecord(
        "test_002",
        embedder.embed("Member Priya Sharma, Aadhaar 1234 5678 9012, card 4111111111111111."),
        "Member Priya Sharma, Aadhaar 1234 5678 9012, card 4111111111111111.",
        {"type": "test", "ingested": "test_run"}
    ),
    VectorRecord(
        "test_003",
        embedder.embed("Email contact@example.com, phone +91 9876543210, hypertension patient."),
        "Email contact@example.com, phone +91 9876543210, hypertension patient.",
        {"type": "test", "ingested": "test_run"}
    ),
]

print(f"  Upserting {len(test_vectors)} test vectors...")
connector.upsert(test_vectors)
print(f"  ✓ Upserted successfully")

# Wait a moment for Pinecone to index
import time
time.sleep(2)

# ============================================================================
# 4. Verify vectors were stored with source_text
# ============================================================================
print("\n[4/5] Verifying vectors stored in Pinecone...")
fetched = connector.fetch(["test_001", "test_002", "test_003"])
print(f"  Fetched {len(fetched)} vectors")

for i, rec in enumerate(fetched, 1):
    has_source = bool(rec.source_text)
    has_metadata = bool(rec.metadata)
    print(f"  [{i}] ID: {rec.id}")
    print(f"      - Has source_text: {has_source}")
    if rec.source_text:
        print(f"        Text preview: {rec.source_text[:60]}...")
    print(f"      - Metadata: {rec.metadata}")

# ============================================================================
# 5. Run full scan (simulating /scan endpoint)
# ============================================================================
print("\n[5/5] Running full scan (like /scan endpoint)...")
scanner = Scanner(detector)
print(f"  Total vectors in index: {connector.count()}")

try:
    report = scanner.scan(connector, batch=64)
    summary = report.summary()
    
    print(f"\n  SCAN RESULTS:")
    print(f"  - Total vectors in index: {summary['total_vectors']}")
    print(f"  - Scanned vectors: {summary['scanned_vectors']}")
    print(f"  - Vectors with PII: {summary['vectors_with_pii']}")
    print(f"  - Total PII instances: {summary['total_pii_instances']}")
    print(f"  - By type: {summary['by_type']}")
    print(f"  - By jurisdiction: {summary['by_jurisdiction']}")
    print(f"  - Cleanable (have source): {summary['cleanable_by_reembed']}")
    print(f"  - Quarantine only (no source): {summary['quarantine_only_no_source']}")
    print(f"  - Detector coverage: {summary['detector_coverage']}")
    
    if report.exposures:
        print(f"\n  EXPOSURES FOUND:")
        for exp in report.exposures[:5]:  # Show first 5
            print(f"    - Vector {exp.vector_id}: {len(exp.findings)} findings")
            for f in exp.findings[:2]:  # Show first 2 findings
                print(f"      • {f.entity_type}: {f.value} (confidence: {f.confidence})")
    
    print(f"\n✅ SCAN COMPLETED SUCCESSFULLY")
    
except Exception as e:
    print(f"\n❌ SCAN FAILED:")
    print(f"  Error: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 80)
print("TEST COMPLETE")
print("=" * 80)
