from aagcp.detect.detector import PIIDetector
from aagcp.scan.scanner import Scanner
from aagcp.store.connectors import VectorRecord


def test_scan_records_scans_only_the_supplied_records():
    detector = PIIDetector(use_presidio=None)
    scanner = Scanner(detector)

    records = [
        VectorRecord(
            "pdf:sample:001:001:001",
            None,
            "Patient Ramesh Iyer, Aadhaar 1234 5678 9012",
            {"source": "pdf"},
        ),
        VectorRecord(
            "pdf:sample:001:001:002",
            None,
            "Routine care note with no PII.",
            {"source": "pdf"},
        ),
    ]

    report = scanner.scan_records(records)

    assert report.total_vectors == 2
    assert report.scanned_vectors == 2
    assert report.vectors_with_pii == 1
    assert report.total_pii_instances >= 1
