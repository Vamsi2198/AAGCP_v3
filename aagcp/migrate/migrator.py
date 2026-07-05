"""
Migration — clean poisoned vectors in an existing index.

You cannot redact a vector: PII is distributed across all dimensions. So the
only real fix is to REPLACE it. For each PII-bearing vector that still has its
source_text:

    1. tokenize the PII in the source (deterministic vault tokens)
    2. re-embed the masked source
    3. upsert — overwrite the poisoned vector in place with the clean one

The old vector is gone; the new one is governed (tokens resolve only via the
vault, per role). No full-corpus re-embed — only the affected subset.

If a vector has NO source_text, it cannot be re-embedded (physics, not choice)
— it is quarantined (deleted) instead, and reported as such. This is the
honest boundary you state to any brownfield customer.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional

from ..detect.detector import PIIDetector
from ..vault import PseudonymVault
from ..embed.embedders import EmbedderAdapter
from ..store.connectors import VectorStoreConnector, VectorRecord
from ..scan.scanner import ScanReport


@dataclass
class MigrationReport:
    reembedded: int = 0
    quarantined: int = 0
    pii_tokens_minted: int = 0
    reembedded_ids: List[str] = field(default_factory=list)
    quarantined_ids: List[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {"reembedded": self.reembedded, "quarantined": self.quarantined,
                "pii_tokens_minted": self.pii_tokens_minted,
                "vectors_left_dirty": 0}


class Migrator:
    def __init__(self, detector: PIIDetector, vault: PseudonymVault,
                 embedder: EmbedderAdapter):
        self.detector = detector
        self.vault = vault
        self.embedder = embedder

    # Strongest identifier wins as the identity key (Aadhaar > PAN > ... > name)
    _STRENGTH = {"AADHAAR": 0, "PAN": 1, "US_SSN": 1, "MRN": 2, "IN_PHONE": 3,
                 "EMAIL": 3, "PERSON": 5}

    def _mask(self, text: str) -> tuple[str, int]:
        """
        Mask every PII span, attributing ALL identifiers in this record to ONE
        subject identity keyed on the strongest identifier present, with the
        person name as the identity's display name. This makes erasure surgical:
        erasing the subject shreds all their identifiers (reference-counted, so
        tokens shared with another subject survive).
        """
        findings = self.detector.scan(text)
        if not findings:
            return text, 0
        # choose canonical identity for this record
        canon = min(findings, key=lambda f: self._STRENGTH.get(f.entity_type, 4))
        identity_id = f"{canon.entity_type}:{canon.value.strip().lower()}"
        display = next((f.value for f in findings if f.entity_type == "PERSON"), None)

        masked = text
        for f in sorted(findings, key=lambda x: x.start, reverse=True):
            dn = f.value if f.entity_type == "PERSON" else display
            tok = self.vault.token_for(f, identity_id=identity_id, display_name=dn)
            masked = masked[:f.start] + tok + masked[f.end:]
        return masked, len(findings)

    def clean(self, store: VectorStoreConnector, report: ScanReport,
              quarantine_when_no_source: bool = True,
              batch: int = 200) -> MigrationReport:
        mrep = MigrationReport()
        to_upsert: List[VectorRecord] = []
        to_delete: List[str] = []

        for exp in report.exposures:
            rec = store.fetch([exp.vector_id])
            if not rec:
                continue
            rec = rec[0]
            if rec.source_text:
                masked, n = self._mask(rec.source_text)
                vec = self.embedder.embed(masked)
                to_upsert.append(VectorRecord(
                    rec.id, vec, masked,
                    {**rec.metadata, "governed": True, "pii_masked": n}))
                mrep.reembedded += 1
                mrep.pii_tokens_minted += n
                mrep.reembedded_ids.append(rec.id)
                if len(to_upsert) >= batch:
                    store.upsert(to_upsert); to_upsert = []
            elif quarantine_when_no_source:
                to_delete.append(rec.id)
                mrep.quarantined += 1
                mrep.quarantined_ids.append(rec.id)

        if to_upsert:
            store.upsert(to_upsert)
        if to_delete:
            store.delete(to_delete)
        return mrep
