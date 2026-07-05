"""
Retrieval — governed query over the (now-clean) index.

Dense similarity from the store, optionally blended with BM25 lexical scoring
for robustness on exact-token matches (deterministic tokens make this clean:
the SAME token appears in query and corpus, so lexical matching on tokens
works WITHOUT storing any raw PII — unlike naive schemes that keep originals
in metadata).

After retrieval, results are rehydrated per the caller's role. The vector DB
returns identical bytes to every role; the layer decides what is revealed.
"""

from __future__ import annotations
import re
from typing import List, Optional

from ..embed.embedders import EmbedderAdapter
from ..store.connectors import VectorStoreConnector
from ..vault import PseudonymVault


def _toks(s: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", s.lower())


class GovernedRetriever:
    def __init__(self, store: VectorStoreConnector, embedder: EmbedderAdapter,
                 vault: PseudonymVault, detector=None):
        self.store = store
        self.embedder = embedder
        self.vault = vault
        self.detector = detector          # to tokenize PII in the query itself

    def query(self, text: str, role_reveal: set, role_partial: dict,
              k: int = 5, hybrid: bool = False) -> List[dict]:
        # If the query itself contains PII, tokenize it the SAME way — so a
        # search for a specific Aadhaar maps to the same token in the corpus.
        q = text
        if self.detector:
            findings = self.detector.scan(text)
            for f in sorted(findings, key=lambda x: x.start, reverse=True):
                tok = self.vault.token_for(f)
                q = q[:f.start] + tok + q[f.end:]

        qvec = self.embedder.embed(q)
        hits = self.store.query(qvec, k=max(k * 3, k) if hybrid else k)

        if hybrid:
            qset = set(_toks(q))
            for h in hits:
                lexical = 0.0
                txt = h.get("source_text") or ""
                if txt:
                    tset = set(_toks(txt))
                    lexical = len(qset & tset) / max(len(qset), 1)
                h["score"] = 0.7 * h["score"] + 0.3 * lexical
            hits = sorted(hits, key=lambda x: -x["score"])[:k]

        for h in hits:
            h["text"] = self.vault.rehydrate(h.get("source_text") or "",
                                             role_reveal, role_partial)
        return hits
