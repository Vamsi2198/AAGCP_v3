"""Deterministic pseudonym vault with reference-counted crypto-shred."""
from __future__ import annotations
import hmac, hashlib, json, secrets, re
from pathlib import Path
from typing import Dict, List, Optional, Set
from .detect.detector import Finding


class PseudonymVault:
    def __init__(self, path: Optional[str] = None, secret: Optional[bytes] = None):
        self.path = Path(path) if path else None
        self.secret = secret or secrets.token_bytes(32)
        self._store: Dict[str, dict] = {}
        self._identities: Dict[str, Set[str]] = {}
        self._idnames: Dict[str, Set[str]] = {}
        self._shredded: List[str] = []
        if self.path and self.path.exists():
            self._load()

    def token_for(self, f: Finding, identity_id: Optional[str] = None,
                  display_name: Optional[str] = None) -> str:
        digest = hmac.new(self.secret,
                          f"{f.entity_type}|{f.value.strip().lower()}".encode(),
                          hashlib.sha256).hexdigest()[:16]   # 64-bit
        token = f"<{f.entity_type}_{digest}>"
        if token in self._shredded:
            return token
        e = self._store.setdefault(token, {"type": f.entity_type,
                                           "value": f.value, "identities": set()})
        if identity_id:
            e["identities"].add(identity_id)
            self._identities.setdefault(identity_id, set()).add(token)
            if display_name:
                self._idnames.setdefault(identity_id, set()).add(display_name)
        return token

    def rehydrate(self, text: str, reveal: set, partial: Dict[str, str]) -> str:
        def sub(m):
            tok = m.group(0)
            if tok in self._shredded:
                return "[ERASED-GDPR]"
            e = self._store.get(tok)
            if not e:
                return tok
            t, v = e["type"], e["value"]
            if "ALL" in reveal or t in reveal:
                return v
            if partial.get(t) == "last4":
                return "*" * max(len(v) - 4, 2) + v[-4:]
            return tok
        return re.sub(r"<[A-Z_]+_[0-9a-f]+>", sub, text)

    def resolve_identities_by_name(self, name: str) -> List[str]:
        n = name.strip().lower()
        return [i for i, names in self._idnames.items()
                if any(n == dn.strip().lower() for dn in names)]

    def get_identity_tokens(self, identity_id: str) -> List[str]:
        return sorted(self._identities.get(identity_id, set()))

    def resolve_identities_by_query(self, text: str) -> List[str]:
        q = re.sub(r"\s+", " ", text.strip().lower())
        if not q:
            return []

        exact = []
        for iid, names in self._idnames.items():
            for dn in names:
                n = re.sub(r"\s+", " ", dn.strip().lower())
                if q == n:
                    exact.append(iid)
                    break
        if exact:
            return sorted(set(exact))

        q_tokens = set(re.findall(r"[a-z0-9]+", q))
        if not q_tokens:
            return []

        scored = []
        for iid, names in self._idnames.items():
            best_overlap = 0
            for dn in names:
                n_tokens = set(re.findall(r"[a-z0-9]+", dn.lower()))
                best_overlap = max(best_overlap, len(q_tokens & n_tokens))
            if best_overlap >= 2 or (len(q_tokens) == 1 and best_overlap == 1):
                scored.append((best_overlap, iid))

        scored.sort(key=lambda x: (-x[0], x[1]))
        return [iid for _, iid in scored]

    def crypto_shred_identity(self, iid: str) -> dict:
        tokens = self._identities.pop(iid, set())
        self._idnames.pop(iid, None)
        destroyed, retained = [], []
        for t in tokens:
            e = self._store.get(t)
            if not e:
                continue
            e["identities"].discard(iid)
            if e["identities"]:
                retained.append(t)
            else:
                del self._store[t]; self._shredded.append(t); destroyed.append(t)
        if self.path:
            self.save()
        return {"identity_id": iid, "tokens_destroyed": destroyed,
                "tokens_retained_shared": retained,
                "vectors_reembedded": 0, "vectors_deleted": 0,
                "method": "reference_counted_crypto_shred"}

    def rectify(self, entity_type: str, old_value: str, new_value: str) -> dict:
        """GDPR Art.16 — fix a value once; every document that references its
        token is corrected at rehydration. No re-embedding needed."""
        digest = hmac.new(self.secret,
                          f"{entity_type}|{old_value.strip().lower()}".encode(),
                          hashlib.sha256).hexdigest()[:16]
        tok = f"<{entity_type}_{digest}>"
        if tok in self._store:
            self._store[tok]["value"] = new_value
            if self.path:
                self.save()
            return {"rectified": True, "token": tok, "new_value": new_value}
        return {"rectified": False, "reason": "value not found in vault"}

    def save(self):
        self.path.write_text(json.dumps({
            "store": {k: {**v, "identities": sorted(v["identities"])}
                      for k, v in self._store.items()},
            "identities": {k: sorted(v) for k, v in self._identities.items()},
            "idnames": {k: sorted(v) for k, v in self._idnames.items()},
            "shredded": self._shredded}, indent=2))

    def _load(self):
        d = json.loads(self.path.read_text())
        self._store = {k: {**v, "identities": set(v.get("identities", []))}
                       for k, v in d.get("store", {}).items()}
        self._identities = {k: set(v) for k, v in d.get("identities", {}).items()}
        self._idnames = {k: set(v) for k, v in d.get("idnames", {}).items()}
        self._shredded = d.get("shredded", [])
