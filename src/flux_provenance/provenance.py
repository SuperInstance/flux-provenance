"""
flux_provenance.provenance — Provenance & Attribution Layer for FLUX Bytecode.

Records WHO authored WHAT bytecode, WHEN it was compiled, from WHAT source,
and provides cryptographic integrity verification. Creates an auditable
chain of custody for all FLUX programs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TransformType(str, Enum):
    """Types of artifact transformations."""
    COMPILE = "COMPILE"
    OPTIMIZE = "OPTIMIZE"
    TRANSLATE = "TRANSLATE"
    MERGE = "MERGE"
    PATCH = "PATCH"
    FORK = "FORK"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProvenanceRecord:
    """Immutable metadata for a bytecode artifact.

    Attributes:
        artifact_hash: SHA-256 hex digest of the bytecode.
        author_id: Identifier of the agent that produced the artifact.
        author_role: Role classification (Architect, Oracle, Worker, etc.).
        source_language: Language of the source material.
        source_hash: SHA-256 of the pre-compilation source.
        compiler_version: Version string of the compiler used.
        target_isa: Target ISA version the bytecode targets.
        timestamp: ISO-8601 UTC timestamp of compilation.
        signature: HMAC-SHA256 hex signature.
        parent_hashes: List of parent artifact hashes (derived works).
        license: Usage license tag (e.g. "MIT", "FLUX-INTERNAL").
        annotations: Free-form key-value metadata.
    """
    artifact_hash: str
    author_id: str
    author_role: str = "Worker"
    source_language: str = "signal"
    source_hash: str = ""
    compiler_version: str = "fluxc-0.1.0"
    target_isa: str = "flux-isa-1"
    timestamp: str = ""
    signature: str = ""
    parent_hashes: Tuple[str, ...] = ()
    license: str = "FLUX-INTERNAL"
    annotations: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.timestamp:
            object.__setattr__(
                self,
                "timestamp",
                datetime.now(timezone.utc).isoformat(),
            )

    # -- convenience helpers ------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "artifact_hash": self.artifact_hash,
            "author_id": self.author_id,
            "author_role": self.author_role,
            "source_language": self.source_language,
            "source_hash": self.source_hash,
            "compiler_version": self.compiler_version,
            "target_isa": self.target_isa,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "parent_hashes": list(self.parent_hashes),
            "license": self.license,
            "annotations": list(self.annotations),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProvenanceRecord:
        """Deserialize from a dictionary."""
        return cls(
            artifact_hash=data["artifact_hash"],
            author_id=data["author_id"],
            author_role=data.get("author_role", "Worker"),
            source_language=data.get("source_language", "signal"),
            source_hash=data.get("source_hash", ""),
            compiler_version=data.get("compiler_version", "fluxc-0.1.0"),
            target_isa=data.get("target_isa", "flux-isa-1"),
            timestamp=data.get("timestamp", ""),
            signature=data.get("signature", ""),
            parent_hashes=tuple(data.get("parent_hashes", [])),
            license=data.get("license", "FLUX-INTERNAL"),
            annotations=tuple(
                tuple(item) if isinstance(item, list) else item
                for item in data.get("annotations", [])
            ),
        )

    def canonical_bytes(self) -> bytes:
        """Return the canonical byte representation for signing.

        All signing-relevant fields are serialized deterministically.
        The signature itself is excluded so it can be verified independently.
        """
        payload = {
            "artifact_hash": self.artifact_hash,
            "author_id": self.author_id,
            "author_role": self.author_role,
            "source_language": self.source_language,
            "source_hash": self.source_hash,
            "compiler_version": self.compiler_version,
            "target_isa": self.target_isa,
            "timestamp": self.timestamp,
            "parent_hashes": list(self.parent_hashes),
            "license": self.license,
            "annotations": list(self.annotations),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------------------
# Signing Engine
# ---------------------------------------------------------------------------

class SigningEngine:
    """Cryptographic signing utilities using HMAC-SHA256."""

    @staticmethod
    def sign(data: bytes, secret_key: str) -> str:
        """Produce an HMAC-SHA256 hex signature."""
        return hmac.new(
            secret_key.encode("utf-8"), data, hashlib.sha256
        ).hexdigest()

    @staticmethod
    def verify(data: bytes, signature: str, secret_key: str) -> bool:
        """Verify an HMAC-SHA256 signature (constant-time comparison)."""
        expected = hmac.new(
            secret_key.encode("utf-8"), data, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """Generate a (public_key, secret_key) pair.

        In this simplified scheme the public_key is a SHA-256 hash of the
        secret_key so that third parties can verify identity without
        learning the secret.
        """
        secret_key = secrets.token_hex(32)
        public_key = hashlib.sha256(secret_key.encode()).hexdigest()
        return public_key, secret_key

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        """Return SHA-256 hex digest of *data*."""
        return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Agent Keyring
# ---------------------------------------------------------------------------

class AgentKeyring:
    """In-memory registry of agent keys for signing / verification."""

    def __init__(self) -> None:
        self._keys: Dict[str, Dict[str, str]] = {}

    def register(self, agent_id: str, public_key: str, secret_key: str) -> None:
        self._keys[agent_id] = {"public": public_key, "secret": secret_key}

    def secret_key(self, agent_id: str) -> Optional[str]:
        entry = self._keys.get(agent_id)
        return entry["secret"] if entry else None

    def public_key(self, agent_id: str) -> Optional[str]:
        entry = self._keys.get(agent_id)
        return entry["public"] if entry else None

    def has_agent(self, agent_id: str) -> bool:
        return agent_id in self._keys

    def list_agents(self) -> List[str]:
        return list(self._keys.keys())

    def remove(self, agent_id: str) -> None:
        self._keys.pop(agent_id, None)


# ---------------------------------------------------------------------------
# Provenance Store (in-memory, immutable-once-written)
# ---------------------------------------------------------------------------

class ProvenanceStore:
    """Git-backed (conceptually) immutable provenance store.

    In this implementation records are kept in memory but are considered
    immutable once written — no update / delete operations are exposed.
    """

    def __init__(self) -> None:
        self._records: Dict[str, ProvenanceRecord] = {}
        self._by_author: Dict[str, List[str]] = {}
        self._by_time: List[Tuple[str, str]] = []  # (timestamp, hash)

    # -- write ---------------------------------------------------------------

    def record(self, prov: ProvenanceRecord) -> None:
        """Register a new provenance record (immutable once written)."""
        h = prov.artifact_hash
        if h in self._records:
            raise ValueError(f"Artifact {h} already recorded")
        self._records[h] = prov
        self._by_author.setdefault(prov.author_id, []).append(h)
        self._by_time.append((prov.timestamp, h))

    # -- query ---------------------------------------------------------------

    def lookup(self, artifact_hash: str) -> Optional[ProvenanceRecord]:
        return self._records.get(artifact_hash)

    def history(self, artifact_hash: str) -> List[ProvenanceRecord]:
        """Walk parent_hashes recursively to build full chain of custody."""
        chain: List[ProvenanceRecord] = []
        visited: Set[str] = set()
        current = artifact_hash
        while current:
            if current in visited:
                break
            visited.add(current)
            prov = self._records.get(current)
            if prov is None:
                break
            chain.append(prov)
            if prov.parent_hashes:
                current = prov.parent_hashes[0]
            else:
                current = ""
        return chain

    def verify(
        self, artifact_bytes: bytes, prov: ProvenanceRecord, secret_key: str
    ) -> bool:
        """Verify the artifact hash *and* HMAC signature."""
        expected_hash = SigningEngine.hash_bytes(artifact_bytes)
        if expected_hash != prov.artifact_hash:
            return False
        return SigningEngine.verify(prov.canonical_bytes(), prov.signature, secret_key)

    def by_author(self, author_id: str) -> List[ProvenanceRecord]:
        hashes = self._by_author.get(author_id, [])
        return [self._records[h] for h in hashes if h in self._records]

    def by_time_range(
        self, start: str, end: str
    ) -> List[ProvenanceRecord]:
        """Return records whose timestamp falls in [start, end] (ISO-8601)."""
        results: List[ProvenanceRecord] = []
        for ts, h in self._by_time:
            if start <= ts <= end:
                prov = self._records.get(h)
                if prov is not None:
                    results.append(prov)
        return results

    def lineage(self, artifact_hash: str) -> Dict[str, Any]:
        """Build the full derivation DAG reachable from *artifact_hash*."""
        nodes: Dict[str, Dict[str, Any]] = {}
        queue = [artifact_hash]
        visited: Set[str] = set()
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            prov = self._records.get(current)
            if prov is None:
                continue
            children = list(prov.parent_hashes)
            nodes[current] = {
                "artifact_hash": current,
                "author_id": prov.author_id,
                "parents": children,
            }
            queue.extend(children)
        return nodes

    def all_records(self) -> List[ProvenanceRecord]:
        return list(self._records.values())

    def count(self) -> int:
        return len(self._records)


# ---------------------------------------------------------------------------
# Attribution Analyzer
# ---------------------------------------------------------------------------

class AttributionAnalyzer:
    """Higher-level provenance analysis utilities."""

    def __init__(self, store: ProvenanceStore) -> None:
        self._store = store

    def author_frequency(self) -> Dict[str, int]:
        """Count how many artifacts each author has contributed."""
        freq: Dict[str, int] = {}
        for prov in self._store.all_records():
            freq[prov.author_id] = freq.get(prov.author_id, 0) + 1
        return freq

    def derivation_depth(self, artifact_hash: str) -> int:
        """Compute how deep *artifact_hash* is in the derivation tree.

        A root artifact (no parents) has depth 0.
        """
        depth = 0
        visited: Set[str] = set()
        current = artifact_hash
        while current:
            if current in visited:
                break
            visited.add(current)
            prov = self._store.lookup(current)
            if prov is None or not prov.parent_hashes:
                break
            depth += 1
            current = prov.parent_hashes[0]
        return depth

    def license_compatibility(
        self, artifact_hash: str, required_license: str
    ) -> bool:
        """Check that the artifact (and all ancestors) carry *required_license*."""
        chain = self._store.history(artifact_hash)
        for prov in chain:
            if prov.license != required_license:
                return False
        return True

    def attribution_report(self, artifact_hash: str) -> Dict[str, Any]:
        """Generate a full attribution report for an artifact."""
        chain = self._store.history(artifact_hash)
        lineage = self._store.lineage(artifact_hash)
        prov = self._store.lookup(artifact_hash)
        if prov is None:
            return {"error": f"Artifact {artifact_hash} not found"}

        authors_seen: List[Dict[str, str]] = []
        seen_ids: Set[str] = set()
        for p in reversed(chain):
            if p.author_id not in seen_ids:
                seen_ids.add(p.author_id)
                authors_seen.append({
                    "author_id": p.author_id,
                    "role": p.author_role,
                    "timestamp": p.timestamp,
                })

        return {
            "artifact_hash": artifact_hash,
            "author": prov.author_id,
            "role": prov.author_role,
            "license": prov.license,
            "compiler": prov.compiler_version,
            "target_isa": prov.target_isa,
            "compiled_at": prov.timestamp,
            "derivation_depth": self.derivation_depth(artifact_hash),
            "total_lineage_nodes": len(lineage),
            "chain_of_custody_length": len(chain),
            "unique_authors_in_lineage": len(seen_ids),
            "author_lineage": authors_seen,
            "annotations": dict(prov.annotations),
        }


# ---------------------------------------------------------------------------
# Chain of Custody
# ---------------------------------------------------------------------------

class ChainOfCustody:
    """High-level API for recording and querying artifact transformations."""

    def __init__(
        self,
        store: ProvenanceStore,
        keyring: AgentKeyring,
        compiler_version: str = "fluxc-0.1.0",
        target_isa: str = "flux-isa-1",
    ) -> None:
        self._store = store
        self._keyring = keyring
        self._compiler_version = compiler_version
        self._target_isa = target_isa

    def transform(
        self,
        parent_hash: str,
        new_bytecode: bytes,
        transform_type: TransformType,
        author_id: str,
        *,
        source_language: str = "bytecode",
        license_tag: str = "FLUX-INTERNAL",
        annotations: Optional[Dict[str, str]] = None,
        extra_parent_hashes: Optional[List[str]] = None,
    ) -> ProvenanceRecord:
        """Record a transformation producing *new_bytecode* from *parent_hash*.

        Returns the newly created ProvenanceRecord.
        """
        parent_prov = self._store.lookup(parent_hash)
        if parent_prov is None:
            raise ValueError(f"Parent artifact {parent_hash} not found in store")

        artifact_hash = SigningEngine.hash_bytes(new_bytecode)
        parent_hashes = [parent_hash] + (extra_parent_hashes or [])

        # Determine role from parent or default
        author_role = "Worker"
        secret = self._keyring.secret_key(author_id)

        # Build annotations with transform info
        ann: List[Tuple[str, str]] = list((annotations or {}).items())
        ann.append(("transform_type", transform_type.value))

        record = ProvenanceRecord(
            artifact_hash=artifact_hash,
            author_id=author_id,
            author_role=author_role,
            source_language=source_language,
            source_hash=parent_hash,
            compiler_version=self._compiler_version,
            target_isa=self._target_isa,
            signature=SigningEngine.sign(b"", "") if secret is None else "",
            parent_hashes=tuple(parent_hashes),
            license=license_tag,
            annotations=tuple(ann),
        )

        # Sign with the author's secret key if available
        if secret is not None:
            sig = SigningEngine.sign(record.canonical_bytes(), secret)
            record = ProvenanceRecord(
                artifact_hash=record.artifact_hash,
                author_id=record.author_id,
                author_role=record.author_role,
                source_language=record.source_language,
                source_hash=record.source_hash,
                compiler_version=record.compiler_version,
                target_isa=record.target_isa,
                timestamp=record.timestamp,
                signature=sig,
                parent_hashes=record.parent_hashes,
                license=record.license,
                annotations=record.annotations,
            )

        self._store.record(record)
        return record

    def compile(
        self,
        source: bytes,
        bytecode: bytes,
        author_id: str,
        **kwargs: Any,
    ) -> ProvenanceRecord:
        """Convenience: compile source → bytecode."""
        source_hash = SigningEngine.hash_bytes(source)
        artifact_hash = SigningEngine.hash_bytes(bytecode)
        secret = self._keyring.secret_key(author_id)

        ann: List[Tuple[str, str]] = list((kwargs.pop("annotations", None) or {}).items())
        ann.append(("transform_type", TransformType.COMPILE.value))

        record = ProvenanceRecord(
            artifact_hash=artifact_hash,
            author_id=author_id,
            author_role=kwargs.pop("author_role", "Worker"),
            source_language=kwargs.pop("source_language", "signal"),
            source_hash=source_hash,
            compiler_version=kwargs.pop("compiler_version", self._compiler_version),
            target_isa=kwargs.pop("target_isa", self._target_isa),
            signature="",
            parent_hashes=tuple(kwargs.pop("parent_hashes", [])),
            license=kwargs.pop("license_tag", "FLUX-INTERNAL"),
            annotations=tuple(ann),
        )

        if secret is not None:
            sig = SigningEngine.sign(record.canonical_bytes(), secret)
            record = ProvenanceRecord(
                artifact_hash=record.artifact_hash,
                author_id=record.author_id,
                author_role=record.author_role,
                source_language=record.source_language,
                source_hash=record.source_hash,
                compiler_version=record.compiler_version,
                target_isa=record.target_isa,
                timestamp=record.timestamp,
                signature=sig,
                parent_hashes=record.parent_hashes,
                license=record.license,
                annotations=record.annotations,
            )

        self._store.record(record)
        return record
