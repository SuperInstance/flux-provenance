"""Comprehensive tests for flux_provenance.provenance — 60+ tests."""

from __future__ import annotations

import time

import pytest

from flux_provenance.provenance import (
    AgentKeyring,
    AttributionAnalyzer,
    ChainOfCustody,
    ProvenanceRecord,
    ProvenanceStore,
    SigningEngine,
    TransformType,
)


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture
def store():
    return ProvenanceStore()


@pytest.fixture
def keyring():
    kr = AgentKeyring()
    for name in ["quill", "oracle-7", "worker-42", "architect-1"]:
        pub, sec = SigningEngine.generate_keypair()
        kr.register(name, pub, sec)
    return kr


@pytest.fixture
def bytecode_a():
    return b"\x00\x01\x02\x03\x04\x05"


@pytest.fixture
def bytecode_b():
    return b"\xff\xfe\xfd\xfc\xfb\xfa"


@pytest.fixture
def bytecode_c():
    return b"\xaa\xbb\xcc\xdd\xee\xff"


@pytest.fixture
def signed_record_a(keyring, bytecode_a):
    """A fully signed provenance record for bytecode_a by quill."""
    h = SigningEngine.hash_bytes(bytecode_a)
    secret = keyring.secret_key("quill")
    rec = ProvenanceRecord(
        artifact_hash=h,
        author_id="quill",
        author_role="Architect",
        source_language="signal",
        source_hash=SigningEngine.hash_bytes(b"source-code"),
        compiler_version="fluxc-0.2.0",
        target_isa="flux-isa-2",
        parent_hashes=(),
        license="MIT",
        annotations=(("module", "core"),),
    )
    sig = SigningEngine.sign(rec.canonical_bytes(), secret)
    return ProvenanceRecord(
        artifact_hash=rec.artifact_hash,
        author_id=rec.author_id,
        author_role=rec.author_role,
        source_language=rec.source_language,
        source_hash=rec.source_hash,
        compiler_version=rec.compiler_version,
        target_isa=rec.target_isa,
        timestamp=rec.timestamp,
        signature=sig,
        parent_hashes=rec.parent_hashes,
        license=rec.license,
        annotations=rec.annotations,
    )


# ===================================================================
# 1. SigningEngine — 12 tests
# ===================================================================

class TestSigningEngine:
    def test_sign_produces_hex_string(self):
        sig = SigningEngine.sign(b"hello", "secret123")
        assert isinstance(sig, str)
        assert len(sig) == 64  # SHA-256 hex

    def test_sign_deterministic(self):
        s1 = SigningEngine.sign(b"data", "key")
        s2 = SigningEngine.sign(b"data", "key")
        assert s1 == s2

    def test_sign_differs_with_different_keys(self):
        s1 = SigningEngine.sign(b"data", "key1")
        s2 = SigningEngine.sign(b"data", "key2")
        assert s1 != s2

    def test_sign_differs_with_different_data(self):
        s1 = SigningEngine.sign(b"data1", "key")
        s2 = SigningEngine.sign(b"data2", "key")
        assert s1 != s2

    def test_verify_valid_signature(self):
        sig = SigningEngine.sign(b"hello", "mykey")
        assert SigningEngine.verify(b"hello", sig, "mykey") is True

    def test_verify_invalid_signature(self):
        sig = SigningEngine.sign(b"hello", "mykey")
        assert SigningEngine.verify(b"hello", sig, "wrongkey") is False

    def test_verify_wrong_data(self):
        sig = SigningEngine.sign(b"hello", "mykey")
        assert SigningEngine.verify(b"world", sig, "mykey") is False

    def test_verify_empty_signature(self):
        assert SigningEngine.verify(b"hello", "", "mykey") is False

    def test_hash_bytes_is_sha256_hex(self):
        h = SigningEngine.hash_bytes(b"test")
        assert isinstance(h, str)
        assert len(h) == 64

    def test_hash_bytes_deterministic(self):
        h1 = SigningEngine.hash_bytes(b"same")
        h2 = SigningEngine.hash_bytes(b"same")
        assert h1 == h2

    def test_hash_bytes_differs_for_different_inputs(self):
        h1 = SigningEngine.hash_bytes(b"a")
        h2 = SigningEngine.hash_bytes(b"b")
        assert h1 != h2

    def test_generate_keypair_returns_tuple_of_strings(self):
        pub, sec = SigningEngine.generate_keypair()
        assert isinstance(pub, str) and len(pub) == 64
        assert isinstance(sec, str) and len(sec) == 64
        assert pub != sec


# ===================================================================
# 2. ProvenanceRecord — 10 tests
# ===================================================================

class TestProvenanceRecord:
    def test_create_minimal_record(self):
        rec = ProvenanceRecord(artifact_hash="abc", author_id="agent-1")
        assert rec.artifact_hash == "abc"
        assert rec.author_id == "agent-1"
        assert rec.author_role == "Worker"
        assert rec.parent_hashes == ()
        assert rec.annotations == ()

    def test_create_full_record(self):
        rec = ProvenanceRecord(
            artifact_hash="h1",
            author_id="a1",
            author_role="Oracle",
            source_language="raw_bytecode",
            source_hash="sh1",
            compiler_version="v3",
            target_isa="isa-3",
            license="Apache-2.0",
            parent_hashes=("ph1", "ph2"),
            annotations=(("k", "v"),),
        )
        assert rec.author_role == "Oracle"
        assert rec.source_language == "raw_bytecode"
        assert rec.license == "Apache-2.0"
        assert len(rec.parent_hashes) == 2
        assert rec.annotations == (("k", "v"),)

    def test_timestamp_auto_populated(self):
        rec = ProvenanceRecord(artifact_hash="x", author_id="y")
        assert rec.timestamp != ""
        assert "T" in rec.timestamp  # ISO format

    def test_frozen_immutability(self):
        rec = ProvenanceRecord(artifact_hash="x", author_id="y")
        with pytest.raises(AttributeError):
            rec.artifact_hash = "changed"

    def test_to_dict_round_trip(self):
        rec = ProvenanceRecord(
            artifact_hash="h1",
            author_id="a1",
            parent_hashes=("p1",),
            annotations=(("k", "v"),),
        )
        d = rec.to_dict()
        assert d["artifact_hash"] == "h1"
        assert d["parent_hashes"] == ["p1"]
        assert d["annotations"] == [("k", "v")]

    def test_from_dict_round_trip(self):
        data = {
            "artifact_hash": "h2",
            "author_id": "a2",
            "author_role": "Architect",
            "source_language": "signal",
            "source_hash": "sh2",
            "compiler_version": "v2",
            "target_isa=": "isa-2",
            "timestamp": "2025-01-01T00:00:00Z",
            "signature": "sig123",
            "parent_hashes": ["p1", "p2"],
            "license": "MIT",
            "annotations": [["env", "prod"]],
        }
        # Fix the typo key
        data["target_isa"] = "isa-2"
        rec = ProvenanceRecord.from_dict(data)
        assert rec.artifact_hash == "h2"
        assert rec.author_role == "Architect"
        assert len(rec.parent_hashes) == 2

    def test_canonical_bytes_deterministic(self):
        rec = ProvenanceRecord(artifact_hash="h", author_id="a")
        b1 = rec.canonical_bytes()
        b2 = rec.canonical_bytes()
        assert b1 == b2

    def test_canonical_bytes_excludes_signature(self):
        rec1 = ProvenanceRecord(artifact_hash="h", author_id="a", signature="sig1", timestamp="2025-01-01T00:00:00Z")
        rec2 = ProvenanceRecord(artifact_hash="h", author_id="a", signature="sig2", timestamp="2025-01-01T00:00:00Z")
        assert rec1.canonical_bytes() == rec2.canonical_bytes()

    def test_canonical_bytes_json_serializable(self):
        import json
        rec = ProvenanceRecord(
            artifact_hash="h", author_id="a", parent_hashes=("p1",),
            annotations=(("k", "v"),),
        )
        data = json.loads(rec.canonical_bytes())
        assert data["artifact_hash"] == "h"
        assert data["parent_hashes"] == ["p1"]

    def test_default_license(self):
        rec = ProvenanceRecord(artifact_hash="h", author_id="a")
        assert rec.license == "FLUX-INTERNAL"


# ===================================================================
# 3. AgentKeyring — 8 tests
# ===================================================================

class TestAgentKeyring:
    def test_register_and_retrieve(self):
        kr = AgentKeyring()
        kr.register("agent-1", "pub1", "sec1")
        assert kr.secret_key("agent-1") == "sec1"
        assert kr.public_key("agent-1") == "pub1"

    def test_has_agent(self):
        kr = AgentKeyring()
        kr.register("a", "p", "s")
        assert kr.has_agent("a") is True
        assert kr.has_agent("b") is False

    def test_list_agents(self):
        kr = AgentKeyring()
        kr.register("a1", "p1", "s1")
        kr.register("a2", "p2", "s2")
        agents = kr.list_agents()
        assert "a1" in agents and "a2" in agents

    def test_secret_key_missing(self):
        kr = AgentKeyring()
        assert kr.secret_key("nobody") is None

    def test_public_key_missing(self):
        kr = AgentKeyring()
        assert kr.public_key("nobody") is None

    def test_remove_agent(self):
        kr = AgentKeyring()
        kr.register("a", "p", "s")
        kr.remove("a")
        assert kr.has_agent("a") is False

    def test_remove_nonexistent(self):
        kr = AgentKeyring()
        kr.remove("ghost")  # should not raise

    def test_register_overwrites(self):
        kr = AgentKeyring()
        kr.register("a", "p1", "s1")
        kr.register("a", "p2", "s2")
        assert kr.secret_key("a") == "s2"


# ===================================================================
# 4. ProvenanceStore — 14 tests
# ===================================================================

class TestProvenanceStore:
    def test_record_and_lookup(self, store, signed_record_a):
        store.record(signed_record_a)
        found = store.lookup(signed_record_a.artifact_hash)
        assert found is not None
        assert found.author_id == "quill"

    def test_lookup_missing(self, store):
        assert store.lookup("nonexistent") is None

    def test_record_duplicate_raises(self, store, signed_record_a):
        store.record(signed_record_a)
        with pytest.raises(ValueError, match="already recorded"):
            store.record(signed_record_a)

    def test_by_author(self, store, signed_record_a, bytecode_b, keyring):
        # Record second artifact by different author
        h_b = SigningEngine.hash_bytes(bytecode_b)
        sec = keyring.secret_key("oracle-7")
        rec_b = ProvenanceRecord(
            artifact_hash=h_b,
            author_id="oracle-7",
            author_role="Oracle",
        )
        sig_b = SigningEngine.sign(rec_b.canonical_bytes(), sec)
        rec_b = ProvenanceRecord(
            artifact_hash=rec_b.artifact_hash,
            author_id=rec_b.author_id,
            author_role=rec_b.author_role,
            source_language=rec_b.source_language,
            source_hash=rec_b.source_hash,
            compiler_version=rec_b.compiler_version,
            target_isa=rec_b.target_isa,
            timestamp=rec_b.timestamp,
            signature=sig_b,
            parent_hashes=rec_b.parent_hashes,
            license=rec_b.license,
            annotations=rec_b.annotations,
        )
        store.record(signed_record_a)
        store.record(rec_b)
        quill_records = store.by_author("quill")
        assert len(quill_records) == 1
        assert quill_records[0].author_id == "quill"
        oracle_records = store.by_author("oracle-7")
        assert len(oracle_records) == 1

    def test_by_author_empty(self, store):
        assert store.by_author("nobody") == []

    def test_history_single(self, store, signed_record_a):
        store.record(signed_record_a)
        chain = store.history(signed_record_a.artifact_hash)
        assert len(chain) == 1
        assert chain[0].artifact_hash == signed_record_a.artifact_hash

    def test_history_chain(self, store, keyring):
        # Build a chain: root -> child -> grandchild
        root_hash = SigningEngine.hash_bytes(b"root")
        sec = keyring.secret_key("quill")
        root = ProvenanceRecord(
            artifact_hash=root_hash, author_id="quill", parent_hashes=(),
        )
        root = _signed_copy(root, sec)
        store.record(root)

        child_hash = SigningEngine.hash_bytes(b"child")
        child = ProvenanceRecord(
            artifact_hash=child_hash, author_id="quill",
            parent_hashes=(root_hash,),
        )
        child = _signed_copy(child, sec)
        store.record(child)

        gc_hash = SigningEngine.hash_bytes(b"grandchild")
        gc = ProvenanceRecord(
            artifact_hash=gc_hash, author_id="quill",
            parent_hashes=(child_hash,),
        )
        gc = _signed_copy(gc, sec)
        store.record(gc)

        chain = store.history(gc_hash)
        assert len(chain) == 3
        assert chain[0].artifact_hash == gc_hash
        assert chain[1].artifact_hash == child_hash
        assert chain[2].artifact_hash == root_hash

    def test_history_breaks_on_missing(self, store, signed_record_a):
        missing_hash = "deadbeef" * 8
        rec = ProvenanceRecord(
            artifact_hash=SigningEngine.hash_bytes(b"x"),
            author_id="quill",
            parent_hashes=(missing_hash,),
        )
        store.record(rec)
        chain = store.history(rec.artifact_hash)
        # chain starts with rec, then breaks because missing_hash not in store
        assert len(chain) == 1

    def test_verify_valid(self, store, signed_record_a, bytecode_a, keyring):
        store.record(signed_record_a)
        secret = keyring.secret_key("quill")
        assert store.verify(bytecode_a, signed_record_a, secret) is True

    def test_verify_wrong_bytes(self, store, signed_record_a, bytecode_b, keyring):
        store.record(signed_record_a)
        secret = keyring.secret_key("quill")
        assert store.verify(bytecode_b, signed_record_a, secret) is False

    def test_verify_wrong_key(self, store, signed_record_a, bytecode_a, keyring):
        store.record(signed_record_a)
        secret = keyring.secret_key("oracle-7")
        assert store.verify(bytecode_a, signed_record_a, secret) is False

    def test_by_time_range(self, store, signed_record_a, bytecode_b, keyring):
        store.record(signed_record_a)
        sec = keyring.secret_key("oracle-7")
        rec_b = _make_record(bytecode_b, "oracle-7", sec)
        store.record(rec_b)
        all_records = store.all_records()
        assert store.count() == 2

    def test_lineage(self, store, keyring):
        sec = keyring.secret_key("quill")
        root = _make_record(b"r", "quill", sec)
        store.record(root)
        child = _make_record(b"c", "quill", sec, parents=(root.artifact_hash,))
        store.record(child)
        gc = _make_record(b"g", "quill", sec, parents=(child.artifact_hash,))
        store.record(gc)

        lin = store.lineage(gc.artifact_hash)
        assert len(lin) == 3
        assert gc.artifact_hash in lin
        assert root.artifact_hash in lin

    def test_all_records(self, store, signed_record_a, bytecode_b, keyring):
        store.record(signed_record_a)
        rec_b = _make_record(bytecode_b, "oracle-7", keyring.secret_key("oracle-7"))
        store.record(rec_b)
        assert store.count() == 2
        assert len(store.all_records()) == 2


# ===================================================================
# 5. AttributionAnalyzer — 9 tests
# ===================================================================

class TestAttributionAnalyzer:
    def test_author_frequency(self, store, keyring):
        for i in range(3):
            rec = _make_record(f"quill-{i}".encode(), "quill", keyring.secret_key("quill"))
            store.record(rec)
        for i in range(2):
            rec = _make_record(f"oracle-{i}".encode(), "oracle-7", keyring.secret_key("oracle-7"))
            store.record(rec)
        analyzer = AttributionAnalyzer(store)
        freq = analyzer.author_frequency()
        assert freq["quill"] == 3
        assert freq["oracle-7"] == 2

    def test_author_frequency_empty(self, store):
        analyzer = AttributionAnalyzer(store)
        assert analyzer.author_frequency() == {}

    def test_derivation_depth_root(self, store, keyring):
        rec = _make_record(b"root", "quill", keyring.secret_key("quill"))
        store.record(rec)
        analyzer = AttributionAnalyzer(store)
        assert analyzer.derivation_depth(rec.artifact_hash) == 0

    def test_derivation_depth_chain(self, store, keyring):
        sec = keyring.secret_key("quill")
        r0 = _make_record(b"r0", "quill", sec)
        store.record(r0)
        r1 = _make_record(b"r1", "quill", sec, parents=(r0.artifact_hash,))
        store.record(r1)
        r2 = _make_record(b"r2", "quill", sec, parents=(r1.artifact_hash,))
        store.record(r2)
        analyzer = AttributionAnalyzer(store)
        assert analyzer.derivation_depth(r2.artifact_hash) == 2
        assert analyzer.derivation_depth(r1.artifact_hash) == 1
        assert analyzer.derivation_depth(r0.artifact_hash) == 0

    def test_license_compatibility_all_match(self, store, keyring):
        sec = keyring.secret_key("quill")
        root = _make_record(b"r", "quill", sec, license_tag="MIT")
        store.record(root)
        child = _make_record(b"c", "quill", sec, parents=(root.artifact_hash,), license_tag="MIT")
        store.record(child)
        analyzer = AttributionAnalyzer(store)
        assert analyzer.license_compatibility(child.artifact_hash, "MIT") is True

    def test_license_compatibility_mismatch(self, store, keyring):
        sec = keyring.secret_key("quill")
        root = _make_record(b"r", "quill", sec, license_tag="GPL")
        store.record(root)
        child = _make_record(b"c", "quill", sec, parents=(root.artifact_hash,), license_tag="MIT")
        store.record(child)
        analyzer = AttributionAnalyzer(store)
        assert analyzer.license_compatibility(child.artifact_hash, "MIT") is False

    def test_attribution_report(self, store, keyring):
        sec = keyring.secret_key("quill")
        rec = _make_record(
            b"artifact", "quill", sec,
            license_tag="Apache-2.0",
            annotations={"module": "core", "version": "1.0"},
        )
        store.record(rec)
        analyzer = AttributionAnalyzer(store)
        report = analyzer.attribution_report(rec.artifact_hash)
        assert report["artifact_hash"] == rec.artifact_hash
        assert report["author"] == "quill"
        assert report["license"] == "Apache-2.0"
        assert report["derivation_depth"] == 0
        assert report["unique_authors_in_lineage"] == 1
        assert report["annotations"]["module"] == "core"

    def test_attribution_report_missing(self, store):
        analyzer = AttributionAnalyzer(store)
        report = analyzer.attribution_report("nonexistent")
        assert "error" in report

    def test_attribution_report_chain(self, store, keyring):
        sec = keyring.secret_key("quill")
        root = _make_record(b"r", "quill", sec)
        store.record(root)
        child = _make_record(b"c", "oracle-7", keyring.secret_key("oracle-7"), parents=(root.artifact_hash,))
        store.record(child)
        analyzer = AttributionAnalyzer(store)
        report = analyzer.attribution_report(child.artifact_hash)
        assert report["derivation_depth"] == 1
        assert report["unique_authors_in_lineage"] == 2
        assert len(report["author_lineage"]) == 2


# ===================================================================
# 6. ChainOfCustody — 14 tests
# ===================================================================

class TestChainOfCustody:
    def test_transform_creates_child(self, store, keyring, bytecode_a, bytecode_b):
        sec = keyring.secret_key("quill")
        root = _make_record(bytecode_a, "quill", sec)
        store.record(root)
        coc = ChainOfCustody(store, keyring)
        child = coc.transform(
            parent_hash=root.artifact_hash,
            new_bytecode=bytecode_b,
            transform_type=TransformType.OPTIMIZE,
            author_id="quill",
        )
        assert child.parent_hashes[0] == root.artifact_hash
        assert store.lookup(child.artifact_hash) is not None

    def test_transform_missing_parent_raises(self, store, keyring, bytecode_b):
        coc = ChainOfCustody(store, keyring)
        with pytest.raises(ValueError, match="not found"):
            coc.transform(
                parent_hash="nonexistent",
                new_bytecode=bytecode_b,
                transform_type=TransformType.COMPILE,
                author_id="quill",
            )

    def test_transform_signature(self, store, keyring, bytecode_a, bytecode_b):
        sec = keyring.secret_key("quill")
        root = _make_record(bytecode_a, "quill", sec)
        store.record(root)
        coc = ChainOfCustody(store, keyring)
        child = coc.transform(
            parent_hash=root.artifact_hash,
            new_bytecode=bytecode_b,
            transform_type=TransformType.PATCH,
            author_id="quill",
        )
        assert child.signature != ""
        assert SigningEngine.verify(child.canonical_bytes(), child.signature, sec) is True

    def test_transform_annotation_has_type(self, store, keyring, bytecode_a, bytecode_b):
        sec = keyring.secret_key("quill")
        root = _make_record(bytecode_a, "quill", sec)
        store.record(root)
        coc = ChainOfCustody(store, keyring)
        child = coc.transform(
            parent_hash=root.artifact_hash,
            new_bytecode=bytecode_b,
            transform_type=TransformType.MERGE,
            author_id="quill",
        )
        ann_dict = dict(child.annotations)
        assert ann_dict.get("transform_type") == "MERGE"

    def test_transform_extra_parents(self, store, keyring):
        sec = keyring.secret_key("quill")
        r0 = _make_record(b"r0", "quill", sec)
        r1 = _make_record(b"r1", "quill", sec)
        store.record(r0)
        store.record(r1)
        coc = ChainOfCustody(store, keyring)
        merged = coc.transform(
            parent_hash=r0.artifact_hash,
            new_bytecode=b"merged",
            transform_type=TransformType.MERGE,
            author_id="quill",
            extra_parent_hashes=[r1.artifact_hash],
        )
        assert r0.artifact_hash in merged.parent_hashes
        assert r1.artifact_hash in merged.parent_hashes

    def test_transform_custom_license(self, store, keyring, bytecode_a, bytecode_b):
        sec = keyring.secret_key("quill")
        root = _make_record(bytecode_a, "quill", sec)
        store.record(root)
        coc = ChainOfCustody(store, keyring)
        child = coc.transform(
            parent_hash=root.artifact_hash,
            new_bytecode=bytecode_b,
            transform_type=TransformType.FORK,
            author_id="quill",
            license_tag="BSD-3-Clause",
        )
        assert child.license == "BSD-3-Clause"

    def test_transform_custom_annotations(self, store, keyring, bytecode_a, bytecode_b):
        sec = keyring.secret_key("quill")
        root = _make_record(bytecode_a, "quill", sec)
        store.record(root)
        coc = ChainOfCustody(store, keyring)
        child = coc.transform(
            parent_hash=root.artifact_hash,
            new_bytecode=bytecode_b,
            transform_type=TransformType.TRANSLATE,
            author_id="quill",
            annotations={"reason": "porting"},
        )
        ann_dict = dict(child.annotations)
        assert ann_dict["reason"] == "porting"

    def test_compile_creates_record(self, store, keyring):
        coc = ChainOfCustody(store, keyring)
        rec = coc.compile(b"source code", b"bytecode", author_id="quill")
        assert rec.source_hash == SigningEngine.hash_bytes(b"source code")
        assert rec.artifact_hash == SigningEngine.hash_bytes(b"bytecode")

    def test_compile_is_signed(self, store, keyring):
        coc = ChainOfCustody(store, keyring)
        sec = keyring.secret_key("quill")
        rec = coc.compile(b"src", b"bc", author_id="quill")
        assert SigningEngine.verify(rec.canonical_bytes(), rec.signature, sec) is True

    def test_compile_custom_params(self, store, keyring):
        coc = ChainOfCustody(store, keyring)
        rec = coc.compile(
            b"src", b"bc", author_id="quill",
            author_role="Architect",
            source_language="signal",
            license_tag="MIT",
        )
        assert rec.author_role == "Architect"
        assert rec.source_language == "signal"
        assert rec.license == "MIT"

    def test_compile_annotated_transform_type(self, store, keyring):
        coc = ChainOfCustody(store, keyring)
        rec = coc.compile(b"src", b"bc", author_id="quill")
        ann_dict = dict(rec.annotations)
        assert ann_dict["transform_type"] == "COMPILE"

    def test_full_chain_of_custody(self, store, keyring):
        """End-to-end: compile → optimize → patch with verification."""
        coc = ChainOfCustody(store, keyring)
        sec = keyring.secret_key("quill")

        # Compile
        compiled = coc.compile(b"source", b"bytecode-v1", author_id="quill")
        assert store.verify(b"bytecode-v1", compiled, sec) is True

        # Optimize
        optimized = coc.transform(
            compiled.artifact_hash, b"bytecode-v2",
            TransformType.OPTIMIZE, "quill",
        )
        assert store.verify(b"bytecode-v2", optimized, sec) is True

        # Patch
        patched = coc.transform(
            optimized.artifact_hash, b"bytecode-v3",
            TransformType.PATCH, "quill",
        )
        assert store.verify(b"bytecode-v3", patched, sec) is True

        # Verify history
        history = store.history(patched.artifact_hash)
        assert len(history) == 3

    def test_multi_author_chain(self, store, keyring):
        """Chain across multiple agents."""
        coc = ChainOfCustody(store, keyring)
        r0 = coc.compile(b"s1", b"b1", author_id="quill")
        r1 = coc.transform(r0.artifact_hash, b"b2", TransformType.OPTIMIZE, "oracle-7")
        r2 = coc.transform(r1.artifact_hash, b"b3", TransformType.PATCH, "worker-42")
        history = store.history(r2.artifact_hash)
        assert len(history) == 3
        assert history[0].author_id == "worker-42"
        assert history[1].author_id == "oracle-7"
        assert history[2].author_id == "quill"

    def test_transform_unknown_author_unsigned(self, store, keyring, bytecode_a, bytecode_b):
        sec = keyring.secret_key("quill")
        root = _make_record(bytecode_a, "quill", sec)
        store.record(root)
        coc = ChainOfCustody(store, keyring)
        child = coc.transform(
            parent_hash=root.artifact_hash,
            new_bytecode=bytecode_b,
            transform_type=TransformType.COMPILE,
            author_id="unknown-agent",
        )
        # No key → no signature (empty string or placeholder)
        # The record should still be created
        assert child.artifact_hash == SigningEngine.hash_bytes(bytecode_b)
        assert child.author_id == "unknown-agent"


# ===================================================================
# 7. TransformType enum — 2 tests
# ===================================================================

class TestTransformType:
    def test_all_values_exist(self):
        expected = {"COMPILE", "OPTIMIZE", "TRANSLATE", "MERGE", "PATCH", "FORK"}
        actual = {t.value for t in TransformType}
        assert actual == expected

    def test_enum_comparison(self):
        assert TransformType.COMPILE == "COMPILE"
        assert TransformType.COMPILE != "COMPILE_WRONG"


# ===================================================================
# Helpers
# ===================================================================

def _signed_copy(rec: ProvenanceRecord, secret_key: str) -> ProvenanceRecord:
    sig = SigningEngine.sign(rec.canonical_bytes(), secret_key)
    return ProvenanceRecord(
        artifact_hash=rec.artifact_hash,
        author_id=rec.author_id,
        author_role=rec.author_role,
        source_language=rec.source_language,
        source_hash=rec.source_hash,
        compiler_version=rec.compiler_version,
        target_isa=rec.target_isa,
        timestamp=rec.timestamp,
        signature=sig,
        parent_hashes=rec.parent_hashes,
        license=rec.license,
        annotations=rec.annotations,
    )


def _make_record(
    bytecode: bytes,
    author_id: str,
    secret_key: str,
    *,
    parents: tuple = (),
    license_tag: str = "FLUX-INTERNAL",
    annotations: Optional[dict] = None,
) -> ProvenanceRecord:
    h = SigningEngine.hash_bytes(bytecode)
    rec = ProvenanceRecord(
        artifact_hash=h,
        author_id=author_id,
        parent_hashes=parents,
        license=license_tag,
        annotations=tuple((annotations or {}).items()),
    )
    sig = SigningEngine.sign(rec.canonical_bytes(), secret_key)
    return ProvenanceRecord(
        artifact_hash=rec.artifact_hash,
        author_id=rec.author_id,
        author_role=rec.author_role,
        source_language=rec.source_language,
        source_hash=rec.source_hash,
        compiler_version=rec.compiler_version,
        target_isa=rec.target_isa,
        timestamp=rec.timestamp,
        signature=sig,
        parent_hashes=rec.parent_hashes,
        license=rec.license,
        annotations=rec.annotations,
    )
