#!/usr/bin/env python3
from pathlib import Path
import json, re, sys

root = Path(__file__).resolve().parents[1]
data = json.loads((root/"tests/golden_vectors.json").read_text())

ids = [v["id"] for v in data["vectors"]]
assert len(ids) == len(set(ids)), "duplicate vector ids"

required = {"BLAKE3-001","BLAKE3-002","GGUF-CANON-001","MMR-001","MMR-1LEAF-001","MMR-3LEAF-001","MMR-5LEAF-001","MMR-7LEAF-001","C2PA-001","C2PA-NEG-001"}
missing = required - set(ids)
assert not missing, f"missing vectors: {sorted(missing)}"

for v in data["vectors"]:
    if v["component"] == "WormGraph MMR":
        assert v["status"] == "READY", v["id"]
        proofs = v["expected_output"]["proofs"]
        assert len(proofs) == v["input"]["leaf_count"]
        for p in proofs:
            hs=p["inclusion_proof_hashes"]
            ds=p["inclusion_proof_directions"]
            ks=p["inclusion_proof_kinds"]
            assert len(hs)==len(ds)==len(ks)
            assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in hs)
            assert all(x in ("left","right") for x in ds)
            assert all(x in ("node","bag") for x in ks)

print("PASS: static golden-vector contract")
print("vectors:", len(data["vectors"]))
print("mmr_profile:", data["mmr_profile_ref"]["digest_hex"])
