#!/usr/bin/env python3
"""Generates three sample receipt chains to test evidence_verify.py."""
import json
from evidence_verify import entry_hash, GENESIS

def build_chain(n, anchored=False):
    prev = GENESIS
    lines = []
    for i in range(1, n + 1):
        ts = f"2026-08-09T10:0{i}:00Z"
        event = {
            "model": "claude-fable-5",
            "request_sha256": f"req{i:02d}" + "a" * 58,
            "response_sha256": f"res{i:02d}" + "b" * 58,
            "gateway": "titan-gate",
            "decision": "allow",
        }
        eh = entry_hash(i, ts, event, prev)
        rec = {"seq": i, "ts": ts, "event": event, "prev_hash": prev, "entry_hash": eh}
        if anchored:
            rec["anchor"] = {"type": "external", "provider": "demo-anchor",
                             "ref": f"anchor://batch/2026-08-09/{eh[:16]}"}
        lines.append(json.dumps(rec, sort_keys=True))
        prev = eh
    return lines

# 1. Valid, unanchored (the "self-attested" case — every competitor's log)
open("sample_selfattested.jsonl", "w").write("\n".join(build_chain(5)) + "\n")

# 2. Valid, anchored (your product's output)
open("sample_anchored.jsonl", "w").write("\n".join(build_chain(5, anchored=True)) + "\n")

# 3. Tampered: take the valid chain, silently edit entry 3's event payload
tampered = [json.loads(l) for l in build_chain(5)]
tampered[2]["event"]["decision"] = "block"  # attacker edits history, forgets to re-hash
open("sample_tampered.jsonl", "w").write(
    "\n".join(json.dumps(r, sort_keys=True) for r in tampered) + "\n")

print("wrote sample_selfattested.jsonl, sample_anchored.jsonl, sample_tampered.jsonl")
