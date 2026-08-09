#!/usr/bin/env python3
"""
evidence_verify.py — reference implementation of `evidence verify`

Verifies AI evidence receipt chains (JSONL) on three levels:
  1. CHAIN     — hash linkage integrity (prev_hash -> entry_hash)
  2. TAMPER    — each entry_hash recomputed from canonical content
  3. INDEPENDENCE — is the chain anchored outside the producing system?

Receipt format (one JSON object per line):
{
  "seq": 1,
  "ts": "2026-08-09T10:00:00Z",
  "event": { ... arbitrary evidence payload ... },
  "prev_hash": "<hex sha256 of previous entry, 64 zeros for genesis>",
  "entry_hash": "<hex sha256 of canonical(seq|ts|event_json|prev_hash)>",
  "anchor": { "type": "external", "provider": "...", "ref": "..." }   # optional
}

Verdict logic:
  - broken linkage or recomputation mismatch  -> CHAIN BROKEN / TAMPERED
  - valid chain, no anchor                    -> SELF-ATTESTED (independence fail)
  - valid chain, anchored                     -> ANCHORED (independence pass)
"""

import hashlib
import json
import sys

GENESIS = "0" * 64


def canonical(seq, ts, event, prev_hash):
    # Deterministic serialization: sorted keys, no whitespace.
    event_json = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return f"{seq}|{ts}|{event_json}|{prev_hash}".encode("utf-8")


def entry_hash(seq, ts, event, prev_hash):
    return hashlib.sha256(canonical(seq, ts, event, prev_hash)).hexdigest()


def verify(path):
    problems = []
    anchored_entries = 0
    entries = []

    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append((lineno, json.loads(line)))
            except json.JSONDecodeError as e:
                problems.append(f"line {lineno}: invalid JSON ({e})")

    if not entries:
        return {"verdict": "EMPTY", "problems": ["no entries found"]}

    prev = GENESIS
    for lineno, e in entries:
        seq, ts = e.get("seq"), e.get("ts")
        ev, ph, eh = e.get("event"), e.get("prev_hash"), e.get("entry_hash")

        if None in (seq, ts, ev, ph, eh):
            problems.append(f"line {lineno}: missing required field")
            continue
        if ph != prev:
            problems.append(
                f"line {lineno}: chain linkage broken "
                f"(prev_hash {ph[:12]}... != expected {prev[:12]}...)"
            )
        recomputed = entry_hash(seq, ts, ev, ph)
        if recomputed != eh:
            problems.append(
                f"line {lineno}: TAMPER DETECTED — entry_hash mismatch "
                f"(stored {eh[:12]}..., recomputed {recomputed[:12]}...)"
            )
        if isinstance(e.get("anchor"), dict) and e["anchor"].get("type") == "external":
            anchored_entries += 1
        prev = eh

    chain_ok = not problems
    result = {
        "entries": len(entries),
        "anchored_entries": anchored_entries,
        "problems": problems,
    }

    if not chain_ok:
        result["verdict"] = "CHAIN BROKEN / TAMPERED"
        result["independence"] = "NOT EVALUATED (fix chain first)"
    elif anchored_entries == 0:
        result["verdict"] = "CHAIN VALID"
        result["independence"] = (
            "SELF-ATTESTED — would not survive independence challenge. "
            "Every hash in this chain was produced and stored by the same "
            "system it describes; a compromised producer can re-sign the "
            "entire chain. No external anchor found."
        )
    else:
        result["verdict"] = "CHAIN VALID"
        result["independence"] = (
            f"ANCHORED — {anchored_entries}/{len(entries)} entries reference "
            "an external anchor. Independence claim is structurally supported "
            "(verify anchor refs against the anchoring provider to complete)."
        )
    return result


def main():
    if len(sys.argv) != 2:
        print("usage: evidence_verify.py <receipts.jsonl>", file=sys.stderr)
        sys.exit(2)
    r = verify(sys.argv[1])
    print(f"entries checked : {r.get('entries', 0)}")
    print(f"chain verdict   : {r['verdict']}")
    for p in r.get("problems", []):
        print(f"  ! {p}")
    if "independence" in r:
        print(f"independence    : {r['independence']}")
    sys.exit(0 if r["verdict"] == "CHAIN VALID" and not r.get("problems") else 1)


if __name__ == "__main__":
    main()
