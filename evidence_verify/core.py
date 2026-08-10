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

    try:
        f = open(path)
    except OSError as e:
        print(f"error: cannot read {path}: {e.strerror or e}", file=sys.stderr)
        sys.exit(2)
    with f:
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



# ---------------- v0.2: external anchor round-trip ----------------

def make_anchor(path):
    """Read a chain, emit a detached anchor record for external storage."""
    r = verify(path)
    if r.get("problems") or r["verdict"] != "CHAIN VALID":
        print("refusing to anchor: chain is not valid", file=sys.stderr)
        for p in r.get("problems", []):
            print(f"  ! {p}", file=sys.stderr)
        sys.exit(1)
    head = None
    count = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            count += 1
            head = json.loads(line)["entry_hash"]
    anchor = {
        "anchor_version": "0.2",
        "head_hash": head,
        "entry_count": count,
        "note": "Store this record OUTSIDE the producing system "
                "(separate repo, gist, S3 bucket, timestamping service). "
                "Independence comes from where this lives, not from this file itself.",
    }
    print(json.dumps(anchor, indent=2, sort_keys=True))


def load_anchor(ref):
    """Load an anchor record from a local file or an http(s) URL."""
    if ref.startswith("http://") or ref.startswith("https://"):
        import urllib.request
        with urllib.request.urlopen(ref, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    with open(ref) as f:
        return json.load(f)


def verify_with_anchor(path, anchor_ref):
    r = verify(path)
    print(f"entries checked : {r.get('entries', 0)}")
    print(f"chain verdict   : {r['verdict']}")
    for p in r.get("problems", []):
        print(f"  ! {p}")
    if r["verdict"] != "CHAIN VALID" or r.get("problems"):
        print("independence    : NOT EVALUATED (fix chain first)")
        sys.exit(1)
    try:
        a = load_anchor(anchor_ref)
    except Exception as e:
        print(f"independence    : ANCHOR UNREADABLE ({e})")
        sys.exit(1)
    head = None
    count = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            count += 1
            head = json.loads(line)["entry_hash"]
    ok_head = a.get("head_hash") == head
    ok_count = a.get("entry_count") == count
    if ok_head and ok_count:
        print("independence    : ANCHOR ROUND-TRIP VERIFIED — head hash and entry")
        print(f"                  count match the external anchor ({count} entries).")
        print("                  Truncation and rewrite are excluded IF the anchor")
        print("                  is stored outside the producing system.")
        sys.exit(0)
    if not ok_head:
        print("independence    : ANCHOR MISMATCH — chain head does not match anchor.")
        print(f"                  anchor head : {str(a.get('head_hash'))[:16]}...")
        print(f"                  chain head  : {str(head)[:16]}...")
        print("                  History was rewritten or the wrong anchor was supplied.")
    if not ok_count:
        print(f"independence    : COUNT MISMATCH — anchor says {a.get('entry_count')}")
        print(f"                  entries, chain has {count}. Possible truncation.")
    sys.exit(1)


def main():
    args = sys.argv[1:]
    if len(args) == 1 and args[0] not in ("anchor", "verify"):
        args = ["verify", args[0]]  # backward compatible: evidence_verify.py file.jsonl
    if len(args) == 2 and args[0] == "anchor":
        make_anchor(args[1]); return
    if len(args) == 2 and args[0] == "verify":
        r = verify(args[1])
        print(f"entries checked : {r.get('entries', 0)}")
        print(f"chain verdict   : {r['verdict']}")
        for p in r.get("problems", []):
            print(f"  ! {p}")
        if "independence" in r:
            print(f"independence    : {r['independence']}")
        anchored_ok = (r["verdict"] == "CHAIN VALID" and not r.get("problems")
                       and r.get("anchored_entries", 0) > 0)
        sys.exit(0 if anchored_ok else 1)
    if len(args) == 4 and args[0] == "verify" and args[2] == "--anchor":
        verify_with_anchor(args[1], args[3]); return
    print("usage: evidence_verify.py verify <receipts.jsonl> [--anchor <file-or-url>]",
          file=sys.stderr)
    print("       evidence_verify.py anchor <receipts.jsonl>   (prints anchor record)",
          file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
