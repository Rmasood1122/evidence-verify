#!/usr/bin/env python3
"""
battery.py — 72-test verification battery for evidence-verify + Titan Gate.

Run from the evidence-verify project folder:
    python battery.py
Optionally point at Titan Gate:
    TITAN_DIR=/c/Users/rmaso/Projects/titan-gate-public python battery.py

Statuses:
  PASS  — behaved as a defensible product must
  FAIL  — defect: must be fixed before launch claims
  GAP   — documented limitation: chain verdict correct, but a v0.2 target
  SKIP  — environment lacks the component (e.g. Titan Gate not present)

Sections:
  A 01-12  Core functional correctness
  B 13-26  Adversarial & security
  C 27-38  Robustness & software quality
  D 39-46  Use-case / CI integration
  E 47-56  Spec conformance & interoperability
  F 57-66  Titan Gate (skipped when repo absent)
  G 67-72  Product-claim verification (does the README tell the truth?)
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.join(HERE, "evidence_verify.py")
PY = sys.executable
TITAN = os.environ.get("TITAN_DIR") or os.path.expanduser("~/Projects/titan-gate-public")

sys.path.insert(0, HERE)
try:
    from evidence_verify import entry_hash, GENESIS  # noqa: E402
except Exception as e:
    print(f"cannot import evidence_verify.py from {HERE}: {e}")
    sys.exit(2)

TMP = tempfile.mkdtemp(prefix="battery_")
RESULTS = []


def run(path_or_args):
    args = path_or_args if isinstance(path_or_args, list) else [path_or_args]
    p = subprocess.run([PY, EV] + args, capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout + p.stderr


def chain(n=5, anchored=False, mutate=None):
    """Build a chain; `mutate` edits the list of dicts before writing."""
    prev, recs = GENESIS, []
    for i in range(1, n + 1):
        ts = f"2026-08-09T10:{i:02d}:00Z"
        ev = {"model": "m", "decision": "allow", "request_sha256": "a" * 64}
        eh = entry_hash(i, ts, ev, prev)
        r = {"seq": i, "ts": ts, "event": ev, "prev_hash": prev, "entry_hash": eh}
        if anchored:
            r["anchor"] = {"type": "external", "provider": "demo", "ref": f"a://{eh[:8]}"}
        recs.append(r)
        prev = eh
    if mutate:
        mutate(recs)
    return recs


def write(recs, name, raw=None, encoding="utf-8", newline="\n"):
    p = os.path.join(TMP, name)
    if raw is not None:
        with open(p, "wb") as f:
            f.write(raw)
    else:
        with open(p, "w", encoding=encoding, newline="") as f:
            for r in recs:
                f.write(json.dumps(r, sort_keys=True) + newline)
    return p


def rehash(recs):
    """Recompute all hashes after mutation (the 'motivated producer' attack)."""
    prev = GENESIS
    for r in recs:
        r["prev_hash"] = prev
        r["entry_hash"] = entry_hash(r["seq"], r["ts"], r["event"], prev)
        prev = r["entry_hash"]


def t(num, name, status, note=""):
    RESULTS.append((num, name, status, note))
    mark = {"PASS": "PASS", "FAIL": "FAIL", "GAP": "GAP ", "SKIP": "SKIP"}[status]
    print(f"[{num:02d}] {mark}  {name}" + (f" — {note}" if note else ""))


def expect(num, name, cond, note_pass="", note_fail=""):
    t(num, name, "PASS" if cond else "FAIL", note_pass if cond else note_fail)


# ---------------- A. CORE FUNCTIONAL (1-12) ----------------
def section_a():
    rc, out = run(write(chain(), "a1.jsonl"))
    expect(1, "valid unanchored chain -> VALID + SELF-ATTESTED",
           "CHAIN VALID" in out and "SELF-ATTESTED" in out and rc == 1)

    rc, out = run(write(chain(anchored=True), "a2.jsonl"))
    expect(2, "valid anchored chain -> VALID + ANCHORED, exit 0",
           "ANCHORED" in out and rc == 0)

    def m3(r): r[2]["event"]["decision"] = "block"
    rc, out = run(write(chain(mutate=m3), "a3.jsonl"))
    expect(3, "silent event edit -> TAMPER DETECTED at line 3",
           "TAMPER DETECTED" in out and "line 3" in out)

    def m4(r): r[1]["entry_hash"] = "f" * 64
    rc, out = run(write(chain(mutate=m4), "a4.jsonl"))
    expect(4, "forged entry_hash -> detected", "TAMPER DETECTED" in out or "linkage broken" in out)

    def m5(r): r[3]["prev_hash"] = "e" * 64
    rc, out = run(write(chain(mutate=m5), "a5.jsonl"))
    expect(5, "forged prev_hash mid-chain -> linkage broken", "linkage broken" in out)

    def m6(r): del r[2]
    rc, out = run(write(chain(mutate=m6), "a6.jsonl"))
    expect(6, "deleted middle entry -> linkage broken", "linkage broken" in out)

    def m7(r):
        fake = dict(r[2]); fake["seq"] = 99; fake["event"] = {"model": "evil"}
        r.insert(3, fake)
    rc, out = run(write(chain(mutate=m7), "a7.jsonl"))
    expect(7, "inserted forged entry -> detected", "TAMPER" in out or "linkage broken" in out)

    def m8(r): r[1], r[3] = r[3], r[1]
    rc, out = run(write(chain(mutate=m8), "a8.jsonl"))
    expect(8, "reordered entries -> detected", "linkage broken" in out)

    rc, out = run(write(chain(1), "a9.jsonl"))
    expect(9, "single-entry chain -> VALID", "CHAIN VALID" in out)

    rc, out = run(write([], "a10.jsonl", raw=b""))
    expect(10, "empty file -> EMPTY, nonzero exit", "EMPTY" in out and rc != 0)

    def m11(r):
        for r_ in r[:2]:
            r_["anchor"] = {"type": "external", "provider": "d", "ref": "x"}
    rc, out = run(write(chain(mutate=m11), "a11.jsonl"))
    expect(11, "partially anchored -> ratio reported", "2/5" in out)

    def m12(r): r[0]["prev_hash"] = "1" * 64
    rc, out = run(write(chain(mutate=m12), "a12.jsonl"))
    expect(12, "wrong genesis -> broken", "linkage broken" in out)


# ---------------- B. ADVERSARIAL / SECURITY (13-26) ----------------
def section_b():
    def m13(r):
        r[2]["event"]["decision"] = "block"; rehash(r)
    rc, out = run(write(chain(mutate=m13), "b13.jsonl"))
    ok = "CHAIN VALID" in out and "SELF-ATTESTED" in out
    t(13, "full re-sign attack -> passes chain, flagged SELF-ATTESTED",
      "PASS" if ok else "FAIL",
      "the category thesis in one test: hash chains cannot stop a motivated producer" if ok else "")

    rc, out = run(write(chain()[:3], "b14.jsonl"))
    ok = "CHAIN VALID" in out
    t(14, "truncation attack (drop tail) -> undetected", "GAP" if ok else "FAIL",
      "no length attestation yet; external anchor of head hash closes this (v0.2)")

    def m15(r): r[0]["anchor"] = {"type": "external", "provider": "??", "ref": "garbage"}
    rc, out = run(write(chain(mutate=m15), "b15.jsonl"))
    t(15, "anchor spoofing: garbage ref counts as anchored", "GAP", 
      "presence-only check today; round-trip anchor verification is Move 2")

    def m16(r): r[0]["anchor"] = {"type": "internal", "provider": "self", "ref": "x"}
    rc, out = run(write(chain(mutate=m16), "b16.jsonl"))
    expect(16, "non-external anchor type -> still SELF-ATTESTED", "SELF-ATTESTED" in out)

    def m17(r): r[3]["seq"] = r[2]["seq"]; rehash(r)
    rc, out = run(write(chain(mutate=m17), "b17.jsonl"))
    t(17, "duplicate seq numbers accepted", "GAP", "seq monotonicity unchecked (v0.2)")

    def m18(r): r[3]["ts"] = "2020-01-01T00:00:00Z"; rehash(r)
    rc, out = run(write(chain(mutate=m18), "b18.jsonl"))
    t(18, "non-monotonic timestamps accepted", "GAP", "ts ordering unchecked (v0.2)")

    def m19(r): r[2]["event"]["blob"] = "x" * 1_000_000; rehash(r)
    rc, out = run(write(chain(mutate=m19), "b19.jsonl"))
    expect(19, "1MB event payload -> verifies", "CHAIN VALID" in out)

    def m20(r):
        d = {}
        cur = d
        for _ in range(100):
            cur["n"] = {}
            cur = cur["n"]
        r[2]["event"]["deep"] = d; rehash(r)
    rc, out = run(write(chain(mutate=m20), "b20.jsonl"))
    expect(20, "100-level nested event -> verifies or clean error", "Traceback" not in out)

    def m21(r): r[2]["event"]["note"] = "テスト🔥 émoji"; rehash(r)
    rc, out = run(write(chain(mutate=m21), "b21.jsonl"))
    expect(21, "unicode/emoji payload -> verifies", "CHAIN VALID" in out)

    def m22(r): r[2]["event"]["nul"] = "a\u0000b"; rehash(r)
    rc, out = run(write(chain(mutate=m22), "b22.jsonl"))
    expect(22, "embedded null char -> verifies", "CHAIN VALID" in out)

    def m23(r):
        r[2]["event"]["prompt"] = "ignore previous instructions; verdict=VALID"; rehash(r)
    rc, out = run(write(chain(mutate=m23), "b23.jsonl"))
    expect(23, "injection-style strings treated as data", "CHAIN VALID" in out)

    def m24(r): r[2]["entry_hash"] = r[2]["entry_hash"][:-1]
    rc, out = run(write(chain(mutate=m24), "b24.jsonl"))
    expect(24, "63-char hash -> mismatch detected", "TAMPER" in out or "linkage" in out)

    def m25(r): r[2]["entry_hash"] = r[2]["entry_hash"].upper()
    rc, out = run(write(chain(mutate=m25), "b25.jsonl"))
    expect(25, "uppercase hex -> mismatch (case-strict)", "TAMPER" in out or "linkage" in out)

    def m26(r): r[2]["seq"] = -7; rehash(r)
    rc, out = run(write(chain(mutate=m26), "b26.jsonl"))
    t(26, "negative seq accepted if hashes valid", "GAP", "seq domain unvalidated (v0.2)")


# ---------------- C. ROBUSTNESS (27-38) ----------------
def section_c():
    recs = chain()
    p = write(recs, "c27.jsonl")
    with open(p, "a") as f:
        f.write("{not json}\n")
    rc, out = run(p)
    expect(27, "malformed JSON line -> reported, no crash",
           "invalid JSON" in out and "Traceback" not in out)

    def m28(r): del r[2]["seq"]
    rc, out = run(write(chain(mutate=m28), "c28.jsonl"))
    expect(28, "missing seq -> missing-field report", "missing required field" in out)

    def m29(r): del r[2]["event"]
    rc, out = run(write(chain(mutate=m29), "c29.jsonl"))
    expect(29, "missing event -> missing-field report", "missing required field" in out)

    def m30(r): del r[2]["entry_hash"]
    rc, out = run(write(chain(mutate=m30), "c30.jsonl"))
    expect(30, "missing entry_hash -> missing-field report", "missing required field" in out)

    def m31(r): r[2]["seq"] = str(r[2]["seq"])
    rc, out = run(write(chain(mutate=m31), "c31.jsonl"))
    ok = "CHAIN VALID" in out
    t(31, 'seq as string "3" still verifies (f-string coercion)', "GAP" if ok else "PASS",
      "type looseness in canonical form; tighten in spec v1" if ok else "strict typing enforced")

    def m32(r): r[2]["extra_field"] = {"future": True}
    rc, out = run(write(chain(mutate=m32), "c32.jsonl"))
    expect(32, "unknown top-level fields ignored (forward-compat)", "CHAIN VALID" in out)

    recs = chain()
    p = os.path.join(TMP, "c33.jsonl")
    with open(p, "w") as f:
        for i, r in enumerate(recs):
            f.write(json.dumps(r, sort_keys=True) + "\n")
            if i == 2:
                f.write("\n\n")
    rc, out = run(p)
    expect(33, "blank lines interspersed -> skipped", "CHAIN VALID" in out)

    body = "".join(json.dumps(r, sort_keys=True) + "\r\n" for r in chain())
    rc, out = run(write(None, "c34.jsonl", raw=body.encode()))
    expect(34, "CRLF (Windows) line endings -> verifies", "CHAIN VALID" in out,
           note_pass="critical for your git CRLF-converted files")

    body = "".join(json.dumps(r, sort_keys=True) + "\n" for r in chain())
    rc, out = run(write(None, "c35.jsonl", raw=b"\xef\xbb\xbf" + body.encode()))
    ok = "Traceback" not in out
    t(35, "UTF-8 BOM at file start", "PASS" if ok and "CHAIN VALID" in out else ("GAP" if ok else "FAIL"),
      "" if "CHAIN VALID" in out else "BOM breaks first-line parse; strip BOM in v0.2 (real Windows risk)")

    body = "".join(json.dumps(r, sort_keys=True) + "   \n" for r in chain())
    rc, out = run(write(None, "c36.jsonl", raw=body.encode()))
    expect(36, "trailing whitespace -> verifies", "CHAIN VALID" in out)

    p = subprocess.run([PY, EV, TMP], capture_output=True, text=True)
    ok = "Traceback" not in (p.stdout + p.stderr)
    t(37, "path is a directory -> graceful error", "PASS" if ok else "FAIL",
      "" if ok else "uncaught exception; wrap open() in try/except")

    p = subprocess.run([PY, EV, os.path.join(TMP, "nope.jsonl")], capture_output=True, text=True)
    ok = "Traceback" not in (p.stdout + p.stderr)
    t(38, "nonexistent file -> graceful error", "PASS" if ok else "FAIL",
      "" if ok else "uncaught FileNotFoundError; wrap open() in try/except")


# ---------------- D. USE-CASE / CI (39-46) ----------------
def section_d():
    rc, _ = run(write(chain(anchored=True), "d39.jsonl"))
    expect(39, "exit 0 iff anchored+valid (CI-gateable)", rc == 0)
    rc, _ = run(write(chain(), "d40.jsonl"))
    expect(40, "exit 1 for self-attested", rc == 1)

    def m41(r): r[2]["event"]["x"] = 1
    rc, _ = run(write(chain(mutate=m41), "d41.jsonl"))
    expect(41, "exit 1 for tampered", rc == 1)

    p = subprocess.run([PY, EV], capture_output=True, text=True)
    expect(42, "exit 2 + usage on no args", p.returncode == 2 and "usage" in p.stderr)

    _, out = run(write(chain(), "d43.jsonl"))
    expect(43, "output machine-greppable ('chain verdict')", "chain verdict" in out)

    f = write(chain(), "d44.jsonl")
    _, o1 = run(f); _, o2 = run(f)
    expect(44, "deterministic output across runs", o1 == o2)

    f = write(chain(1000), "d45.jsonl")
    t0 = time.time(); run(f); dt = time.time() - t0
    expect(45, f"1,000 entries in {dt:.2f}s (<2s)", dt < 2.0)

    f = write(chain(10000), "d46.jsonl")
    rc, out = run(f)
    expect(46, "10,000 entries -> completes, VALID", "CHAIN VALID" in out)


# ---------------- E. SPEC CONFORMANCE (47-56) ----------------
def section_e():
    recs = chain()
    p = os.path.join(TMP, "e47.jsonl")
    with open(p, "w") as f:
        for r in recs:
            keys = list(r.keys())[::-1]
            f.write("{" + ",".join(json.dumps(k) + ":" + json.dumps(r[k], sort_keys=True)
                                   for k in keys) + "}\n")
    rc, out = run(p)
    expect(47, "key order in file irrelevant (canonical sorts)", "CHAIN VALID" in out)

    p = os.path.join(TMP, "e48.jsonl")
    with open(p, "w") as f:
        for r in chain():
            f.write(json.dumps(r, sort_keys=True, indent=None, separators=(", ", ": ")) + "\n")
    rc, out = run(p)
    expect(48, "whitespace in stored JSON irrelevant", "CHAIN VALID" in out)

    def m49(r): r[2]["event"]["score"] = 1.5; rehash(r)
    rc, out = run(write(chain(mutate=m49), "e49.jsonl"))
    expect(49, "float values verify", "CHAIN VALID" in out)

    ev1 = {"v": 1}; ev2 = {"v": 1.0}
    c1 = json.dumps(ev1, sort_keys=True, separators=(",", ":"))
    c2 = json.dumps(ev2, sort_keys=True, separators=(",", ":"))
    expect(50, "spec strictness: 1 vs 1.0 canonically distinct", c1 != c2,
           note_pass="int/float are different evidence; producers must be consistent")

    def m51(r): r[2]["event"]["name"] = "café"; rehash(r)
    rc, out = run(write(chain(mutate=m51), "e51.jsonl"))
    expect(51, "non-ASCII literal in file verifies", "CHAIN VALID" in out)

    def m52(r): r[2]["event"]["arr"] = [3, 1, 2]; rehash(r)
    rc, out = run(write(chain(mutate=m52), "e52.jsonl"))
    expect(52, "array order preserved (not sorted)", "CHAIN VALID" in out)

    def m53(r): r[2]["event"]["ok"] = True; r[2]["event"]["none"] = None; rehash(r)
    rc, out = run(write(chain(mutate=m53), "e53.jsonl"))
    expect(53, "booleans and null verify", "CHAIN VALID" in out)

    def m54(r): r[2]["event"] = {}; rehash(r)
    rc, out = run(write(chain(mutate=m54), "e54.jsonl"))
    expect(54, "empty event object verifies", "CHAIN VALID" in out)

    expect(55, "genesis constant = 64 zeros", GENESIS == "0" * 64)

    r = chain(1)[0]
    canon = json.dumps(r["event"], sort_keys=True, separators=(",", ":"))
    payload = f'{r["seq"]}|{r["ts"]}|{canon}|{r["prev_hash"]}'.encode()
    independent = hashlib.sha256(payload).hexdigest()
    expect(56, "independent re-implementation reproduces hash",
           independent == r["entry_hash"],
           note_pass="the spec is implementable without our code — open-standard claim holds")


# ---------------- F. TITAN GATE (57-66) ----------------
def section_f():
    if not os.path.isdir(TITAN):
        for n, name in [(57, "titan-gate-public repo present"),
                        (58, "examples/TV1.json present"),
                        (59, "titan/verify.py present"),
                        (60, "TV1 verifies with documented zero key"),
                        (61, "TV2 verifies"), (62, "TV3 verifies"),
                        (63, "tampered TV1 -> verification FAILS"),
                        (64, "wrong key -> verification FAILS"),
                        (65, "pip package titan-gate importable"),
                        (66, "README independence-language review")]:
            t(n, name, "SKIP", f"set TITAN_DIR or place repo at {TITAN}")
        return

    t(57, "titan-gate-public repo present", "PASS", TITAN)
    tv1 = os.path.join(TITAN, "examples", "TV1.json")
    vfy = os.path.join(TITAN, "titan", "verify.py")
    expect(58, "examples/TV1.json present", os.path.isfile(tv1))
    expect(59, "titan/verify.py present", os.path.isfile(vfy))

    ZK = "0" * 64
    def tverify(path, key=ZK):
        p = subprocess.run([PY, vfy, path, "--key", key],
                           capture_output=True, text=True, timeout=60, cwd=TITAN)
        return p.returncode, p.stdout + p.stderr

    if os.path.isfile(tv1) and os.path.isfile(vfy):
        rc, out = tverify(tv1)
        expect(60, "TV1 verifies with documented zero key", rc == 0 and "PASS" in out.upper())
        for num, tvname in [(61, "TV2.json"), (62, "TV3.json")]:
            tvp = os.path.join(TITAN, "examples", tvname)
            if os.path.isfile(tvp):
                rc, out = tverify(tvp)
                expect(num, f"{tvname} verifies", rc == 0)
            else:
                t(num, f"{tvname} verifies", "SKIP", "file absent")

        try:
            with open(tv1) as f:
                doc = json.load(f)
            # flip one character somewhere in the payload
            s = json.dumps(doc)
            s2 = s.replace("PASS", "FAIL", 1) if "PASS" in s else s[:-2] + "X" + s[-2:]
            tp = os.path.join(TMP, "TV1_tampered.json")
            with open(tp, "w") as f:
                f.write(s2)
            rc, out = tverify(tp)
            expect(63, "tampered TV1 -> verification FAILS", rc != 0 or "FAIL" in out.upper(),
                   note_fail="CRITICAL: tampering not detected by titan-verify")
        except Exception as e:
            t(63, "tampered TV1 -> verification FAILS", "SKIP", f"could not build tamper case: {e}")

        rc, out = tverify(tv1, key="1" * 64)
        expect(64, "wrong key -> verification FAILS", rc != 0 or "FAIL" in out.upper() or "INVALID" in out.upper())
    else:
        for n in (60, 61, 62, 63, 64):
            t(n, "titan verify tests", "SKIP", "verify.py or TV1 missing")

    p = subprocess.run([PY, "-c", "import titan"], capture_output=True, text=True)
    t(65, "pip package importable (import titan)", "PASS" if p.returncode == 0 else "SKIP",
      "" if p.returncode == 0 else "not installed in this python; try: pip install titan-gate")

    readme = os.path.join(TITAN, "README.md")
    if os.path.isfile(readme):
        txt = open(readme, encoding="utf-8", errors="replace").read().lower()
        flag = "no trusted third party" in txt
        t(66, "README independence-language review", "GAP" if flag else "PASS",
          "README touts 'no trusted third party' — strategically inverted vs the "
          "evidence-verify thesis (independence NEEDS an external anchor); align messaging"
          if flag else "no conflicting independence language found")
    else:
        t(66, "README independence-language review", "SKIP", "README.md not found")


# ---------------- G. PRODUCT-CLAIM VERIFICATION (67-72) ----------------
def section_g():
    src = open(EV, encoding="utf-8").read()
    import ast
    tree = ast.parse(src)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    # Every module the standard library ships, so a lazy stdlib import (urllib in
    # load_anchor) is not reported as a dependency. A third-party import still fails.
    stdlib = set(sys.stdlib_module_names)
    expect(67, "zero-dependency claim true (stdlib only)", imports <= stdlib,
           note_pass=f"imports: {sorted(imports)}",
           note_fail=f"non-stdlib imports found: {sorted(imports - stdlib)}")

    lic = any(os.path.isfile(os.path.join(HERE, n)) for n in ("LICENSE", "LICENSE.md", "LICENSE.txt"))
    expect(68, "LICENSE file exists (README claims Apache-2.0)", lic,
           note_fail="README promises Apache-2.0 but no LICENSE file is in the repo — add it")

    readme = os.path.join(HERE, "README.md")
    txt = open(readme, encoding="utf-8", errors="replace").read() if os.path.isfile(readme) else ""
    expect(69, "README documents receipt format", '"prev_hash"' in txt and '"entry_hash"' in txt)
    expect(70, "README timeline corrected (December 2, 2027)", "December 2, 2027" in txt,
           note_fail="README still carries the pre-Omnibus deadline")

    ms = os.path.join(HERE, "make_samples.py")
    if os.path.isfile(ms):
        d1, d2 = os.path.join(TMP, "g71a"), os.path.join(TMP, "g71b")
        for d in (d1, d2):
            os.makedirs(d, exist_ok=True)
            subprocess.run([PY, ms], cwd=d, capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": HERE})
        f1 = os.path.join(d1, "sample_selfattested.jsonl")
        f2 = os.path.join(d2, "sample_selfattested.jsonl")
        same = (os.path.isfile(f1) and os.path.isfile(f2)
                and open(f1, "rb").read() == open(f2, "rb").read())
        expect(71, "sample generation deterministic", same)
    else:
        t(71, "sample generation deterministic", "SKIP", "make_samples.py absent")

    rc, out = run(write(chain(7, anchored=True), "g72.jsonl"))
    expect(72, "round-trip: generate -> verify -> VALID+ANCHORED",
           rc == 0 and "ANCHORED" in out)


def main():
    print(f"evidence-verify battery — 72 tests\ntarget: {EV}\ntitan:  {TITAN}\n")
    for s in (section_a, section_b, section_c, section_d, section_e, section_f, section_g):
        print()
        s()
    counts = {}
    for _, _, st, _ in RESULTS:
        counts[st] = counts.get(st, 0) + 1
    print("\n" + "=" * 60)
    print(f"TOTAL {len(RESULTS)} | PASS {counts.get('PASS',0)} | "
          f"FAIL {counts.get('FAIL',0)} | GAP {counts.get('GAP',0)} | SKIP {counts.get('SKIP',0)}")
    print("=" * 60)
    shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(1 if counts.get("FAIL") else 0)


if __name__ == "__main__":
    main()
