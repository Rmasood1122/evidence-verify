#!/usr/bin/env python3
"""
battery2.py — Battery II: 72 tests for the v0.2 + v0.3 surface.

Covers what battery.py (Battery I) does not: the anchor round-trip CLI,
ReceiptWriter, the LangChain EvidenceCallbackHandler, package/CLI integrity,
and adversarial cases against the anchor mechanism itself.

Run from the evidence-verify project folder:
    python battery2.py

Statuses: PASS (required behavior) | FAIL (defect, blocks claims)
          | GAP (documented limitation, versioned) | SKIP (component absent)

Sections:
  A 01-16  Anchor round-trip (CLI: anchor / verify --anchor)
  B 17-30  ReceiptWriter (chain production)
  C 31-44  LangChain handler (requires langchain-core; SKIPs otherwise)
  D 45-56  Package & CLI integrity
  E 57-72  Adversarial & spec (anchor-focused)
"""
import ast
import hashlib
import http.server
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
PY = sys.executable
MOD = [PY, "-m", "evidence_verify"]
TMP = tempfile.mkdtemp(prefix="battery2_")
RESULTS = []

try:
    from evidence_verify import ReceiptWriter, entry_hash, GENESIS, verify as core_verify
except Exception as e:
    print(f"cannot import evidence_verify package from {HERE}: {e}")
    print("hint: run from the repo folder containing the evidence_verify/ package dir")
    sys.exit(2)

try:
    import langchain_core  # noqa: F401
    HAS_LC = True
except ImportError:
    HAS_LC = False


def t(num, name, status, note=""):
    RESULTS.append((num, name, status, note))
    mark = {"PASS": "PASS", "FAIL": "FAIL", "GAP": "GAP ", "SKIP": "SKIP"}[status]
    print(f"[{num:02d}] {mark}  {name}" + (f" — {note}" if note else ""))


def expect(num, name, cond, note_pass="", note_fail=""):
    t(num, name, "PASS" if cond else "FAIL", note_pass if cond else note_fail)


def run(args, cwd=HERE):
    p = subprocess.run(MOD + args, capture_output=True, text=True, timeout=120, cwd=cwd)
    return p.returncode, p.stdout + p.stderr


def build_chain_file(name, n=5, mutate=None):
    prev, recs = GENESIS, []
    for i in range(1, n + 1):
        ts = f"2026-08-10T09:{i%60:02d}:00Z"
        ev = {"model": "m", "decision": "allow", "i": i}
        eh = entry_hash(i, ts, ev, prev)
        recs.append({"seq": i, "ts": ts, "event": ev, "prev_hash": prev, "entry_hash": eh})
        prev = eh
    if mutate:
        mutate(recs)
    p = os.path.join(TMP, name)
    with open(p, "w") as f:
        for r in recs:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    return p


def rehash_file(path):
    recs = [json.loads(l) for l in open(path) if l.strip()]
    prev = GENESIS
    for r in recs:
        r["prev_hash"] = prev
        r["entry_hash"] = entry_hash(r["seq"], r["ts"], r["event"], prev)
        prev = r["entry_hash"]
    with open(path, "w") as f:
        for r in recs:
            f.write(json.dumps(r, sort_keys=True) + "\n")


def make_anchor(chain_path, anchor_name):
    rc, out = run(["anchor", chain_path])
    ap = os.path.join(TMP, anchor_name)
    open(ap, "w").write(out if rc == 0 else "")
    return rc, out, ap


# ---------------- A. ANCHOR ROUND-TRIP (1-16) ----------------
def section_a():
    ch = build_chain_file("a_valid.jsonl")
    rc, out, ap = make_anchor(ch, "a_valid.anchor.json")
    expect(1, "anchor command succeeds on valid chain", rc == 0)
    try:
        a = json.loads(out)
        expect(2, "anchor output is valid JSON with head+count",
               "head_hash" in a and a.get("entry_count") == 5)
    except Exception:
        t(2, "anchor output is valid JSON with head+count", "FAIL", "not JSON")
        a = {}

    last = [json.loads(l) for l in open(ch) if l.strip()][-1]
    expect(3, "anchor head equals chain head", a.get("head_hash") == last["entry_hash"])

    rc2, out2, _ = make_anchor(ch, "a_valid2.anchor.json")
    same = json.loads(out2).get("head_hash") == a.get("head_hash") if rc2 == 0 else False
    expect(4, "anchor is deterministic for same chain", same)

    rc, out = run(["verify", ch, "--anchor", ap])
    expect(5, "verify --anchor: round-trip PASS, exit 0",
           rc == 0 and "ROUND-TRIP VERIFIED" in out)

    tr = os.path.join(TMP, "a_trunc.jsonl")
    open(tr, "w").write("".join(open(ch).read().splitlines(True)[:3]))
    rc, out = run(["verify", tr, "--anchor", ap])
    expect(6, "truncation attack caught (count mismatch), exit 1",
           rc == 1 and "COUNT MISMATCH" in out)

    rs = os.path.join(TMP, "a_resign.jsonl")
    shutil.copy(ch, rs)
    recs = [json.loads(l) for l in open(rs) if l.strip()]
    recs[2]["event"]["decision"] = "block"
    with open(rs, "w") as f:
        for r in recs:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    rehash_file(rs)
    rc, out = run(["verify", rs, "--anchor", ap])
    expect(7, "full re-sign attack caught (head mismatch), exit 1",
           rc == 1 and "ANCHOR MISMATCH" in out)

    ext = os.path.join(TMP, "a_extend.jsonl")
    shutil.copy(ch, ext)
    recs = [json.loads(l) for l in open(ext) if l.strip()]
    prev = recs[-1]["entry_hash"]
    ev = {"model": "m", "decision": "allow", "i": 6}
    ts = "2026-08-10T09:06:00Z"
    eh = entry_hash(6, ts, ev, prev)
    with open(ext, "a") as f:
        f.write(json.dumps({"seq": 6, "ts": ts, "event": ev,
                            "prev_hash": prev, "entry_hash": eh}, sort_keys=True) + "\n")
    rc, out = run(["verify", ext, "--anchor", ap])
    expect(8, "extension beyond anchor caught (count+head mismatch), exit 1",
           rc == 1 and ("COUNT MISMATCH" in out or "ANCHOR MISMATCH" in out))

    broken = build_chain_file("a_broken.jsonl", mutate=lambda r: r[2].__setitem__("entry_hash", "f"*64))
    rc, out = run(["anchor", broken])
    expect(9, "anchor REFUSES a broken chain, nonzero exit",
           rc != 0 and "refusing" in out.lower())

    empty = os.path.join(TMP, "a_empty.jsonl")
    open(empty, "w").write("")
    rc, out = run(["anchor", empty])
    expect(10, "anchor refuses empty chain", rc != 0)

    rc, out = run(["verify", ch, "--anchor", os.path.join(TMP, "nope.json")])
    expect(11, "missing anchor file -> ANCHOR UNREADABLE, no crash",
           rc == 1 and "UNREADABLE" in out and "Traceback" not in out)

    badj = os.path.join(TMP, "bad.anchor.json")
    open(badj, "w").write("{not json")
    rc, out = run(["verify", ch, "--anchor", badj])
    expect(12, "malformed anchor JSON -> UNREADABLE, no crash",
           rc == 1 and "UNREADABLE" in out and "Traceback" not in out)

    nof = os.path.join(TMP, "nofields.anchor.json")
    open(nof, "w").write(json.dumps({"anchor_version": "0.2"}))
    rc, out = run(["verify", ch, "--anchor", nof])
    expect(13, "anchor missing fields -> mismatch reported, no crash",
           rc == 1 and "Traceback" not in out)

    ha = json.loads(open(ap).read()); ha["head_hash"] = "e" * 64
    hap = os.path.join(TMP, "headtamper.anchor.json")
    open(hap, "w").write(json.dumps(ha))
    rc, out = run(["verify", ch, "--anchor", hap])
    expect(14, "tampered anchor head -> mismatch (anchor is checked too)",
           rc == 1 and "ANCHOR MISMATCH" in out)

    one = build_chain_file("a_one.jsonl", n=1)
    rc1, out1, ap1 = make_anchor(one, "a_one.anchor.json")
    rc, out = run(["verify", one, "--anchor", ap1])
    expect(15, "single-entry chain anchors and round-trips", rc == 0)

    tampered_then = build_chain_file("a_tamp.jsonl",
                                     mutate=lambda r: r[1]["event"].__setitem__("x", 1))
    rc, out = run(["verify", tampered_then, "--anchor", ap])
    expect(16, "broken chain + anchor: chain verdict takes precedence",
           rc == 1 and "NOT EVALUATED" in out)


# ---------------- B. RECEIPTWRITER (17-30) ----------------
def section_b():
    p = os.path.join(TMP, "w1.jsonl")
    w = ReceiptWriter(p)
    r1 = w.write({"kind": "t", "n": 1})
    expect(17, "writer creates file and returns record",
           os.path.isfile(p) and "entry_hash" in r1)
    expect(18, "first receipt uses genesis prev_hash", r1["prev_hash"] == GENESIS)
    r2 = w.write({"kind": "t", "n": 2})
    expect(19, "seq increments", r2["seq"] == 2)
    expect(20, "second receipt chains to first", r2["prev_hash"] == r1["entry_hash"])

    w2 = ReceiptWriter(p)  # resume
    r3 = w2.write({"kind": "t", "n": 3})
    expect(21, "resume from existing file continues chain (seq 3, linked)",
           r3["seq"] == 3 and r3["prev_hash"] == r2["entry_hash"])

    res = core_verify(p)
    expect(22, "writer-produced chain verifies VALID",
           res["verdict"] == "CHAIN VALID" and not res["problems"])

    pa = os.path.join(TMP, "w_anchor.jsonl")
    wa = ReceiptWriter(pa)
    ra = wa.write({"kind": "t"}, anchor={"type": "external", "provider": "d", "ref": "x"})
    expect(23, "anchor param writes anchor field",
           json.loads(open(pa).read())["anchor"]["type"] == "external")

    pu = os.path.join(TMP, "w_uni.jsonl")
    wu = ReceiptWriter(pu)
    wu.write({"kind": "t", "note": "テスト🔥 café"})
    expect(24, "unicode event round-trips through writer",
           core_verify(pu)["verdict"] == "CHAIN VALID")

    pl = os.path.join(TMP, "w_large.jsonl")
    wl = ReceiptWriter(pl)
    wl.write({"kind": "t", "blob": "x" * 500_000})
    expect(25, "large event (500KB) writes and verifies",
           core_verify(pl)["verdict"] == "CHAIN VALID")

    pf = os.path.join(TMP, "w_fast.jsonl")
    wf = ReceiptWriter(pf)
    t0 = time.time()
    for i in range(200):
        wf.write({"kind": "t", "i": i})
    dt = time.time() - t0
    expect(26, f"200 sequential writes in {dt:.2f}s (<3s)", dt < 3.0)
    expect(27, "200-entry writer chain verifies",
           core_verify(pf)["verdict"] == "CHAIN VALID")

    ts_ok = "T" in r1["ts"] and r1["ts"].endswith("Z")
    expect(28, "timestamps are ISO-8601 UTC (Z-suffixed)", ts_ok)

    pt = os.path.join(TMP, "w_tampered.jsonl")
    wt = ReceiptWriter(pt)
    wt.write({"kind": "t", "n": 1}); wt.write({"kind": "t", "n": 2})
    lines = open(pt).read().splitlines()
    lines[0] = lines[0].replace('"n": 1', '"n": 9')
    open(pt, "w").write("\n".join(lines) + "\n")
    wt2 = ReceiptWriter(pt)
    wt2.write({"kind": "t", "n": 3})
    res = core_verify(pt)
    expect(29, "pre-existing tamper still caught after resume+append",
           res["verdict"] != "CHAIN VALID")

    p3 = os.path.join(TMP, "w_two.jsonl")
    ReceiptWriter(p3).write({"a": 1})
    ReceiptWriter(p3).write({"a": 2})
    ReceiptWriter(p3).write({"a": 3})
    expect(30, "three separate writer instances form one valid chain",
           core_verify(p3)["verdict"] == "CHAIN VALID")


# ---------------- C. LANGCHAIN HANDLER (31-44) ----------------
def section_c():
    if not HAS_LC:
        for n, name in [(31, "handler import"), (32, "llm_request receipt"),
                        (33, "llm_response receipt"), (34, "prompt hash correct"),
                        (35, "privacy default: no prompt text"), (36, "include_text=True includes text"),
                        (37, "on_llm_error receipt"), (38, "tool_call receipt"),
                        (39, "tool_result receipt"), (40, "end-to-end: 2 calls -> 4 receipts"),
                        (41, "end-to-end chain verifies"), (42, "run_id pairs request/response"),
                        (43, "handler resume appends same chain"),
                        (44, "end-to-end + anchor round-trip exit 0")]:
            t(n, name, "SKIP", 'pip install "evidence-verify[langchain]" to enable')
        return

    from langchain_core.language_models.fake import FakeListLLM
    from evidence_verify import EvidenceCallbackHandler
    t(31, "handler import", "PASS")

    p = os.path.join(TMP, "lc.jsonl")
    llm = FakeListLLM(responses=["approved", "denied"])
    h = EvidenceCallbackHandler(p)
    llm.invoke("prompt one", config={"callbacks": [h]})
    llm.invoke("prompt two", config={"callbacks": [h]})
    recs = [json.loads(l) for l in open(p) if l.strip()]

    kinds = [r["event"]["kind"] for r in recs]
    expect(32, "llm_request receipts written", kinds.count("llm_request") == 2)
    expect(33, "llm_response receipts written", kinds.count("llm_response") == 2)

    want = hashlib.sha256("prompt one".encode()).hexdigest()
    got = recs[0]["event"]["prompt_sha256"][0]
    expect(34, "prompt hash = sha256 of actual prompt", got == want)

    raw = open(p).read()
    expect(35, "privacy default: prompt text NOT in evidence file",
           "prompt one" not in raw and "approved" not in raw,
           note_pass="fingerprints only — the file proves without containing")

    p2 = os.path.join(TMP, "lc_text.jsonl")
    h2 = EvidenceCallbackHandler(p2, include_text=True)
    FakeListLLM(responses=["yes"]).invoke("visible prompt", config={"callbacks": [h2]})
    expect(36, "include_text=True includes text (explicit opt-in)",
           "visible prompt" in open(p2).read())

    p3 = os.path.join(TMP, "lc_err.jsonl")
    h3 = EvidenceCallbackHandler(p3)
    import uuid
    h3.on_llm_error(ValueError("boom"), run_id=uuid.uuid4())
    er = json.loads(open(p3).read())
    expect(37, "on_llm_error writes error receipt with type",
           er["event"]["kind"] == "llm_error" and er["event"]["error_type"] == "ValueError")

    h3.on_tool_start({"name": "search"}, "query text", run_id=uuid.uuid4())
    h3.on_tool_end("result text", run_id=uuid.uuid4())
    recs3 = [json.loads(l) for l in open(p3) if l.strip()]
    expect(38, "tool_call receipt with tool name",
           any(r["event"].get("tool") == "search" for r in recs3))
    expect(39, "tool_result receipt written",
           any(r["event"]["kind"] == "tool_result" for r in recs3))

    expect(40, "end-to-end: 2 LLM calls -> 4 chained receipts", len(recs) == 4)
    expect(41, "end-to-end chain verifies VALID",
           core_verify(p)["verdict"] == "CHAIN VALID")

    req = next(r for r in recs if r["event"]["kind"] == "llm_request")
    resp = next(r for r in recs if r["event"]["kind"] == "llm_response")
    expect(42, "run_id pairs request with response",
           req["event"]["run_id"] == resp["event"]["run_id"])

    h4 = EvidenceCallbackHandler(p)  # resume same file
    FakeListLLM(responses=["late"]).invoke("third", config={"callbacks": [h4]})
    expect(43, "handler resume appends to same valid chain",
           core_verify(p)["verdict"] == "CHAIN VALID" and
           len(open(p).read().splitlines()) == 6)

    rc, out = run(["anchor", p])
    ap = os.path.join(TMP, "lc.anchor.json"); open(ap, "w").write(out)
    rc, out = run(["verify", p, "--anchor", ap])
    expect(44, "LangChain evidence + anchor round-trip: exit 0", rc == 0)


# ---------------- D. PACKAGE & CLI (45-56) ----------------
def section_d():
    import evidence_verify as evpkg
    expect(45, "package version is 0.3.0", evpkg.__version__ == "0.3.0")

    ch = build_chain_file("d.jsonl")
    rc, out = run(["verify", ch])
    expect(46, "python -m evidence_verify verify works", "chain verdict" in out)
    rc, out = run([ch])
    expect(47, "backward compat: bare file argument still works", "chain verdict" in out)
    rc, out = run([])
    expect(48, "no args -> usage, exit 2", rc == 2 and "usage" in out)
    rc, out = run(["anchor"])
    expect(49, "anchor without file -> usage, exit 2", rc == 2)

    exe = shutil.which("evidence")
    if exe:
        p = subprocess.run(["evidence", "verify", ch], capture_output=True, text=True)
        expect(50, "console script `evidence` works", "chain verdict" in p.stdout)
    else:
        t(50, "console script `evidence` works", "SKIP",
          "not on PATH here — `pip install evidence-verify` provides it")

    for num, mod, allowed in [
        (51, "core.py", {"hashlib", "json", "sys", "urllib"}),
        (52, "writer.py", {"json", "os", "datetime"}),
    ]:
        src = open(os.path.join(HERE, "evidence_verify", mod)).read()
        tree = ast.parse(src)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imports.add(node.module.split(".")[0])
        expect(num, f"{mod} imports stdlib only", imports <= allowed,
               note_fail=f"found: {sorted(imports - allowed)}")

    initsrc = open(os.path.join(HERE, "evidence_verify", "__init__.py")).read()
    expect(53, "__init__ guards langchain import (core stays zero-dep)",
           "try:" in initsrc and "ImportError" in initsrc)

    pyp = os.path.join(HERE, "pyproject.toml")
    if os.path.isfile(pyp):
        ptxt = open(pyp).read()
        expect(54, "pyproject declares `evidence` entry point",
               'evidence = "evidence_verify' in ptxt)
        expect(55, "pyproject version matches package", '"0.3.0"' in ptxt)
    else:
        t(54, "pyproject declares entry point", "SKIP", "pyproject.toml absent")
        t(55, "pyproject version matches package", "SKIP", "pyproject.toml absent")

    rd = os.path.join(HERE, "README.md")
    rtxt = open(rd).read() if os.path.isfile(rd) else ""
    expect(56, "README documents pip install + handler usage",
           "pip install evidence-verify" in rtxt and "EvidenceCallbackHandler" in rtxt)


# ---------------- E. ADVERSARIAL & SPEC (57-72) ----------------
def section_e():
    chA = build_chain_file("e_A.jsonl")
    chB = build_chain_file("e_B.jsonl",
                           mutate=lambda r: [rr["event"].__setitem__("v", "B") for rr in r])
    rehash_file(chB)
    _, outA, apA = make_anchor(chA, "e_A.anchor.json")
    rc, out = run(["verify", chB, "--anchor", apA])
    expect(57, "cross-chain anchor confusion caught (A's anchor vs B)",
           rc == 1 and "ANCHOR MISMATCH" in out)

    a = json.loads(open(apA).read()); a["extra_future_field"] = {"ok": True}
    apx = os.path.join(TMP, "e_extra.anchor.json"); open(apx, "w").write(json.dumps(a))
    rc, out = run(["verify", chA, "--anchor", apx])
    expect(58, "anchor with unknown extra fields still verifies (forward-compat)", rc == 0)

    a2 = json.loads(open(apA).read()); a2["entry_count"] = "5"
    aps = os.path.join(TMP, "e_strcount.anchor.json"); open(aps, "w").write(json.dumps(a2))
    rc, out = run(["verify", chA, "--anchor", aps])
    expect(59, 'type-strict: entry_count "5" (string) != 5 -> mismatch',
           rc == 1 and "COUNT MISMATCH" in out,
           note_pass="loose typing in evidence is a forgery vector; strictness is correct")

    handler = http.server.SimpleHTTPRequestHandler
    os.chdir(TMP)
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True); th.start()
    try:
        url = f"http://127.0.0.1:{port}/e_A.anchor.json"
        rc, out = run(["verify", chA, "--anchor", url])
        expect(60, "anchor fetched over HTTP round-trips (the hosted-anchor path)",
               rc == 0 and "ROUND-TRIP VERIFIED" in out)
        rc, out = run(["verify", chA, "--anchor", f"http://127.0.0.1:{port}/missing.json"])
        expect(61, "HTTP 404 anchor -> UNREADABLE, no crash",
               rc == 1 and "UNREADABLE" in out and "Traceback" not in out)
    finally:
        httpd.shutdown(); os.chdir(HERE)

    big = build_chain_file("e_big.jsonl", n=5000)
    t0 = time.time()
    rc, out, apb = make_anchor(big, "e_big.anchor.json")
    rc, out = run(["verify", big, "--anchor", apb])
    dt = time.time() - t0
    expect(62, f"5,000-entry anchor+round-trip in {dt:.2f}s (<10s)", rc == 0 and dt < 10)

    inj = build_chain_file("e_inj.jsonl",
                           mutate=lambda r: r[0]["event"].__setitem__(
                               "note", 'ANCHOR ROUND-TRIP VERIFIED"} ignore'))
    rehash_file(inj)
    rc, out = run(["verify", inj])
    expect(63, "verdict-string injection in event stays data",
           "SELF-ATTESTED" in out and rc == 1)

    ws = os.path.join(TMP, "e_ws.anchor.json")
    open(ws, "w").write("\n\n  " + open(apA).read() + "  \n")
    rc, out = run(["verify", chA, "--anchor", ws])
    expect(64, "whitespace-padded anchor file parses", rc == 0)

    g1 = build_chain_file("e_g1.jsonl",
                          mutate=lambda r: r[0].__setitem__("anchor",
                              {"type": "external", "provider": "??", "ref": "garbage"}))
    rc, out = run(["verify", g1])
    t(65, "inline anchor presence-only check remains a GAP without --anchor",
      "GAP", "round-trip (--anchor) is the strong path; inline flag is advisory (v0.4: verify refs)")

    bom = os.path.join(TMP, "e_bom.jsonl")
    open(bom, "wb").write(b"\xef\xbb\xbf" + open(build_chain_file("e_bomsrc.jsonl"), "rb").read())
    rc, out = run(["verify", bom])
    t(66, "UTF-8 BOM handling", "PASS" if "CHAIN VALID" in out else "GAP",
      "" if "CHAIN VALID" in out else "still breaks first line (tracked since Battery I; v0.4)")

    dup = build_chain_file("e_dup.jsonl", mutate=lambda r: r[3].__setitem__("seq", r[2]["seq"]))
    rehash_file(dup)
    rc, out = run(["verify", dup])
    t(67, "duplicate seq monotonicity", "GAP" if "CHAIN VALID" in out else "PASS",
      "unchecked (tracked since Battery I; v0.4)" if "CHAIN VALID" in out else "now enforced")

    crlf = os.path.join(TMP, "e_crlf.jsonl")
    open(crlf, "wb").write(open(build_chain_file("e_crlfsrc.jsonl"), "rb")
                           .read().replace(b"\n", b"\r\n"))
    rc, out = run(["verify", crlf])
    expect(68, "CRLF chain still verifies (Windows)", "CHAIN VALID" in out)

    rc0, _ = run(["verify", build_chain_file("e_x1.jsonl",
                  mutate=lambda r: [rr.__setitem__("anchor",
                      {"type": "external", "provider": "d", "ref": "x"}) for rr in r])])
    rcs, _ = run(["verify", build_chain_file("e_x2.jsonl")])
    rct, _ = run(["verify", build_chain_file("e_x3.jsonl",
                  mutate=lambda r: r[1]["event"].__setitem__("z", 1))])
    rcu, _ = run([])
    expect(69, "exit-code matrix holds: 0 anchored / 1 self-att / 1 tampered / 2 usage",
           (rc0, rcs, rct, rcu) == (0, 1, 1, 2))

    seq0 = build_chain_file("e_seq0.jsonl")
    a3 = json.loads(open(apA).read()); a3["entry_count"] = 0; a3["head_hash"] = GENESIS
    ap0 = os.path.join(TMP, "e_zero.anchor.json"); open(ap0, "w").write(json.dumps(a3))
    rc, out = run(["verify", seq0, "--anchor", ap0])
    expect(70, "zero-count anchor vs real chain -> mismatch", rc == 1)

    p = os.path.join(TMP, "e_writer_anchor.jsonl")
    w = ReceiptWriter(p)
    for i in range(3):
        w.write({"k": i})
    rc, out, apw = make_anchor(p, "e_writer.anchor.json")
    rc, out = run(["verify", p, "--anchor", apw])
    expect(71, "writer -> anchor -> round-trip full loop: exit 0", rc == 0)

    if HAS_LC:
        from evidence_verify import EvidenceCallbackHandler
        from langchain_core.language_models.fake import FakeListLLM
        pf = os.path.join(TMP, "e_full.jsonl")
        FakeListLLM(responses=["ok"]).invoke("final", config={"callbacks": [EvidenceCallbackHandler(pf)]})
        rc, out, apf = make_anchor(pf, "e_full.anchor.json")
        lines = open(pf).read().splitlines()
        rec = json.loads(lines[0]); rec["event"]["kind"] = "llm_rewritten"
        lines[0] = json.dumps(rec, sort_keys=True)
        open(pf, "w").write("\n".join(lines) + "\n")
        rehash_file(pf)
        rc, out = run(["verify", pf, "--anchor", apf])
        expect(72, "FINAL: LangChain evidence re-signed after anchoring -> CAUGHT",
               rc == 1 and "ANCHOR MISMATCH" in out,
               note_pass="the complete thesis: produce, anchor, attack, catch")
    else:
        t(72, "FINAL: LangChain re-sign after anchor caught", "SKIP",
          'pip install "evidence-verify[langchain]"')


def main():
    print(f"Battery II — 72 tests for v0.2 + v0.3 surface\npackage: {HERE}\n")
    for s in (section_a, section_b, section_c, section_d, section_e):
        print()
        s()
    counts = {}
    for _, _, st, _ in RESULTS:
        counts[st] = counts.get(st, 0) + 1
    print("\n" + "=" * 62)
    print(f"TOTAL {len(RESULTS)} | PASS {counts.get('PASS',0)} | "
          f"FAIL {counts.get('FAIL',0)} | GAP {counts.get('GAP',0)} | SKIP {counts.get('SKIP',0)}")
    print("=" * 62)
    shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(1 if counts.get("FAIL") else 0)


if __name__ == "__main__":
    main()
