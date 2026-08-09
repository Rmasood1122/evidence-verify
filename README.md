# evidence verify

**One command that answers the question your AI audit logs can't:**
*who guarantees this log wasn't altered by the system that produced it?*

```
$ evidence verify receipts.jsonl

entries checked : 5
chain verdict   : CHAIN VALID
independence    : SELF-ATTESTED — would not survive independence challenge.
                  Every hash in this chain was produced and stored by the same
                  system it describes; a compromised producer can re-sign the
                  entire chain. No external anchor found.
```

## Why this exists

The EU AI Act's Article 12 requires automatic event logging for high-risk AI
systems (Annex III obligations now apply from December 2, 2027 under the July 2026 Omnibus amendment; retention ≥6 months under Articles
19/26(6)). Most vendors answer with hash-chained logs.

A hash chain proves **sequence**. It does not prove **independence**. If the
system that writes the log is compromised — or simply motivated — it can
rewrite history and re-sign the entire chain. The log is a diary, not an
affidavit. **The enforcer cannot be the notary.**

`evidence verify` checks three levels:

1. **CHAIN** — is every entry linked to the previous one?
2. **TAMPER** — does every entry's content still match its hash?
3. **INDEPENDENCE** — does the chain reference an anchor *outside* the
   producing system? If not, it says so, plainly.

It works on any log that follows the receipt format below — including logs
from other gateways and proxies. Point it at your current vendor's export and
see what an auditor would see.

## Install

Go 1.21+:

```
go build -o evidence .
./evidence verify sample_selfattested.jsonl
```

Python reference implementation (identical logic, used for cross-testing):

```
python3 evidence_verify.py sample_selfattested.jsonl
```

## Exit codes

`0` = chain valid **and** anchored (round-trip verified when `--anchor` is given). `1` = self-attested, mismatch, or broken/tampered.
`2` = usage or file error. CI can gate on `0`.

## Receipt format (v0.1 — spec RFC coming)

One JSON object per line (JSONL):

```json
{
  "seq": 1,
  "ts": "2026-08-09T10:01:00Z",
  "event": { "model": "...", "request_sha256": "...", "response_sha256": "...", "decision": "allow" },
  "prev_hash": "<sha256 of previous entry; 64 zeros for genesis>",
  "entry_hash": "<sha256 of seq|ts|canonical(event)|prev_hash>",
  "anchor": { "type": "external", "provider": "...", "ref": "..." }
}
```

`canonical(event)` = JSON with sorted keys, no whitespace (RFC 8785-style).
The Go and Python implementations are byte-compatible.


## v0.2: anchor round-trip

Anchor a chain (store the output OUTSIDE the producing system — a separate
repo, a gist, S3, a timestamping service):

```
python evidence_verify.py anchor receipts.jsonl > anchor.json
```

Verify against the anchor (local file or https URL):

```
python evidence_verify.py verify receipts.jsonl --anchor anchor.json
python evidence_verify.py verify receipts.jsonl --anchor https://example.com/anchor.json
```

Round-trip verification catches what hash chains alone cannot: full history
rewrites (re-signed chains) and truncation. The independence guarantee is
exactly as strong as the independence of where the anchor lives.

## Samples

- `sample_selfattested.jsonl` — valid chain, no anchor (what most vendors ship)
- `sample_anchored.jsonl` — valid chain with external anchor references
- `sample_tampered.jsonl` — one entry silently edited; the verifier catches it

Regenerate with `python3 make_samples.py`.

## Roadmap

- Ed25519 signature verification (asymmetric, third-party verifiable)
- eIDAS-compatible qualified timestamp validation for anchors
- Adapters: Kong plugin export, LangChain callback, LiteLLM, OpenAI
  compliance-log export (which retains ~30 days by default — mind the
  6-month retention gap)

## License

Apache-2.0. Verification stays free forever. That's the point.
