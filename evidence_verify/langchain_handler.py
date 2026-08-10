"""LangChain callback handler that writes tamper-evident evidence receipts.

Usage:
    from evidence_verify import EvidenceCallbackHandler
    handler = EvidenceCallbackHandler("receipts.jsonl")
    llm.invoke(prompt, config={"callbacks": [handler]})

Every LLM call produces two chained receipts (request, response) with
SHA-256 fingerprints of prompts and outputs -- content hashes only by
default, so no prompt text leaves your control via the evidence file.
Verify anytime:  python -m evidence_verify verify receipts.jsonl
"""
import hashlib
from langchain_core.callbacks import BaseCallbackHandler
from .writer import ReceiptWriter


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class EvidenceCallbackHandler(BaseCallbackHandler):
    def __init__(self, path, include_text=False):
        self.w = ReceiptWriter(path)
        self.include_text = include_text

    def on_llm_start(self, serialized, prompts, *, run_id, **kwargs):
        ev = {"kind": "llm_request", "run_id": str(run_id),
              "model": (serialized or {}).get("name", "unknown"),
              "prompt_sha256": [_sha256(p) for p in prompts],
              "prompt_count": len(prompts)}
        if self.include_text:
            ev["prompts"] = prompts
        self.w.write(ev)

    def on_llm_end(self, response, *, run_id, **kwargs):
        texts = [g.text for gens in response.generations for g in gens]
        ev = {"kind": "llm_response", "run_id": str(run_id),
              "response_sha256": [_sha256(t) for t in texts],
              "response_count": len(texts)}
        if self.include_text:
            ev["responses"] = texts
        self.w.write(ev)

    def on_llm_error(self, error, *, run_id, **kwargs):
        self.w.write({"kind": "llm_error", "run_id": str(run_id),
                      "error_type": type(error).__name__,
                      "error_sha256": _sha256(str(error))})

    def on_tool_start(self, serialized, input_str, *, run_id, **kwargs):
        self.w.write({"kind": "tool_call", "run_id": str(run_id),
                      "tool": (serialized or {}).get("name", "unknown"),
                      "input_sha256": _sha256(input_str)})

    def on_tool_end(self, output, *, run_id, **kwargs):
        self.w.write({"kind": "tool_result", "run_id": str(run_id),
                      "output_sha256": _sha256(str(output))})
