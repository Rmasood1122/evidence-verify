"""ReceiptWriter: append hash-chained receipts to a JSONL evidence file."""
import json
import os
from datetime import datetime, timezone
from .core import entry_hash, GENESIS


class ReceiptWriter:
    def __init__(self, path):
        self.path = path
        self.seq = 0
        self.prev = GENESIS
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        rec = json.loads(line)
                        self.seq = rec["seq"]
                        self.prev = rec["entry_hash"]

    def write(self, event, anchor=None):
        self.seq += 1
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        eh = entry_hash(self.seq, ts, event, self.prev)
        rec = {"seq": self.seq, "ts": ts, "event": event,
               "prev_hash": self.prev, "entry_hash": eh}
        if anchor:
            rec["anchor"] = anchor
        with open(self.path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        self.prev = eh
        return rec
