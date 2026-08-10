"""evidence-verify: tamper-evident, anchorable receipts for AI systems."""
from .core import entry_hash, GENESIS, verify
from .writer import ReceiptWriter
__version__ = "0.3.0"
try:
    from .langchain_handler import EvidenceCallbackHandler  # noqa: F401
except ImportError:
    pass  # langchain-core not installed; core stays zero-dependency
