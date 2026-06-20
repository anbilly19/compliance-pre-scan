"""Policy engine — evaluates scan hits against Rego rules via OPA or inline fallback."""
from .engine import evaluate, PolicyInput, PolicyResult

__all__ = ["evaluate", "PolicyInput", "PolicyResult"]
