"""Rule modules: agent-facing checks, privacy/telemetry detection, and the rule registry."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    """Explicit rule metadata: stable id, the severities it can emit, meaning and docs."""
    id: str
    severity: str
    meaning: str
    remediation: str = ""
    docs: str = ""

from .registry import RULES  # noqa: E402  (registry imports Rule from here)
