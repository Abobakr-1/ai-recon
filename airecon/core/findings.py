"""Findings model.

A recon tool produces observations, not verdicts. Every result carries an
explicit confidence state so a low-signal hit (e.g. a header that *might*
identify a backend) is never presented with the same weight as a confirmed
endpoint enumeration.

Confidence ladder (highest first), aligned with the evidence rules:
  CONFIRMED   - directly observed, reproducible, no benign explanation left
  LIKELY      - strong structural signal, one plausible benign alternative
  POSSIBLE    - heuristic/pattern match; corroborate before reporting
  INFO        - useful context, not a vulnerability by itself
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    INFO = "info"


CONFIDENCE_RANK = {
    Confidence.CONFIRMED: 3,
    Confidence.LIKELY: 2,
    Confidence.POSSIBLE: 1,
    Confidence.INFO: 0,
}


@dataclass
class Finding:
    """One structured recon observation."""

    module: str                     # which recon phase produced it
    title: str
    detail: str = ""
    confidence: Confidence = Confidence.INFO
    evidence: list[str] = field(default_factory=list)   # evidence file refs
    data: dict = field(default_factory=dict)            # machine-readable
    impact: str = ""                # only what was demonstrated
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "title": self.title,
            "detail": self.detail,
            "confidence": self.confidence.value,
            "evidence": self.evidence,
            "data": self.data,
            "impact": self.impact,
            "tags": self.tags,
        }


class Findings:
    """Collects findings and provides simple filtering/reporting helpers."""

    def __init__(self) -> None:
        self._items: list[Finding] = []

    def add(self, finding: Finding) -> Finding:
        self._items.append(finding)
        return finding

    def add_simple(self, module: str, title: str, detail: str = "",
                   confidence: Confidence = Confidence.INFO, **kw) -> Finding:
        return self.add(Finding(module=module, title=title, detail=detail,
                                confidence=confidence, **kw))

    def __iter__(self):
        return iter(self._items)

    def __len__(self):
        return len(self._items)

    def by_confidence(self, minimum: Confidence) -> list[Finding]:
        floor = CONFIDENCE_RANK[minimum]
        return [f for f in self._items if CONFIDENCE_RANK[f.confidence] >= floor]

    def to_list(self) -> list[dict]:
        return [f.to_dict() for f in self._items]
