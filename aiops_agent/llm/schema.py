# aiops_agent/llm/schema.py
from __future__ import annotations

from pydantic import BaseModel, Field
from typing import List, Literal, Optional

Confidence = Literal["low", "medium", "high"]
Category = Literal["config", "dependency", "crashloop", "memory", "app_bug", "unknown"]


class LLMSummary(BaseModel):
    # backward compatible defaults
    root_cause: str = Field(default="unknown")
    key_evidence: List[str] = Field(default_factory=list)
    next_actions: List[str] = Field(default_factory=list)


class SuggestedClassification(BaseModel):
    # optional classifier suggestion (especially useful when triage is unknown/low confidence)
    candidate: Category = Field(default="unknown")
    confidence: Confidence = Field(default="low")
    why: List[str] = Field(default_factory=list)
    missing_evidence_to_confirm: List[str] = Field(default_factory=list)


class LLMOutput(BaseModel):
    # backward compatible defaults
    llm_summary: LLMSummary = Field(default_factory=LLMSummary)
    risk_notes: List[str] = Field(default_factory=list)
    confidence: Confidence = Field(default="low")

    # NEW (optional): present only when model decides / or when instructed (unknown/low)
    suggested_classification: Optional[SuggestedClassification] = Field(default=None)