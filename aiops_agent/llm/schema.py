# aiops_agent/llm/schema.py
from pydantic import BaseModel, Field
from typing import List, Literal

class LLMSummary(BaseModel):
    root_cause: str
    key_evidence: List[str]
    next_actions: List[str]

class LLMOutput(BaseModel):
    llm_summary: LLMSummary
    risk_notes: List[str]
    confidence: Literal["low", "medium", "high"]