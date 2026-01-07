from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

class IncidentContext(BaseModel):
    generated_at: datetime
    lookback_minutes: int
    namespace: str
    app_label: str
    prom_queries: dict[str, Any] = Field(default_factory=dict)
    loki_queries: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    llm: Optional[Dict[str, Any]] = Field(default_factory=dict)
