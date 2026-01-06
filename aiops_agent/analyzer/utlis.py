# utils.py or triage.py 顶部
from typing import Any, Optional

def _num(x: Any) -> Optional[float]:
    if x is None:
        return None
    try:
        return int(x)
    except (TypeError, ValueError):
        return None