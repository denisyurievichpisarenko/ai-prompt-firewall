from pydantic import BaseModel, Field
from typing import Dict, List

class SecurityRequest(BaseModel):
    user_prompt: str = Field(..., min_length=0, description="The raw prompt submitted by the user")

class ShieldMetrics(BaseModel):
    regex_processing_time_ms: float
    llm_processing_time_ms: float
    total_time_ms: float

class SecurityResponse(BaseModel):
    original_prompt: str
    sanitized_prompt: str
    pii_found: List[str]
    is_jailbreak: bool
    jailbreak_risk_score: str  # "HIGH", "MEDIUM", "LOW"
    final_verdict: str         # "ALLOW" or "BLOCK"
    metrics: ShieldMetrics