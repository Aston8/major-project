from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict, Any

class TextScanRequest(BaseModel):
    content: str = Field(..., min_length=2, max_length=10000)
    source_type: str = "SMS" # SMS, Email, WhatsApp, Telegram, Social Media

class URLScanRequest(BaseModel):
    url: str

class EmailScanRequest(BaseModel):
    content: str
    sender_email: Optional[str] = None
    headers: Optional[str] = None

class AIModelResult(BaseModel):
    score: float
    confidence: float
    category: str
    explanation: str
    highlighted_keywords: List[str] = []

class FusionResult(BaseModel):
    final_score: float
    category: str  # Safe (0-30), Suspicious (31-60), Dangerous (61-100)
    confidence: float
    explanation: str
    recommendations: List[str] = []

class URLMetadata(BaseModel):
    url: str
    domain: str
    domain_age_days: Optional[int] = None
    whois_info: Optional[Dict[str, Any]] = None
    ssl_valid: bool = False
    ssl_info: Optional[Dict[str, Any]] = None
    redirect_chain: List[str] = []
    is_shortener: bool = False
    suspicious_patterns: List[str] = []

class SandboxResult(BaseModel):
    executed: bool = False
    screenshot_url: Optional[str] = None
    html_snapshot_path: Optional[str] = None
    network_requests: List[Dict[str, Any]] = []
    download_attempts: List[Dict[str, Any]] = []
    console_errors: List[str] = []
    detected_forms: List[Dict[str, Any]] = []
    behavior_findings: List[str] = []
    sandbox_verdict: str = "Safe"
    ai_vision_analysis: Optional[Dict[str, Any]] = None

class ScanResponse(BaseModel):
    id: str = Field(..., alias="_id")
    user_id: Optional[str] = None
    type: str  # text, image, voice, email, url
    input_data: Dict[str, Any]
    local_ml_result: Optional[AIModelResult] = None
    gemini_result: Optional[AIModelResult] = None
    grok_result: Optional[AIModelResult] = None
    fusion_result: FusionResult
    url_metadata: Optional[URLMetadata] = None
    sandbox_report: Optional[SandboxResult] = None
    threat_intel_score: Optional[float] = None
    threat_intel_details: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        populate_by_name = True
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }
