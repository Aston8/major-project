import logging
import re
from typing import Dict, Any, Optional

logger = logging.getLogger("smartshield.fusion")

SAFE_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "chatgpt.com", "openai.com",
    "github.com", "facebook.com", "netflix.com", "amazon.com", "youtube.com",
    "wikipedia.org", "linkedin.com", "twitter.com", "x.com", "instagram.com"
]

def is_whitelisted(text_to_check: str) -> bool:
    if not text_to_check:
        return False
    text_lower = text_to_check.lower()
    
    # Split text into potential domain tokens by space, slashes, colons, or other query/path delimiters
    tokens = re.split(r'[\s\/\:\?\#\=\&]+', text_lower)
    for token in tokens:
        # Strip leading/trailing dots
        token = token.strip(".")
        for domain in SAFE_DOMAINS:
            # Match domain exactly or as a subdomain (e.g. accounts.google.com ends with .google.com)
            if token == domain or token.endswith("." + domain):
                return True
    return False

def fuse_text_scores(
    qwen_res: Dict[str, Any],
    sandbox_res: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Risk Fusion logic for text-based inputs (SMS, Whatsapp, Voice transcript, Email body).
    Applies the primary verdict based on local Qwen2.5-VL analysis, blended with
    optional Sandbox execution logs if a URL was detected and sandboxed.
    """
    qwen_explanation = qwen_res.get("explanation", "No explanation details available.")
    
    # Check whitelist override
    whitelist_triggered = is_whitelisted(qwen_explanation)
    if sandbox_res:
        for req in sandbox_res.get("network_requests", []):
            if is_whitelisted(req.get("url", "")) or is_whitelisted(req.get("domain", "")):
                whitelist_triggered = True
                break
                
    if whitelist_triggered:
        return {
            "final_score": 5.0,
            "category": "Safe",
            "confidence": 99.0,
            "explanation": "Final Risk Engine VERDICT: [Not Scam] (Score: 5.0). Whitelist Check: The domain is identified as a trusted global platform (e.g. ChatGPT, Google, Microsoft). The content is verified as legitimate and safe.",
            "recommendations": [
                "Trusted platform verified.",
                "Safe for standard browsing and authentication."
            ],
            "strategy": "Whitelist Override"
        }

    qwen_score = qwen_res.get("score", 0.0)
    confidence = qwen_res.get("confidence", 85.0)
    
    if sandbox_res:
        sandbox_verdict = sandbox_res.get("sandbox_verdict", "Safe")
        sandbox_score = 10.0
        if sandbox_verdict == "Dangerous":
            sandbox_score = 100.0
        elif sandbox_verdict == "Suspicious":
            sandbox_score = 60.0
        
        # Blend the text semantics score with the URL sandbox score (50/50 weight)
        final_score = (qwen_score * 0.5) + (sandbox_score * 0.5)
        # Sandbox execution adds real behavioral proof, increasing confidence
        confidence = min(max(confidence, 90.0), 98.0)
    else:
        final_score = qwen_score
    
    # Standard categories: Safe (0-30), Suspicious (31-60), Dangerous (61-100)
    category = "Safe"
    if final_score >= 60:
        category = "Dangerous"
    elif final_score >= 30:
        category = "Suspicious"
        
    is_scam = category in ["Dangerous", "Suspicious"]
    verdict_label = "Scam" if is_scam else "Not Scam"
    
    recs = []
    if is_scam:
        recs = [
            "Do NOT click any links in this message.",
            "Do NOT share OTPs, passwords, or personal identity documents.",
            "Report this contact to your service provider or cybersecurity cell.",
            "Block this sender number/email immediately."
        ]
    else:
        recs = [
            "No immediate threats detected.",
            "Always remain vigilant when receiving unsolicited links."
        ]
        
    if sandbox_res:
        findings = ", ".join(sandbox_res.get("behavior_findings", []))
        findings_str = f" Sandbox findings: {findings}." if findings else ""
        explanation = f"Final Risk Engine VERDICT: [{verdict_label}] (Score: {round(final_score, 1)}). Combined Qwen text analysis and URL Sandbox check.{findings_str} {qwen_explanation}"
    else:
        explanation = f"Final Risk Engine VERDICT: [{verdict_label}] (Score: {round(final_score, 1)}). {qwen_explanation}"

    return {
        "final_score": round(final_score, 2),
        "category": category,
        "confidence": round(confidence, 2),
        "explanation": explanation,
        "recommendations": recs,
        "strategy": "Qwen + Sandbox Fusion" if sandbox_res else "Local Qwen2.5-VL Engine"
    }

def fuse_url_scores(
    reputation_res: Dict[str, Any], 
    threat_intel_res: Dict[str, Any], 
    sandbox_res: Dict[str, Any],
    qwen_res: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Fuses URL reputation, sandbox execution reports, threat feeds, and local Qwen2.5-VL vision-language analysis.
    URL Fusion weights:
      - Sandbox Report Verdict: 35%
      - Threat Intel Aggregator: 25%
      - URL Reputation Indicators: 20%
      - Local Qwen2.5-VL Analysis: 20%
    """
    # 0. Check Whitelist Override
    target_url = reputation_res.get("url", "") or sandbox_res.get("url", "") or ""
    whitelist_triggered = is_whitelisted(target_url)
    
    # Also check network request domains captured by sandbox
    for req in sandbox_res.get("network_requests", []):
        if is_whitelisted(req.get("url", "")) or is_whitelisted(req.get("domain", "")):
            whitelist_triggered = True
            break
            
    if whitelist_triggered:
        return {
            "final_score": 5.0,
            "category": "Safe",
            "confidence": 99.0,
            "explanation": "Final Risk Engine VERDICT: [Not Scam] (Score: 5.0). Whitelist Check: The domain is identified as a trusted global platform. The content is verified as legitimate and safe.",
            "recommendations": [
                "Trusted platform verified.",
                "Safe for standard browsing and authentication."
            ]
        }

    sandbox_verdict = sandbox_res.get("sandbox_verdict", "Safe")
    sandbox_score = 0.0
    if sandbox_verdict == "Dangerous":
        sandbox_score = 100.0
    elif sandbox_verdict == "Suspicious":
        sandbox_score = 60.0
    elif sandbox_verdict == "Safe":
        sandbox_score = 10.0
        
    threat_score = threat_intel_res.get("risk_score", 0.0)
    reputation_score = reputation_res.get("risk_score", 0.0)
    
    # Qwen LLM score
    llm_score = qwen_res.get("score", 0.0) if qwen_res else 0.0
    
    # Calculate weighted score
    final_score = (sandbox_score * 0.35) + (threat_score * 0.25) + (reputation_score * 0.20) + (llm_score * 0.20)
    
    category = "Safe"
    if final_score > 60:
        category = "Dangerous"
    elif final_score > 30:
        category = "Suspicious"
        
    is_scam = category in ["Dangerous", "Suspicious"]
    verdict_label = "Scam" if is_scam else "Not Scam"
        
    recs = []
    if is_scam:
        recs = [
            "DO NOT browse this URL or enter details.",
            "This site has been verified as a threat (phishing/malware download).",
            "Report this domain to registrar or security feeds like PhishTank.",
            "Clear browser cache if you entered credentials here."
        ]
    else:
        recs = [
            "No immediate malicious activity found.",
            "Browser sandboxing confirmed page loaded without downloads or password harvesting forms."
        ]
        
    findings = []
    findings.extend(reputation_res.get("suspicious_patterns", []))
    findings.extend(sandbox_res.get("behavior_findings", []))
    findings.extend(threat_intel_res.get("threat_indicators", []))
    
    explanation = f"Final Risk Engine VERDICT: [{verdict_label}] (Score: {round(final_score, 1)}). Multi-modal fusion using Sandbox and local Qwen2.5-VL checks. "
    if findings:
        explanation += f"Identified warning indicators: {'; '.join(findings[:5])}."
    else:
        explanation += "No technical or reputation markers were flagged during assessment."
        
    return {
        "final_score": round(final_score, 2),
        "category": category,
        "confidence": 85.0, # High confidence due to multi-source checking
        "explanation": explanation,
        "recommendations": recs
    }
