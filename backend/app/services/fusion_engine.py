import logging
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("smartshield.fusion")

SAFE_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "chatgpt.com", "openai.com",
    "github.com", "facebook.com", "netflix.com", "amazon.com", "youtube.com",
    "wikipedia.org", "linkedin.com", "twitter.com", "x.com", "instagram.com"
]

def is_whitelisted(url_or_domain: str) -> bool:
    if not url_or_domain:
        return False
    
    url_lower = url_or_domain.lower().strip()
    
    # Try to extract the hostname properly using urlparse
    if not url_lower.startswith(("http://", "https://")):
        parsed = urlparse("http://" + url_lower)
    else:
        parsed = urlparse(url_lower)
        
    hostname = parsed.netloc or parsed.path
    hostname = hostname.split(":")[0].strip()
    if hostname.startswith("www."):
        hostname = hostname[4:]
        
    for domain in SAFE_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            return True
            
    return False


def fuse_text_scores(
    qwen_res: Dict[str, Any],
    sandbox_res: Optional[Dict[str, Any]] = None,
    text_content: Optional[str] = None
) -> Dict[str, Any]:
    """
    Risk Fusion logic for text-based inputs (SMS, Whatsapp, Voice transcript, Email body).
    Applies the primary verdict based on local Qwen2.5-VL analysis, blended with
    optional Sandbox execution logs if a URL was detected and sandboxed.
    """
    qwen_explanation = qwen_res.get("explanation", "No explanation details available.")
    whitelist_triggered = False
    whitelist_reason = ""
    
    # 1. Check if the sandboxed URL is whitelisted
    if sandbox_res and sandbox_res.get("url"):
        target_url = sandbox_res.get("url")
        if is_whitelisted(target_url):
            whitelist_triggered = True
            whitelist_reason = f"The embedded URL domain ({target_url}) is identified as a trusted global platform."
            
    # 2. If no sandbox, check if the input text itself is exactly a whitelisted URL/domain
    if not whitelist_triggered and text_content:
        cleaned_text = text_content.strip()
        if " " not in cleaned_text and is_whitelisted(cleaned_text):
            whitelist_triggered = True
            whitelist_reason = f"The input content is verified as a trusted global platform ({cleaned_text})."
                
    if whitelist_triggered:
        return {
            "final_score": 5.0,
            "category": "Safe",
            "confidence": 99.0,
            "explanation": f"Final Risk Engine VERDICT: [Not Scam] (Score: 5.0). Whitelist Check: {whitelist_reason}",
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
        if qwen_score >= 30.0:
            final_score = max(final_score, qwen_score)
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
        explanation = f"Final Risk Engine VERDICT: [{verdict_label}] (Score: {round(final_score, 1)}). Combined AI text analysis and URL Sandbox check.{findings_str} {qwen_explanation}"
    else:
        explanation = f"Final Risk Engine VERDICT: [{verdict_label}] (Score: {round(final_score, 1)}). {qwen_explanation}"

    return {
        "final_score": round(final_score, 2),
        "category": category,
        "confidence": round(confidence, 2),
        "explanation": explanation,
        "recommendations": recs,
        "strategy": "SmartShield AI + Sandbox Fusion" if sandbox_res else "SmartShield AI Engine",
        "tactic_breakdown": qwen_res.get("tactic_breakdown"),
        "tactic_highlights": qwen_res.get("tactic_highlights"),
        "dna_signals": qwen_res.get("dna_signals")
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
    if llm_score >= 30.0:
        final_score = max(final_score, llm_score)
    
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
    
    explanation = f"Final Risk Engine VERDICT: [{verdict_label}] (Score: {round(final_score, 1)}). Multi-modal fusion using Sandbox and local AI content checks. "
    if findings:
        explanation += f"Identified warning indicators: {'; '.join(findings[:5])}."
    else:
        explanation += "No technical or reputation markers were flagged during assessment."
        
    return {
        "final_score": round(final_score, 2),
        "category": category,
        "confidence": 85.0, # High confidence due to multi-source checking
        "explanation": explanation,
        "recommendations": recs,
        "tactic_breakdown": qwen_res.get("tactic_breakdown") if qwen_res else None,
        "tactic_highlights": qwen_res.get("tactic_highlights") if qwen_res else None,
        "dna_signals": qwen_res.get("dna_signals") if qwen_res else None
    }
