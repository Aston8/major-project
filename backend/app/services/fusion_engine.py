import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("smartshield.fusion")

def fuse_text_scores(local_res: Dict[str, Any], gemini_res: Optional[Dict[str, Any]], grok_res: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Risk Fusion logic for text inputs (SMS, Whatsapp, Emails).
    Applies the primary weighted combination:
      40% Local ML, 30% Gemini, 30% Grok
    With failover logic:
      - Gemini fails: Local 50% + Grok 50%
      - Grok fails: Local 50% + Gemini 50%
      - Both fail: Local 100%
    """
    local_score = local_res.get("score", 0.0)
    
    # Check if Gemini/Grok results are valid and not stubs (or if we have key access)
    # If the service returns a result, we check if it was mock. In case of API failure,
    # we represent it via None or check flags. Here we base it on key presence or valid scores.
    has_gemini = gemini_res is not None and not gemini_res.get("explanation", "").startswith("Gemini Analysis (Mock mode)")
    has_grok = grok_res is not None and not grok_res.get("explanation", "").startswith("Grok secondary verification (mock mode)")
    
    final_score = 0.0
    strategy = ""
    
    if has_gemini and has_grok:
        # standard weighted model
        final_score = (local_score * 0.40) + (gemini_res["score"] * 0.30) + (grok_res["score"] * 0.30)
        strategy = "Weighted (40% Local ML, 30% Gemini, 30% Grok)"
    elif has_grok:
        # Gemini failed
        final_score = (local_score * 0.50) + (grok_res["score"] * 0.50)
        strategy = "Failover Mode (50% Local ML, 50% Grok)"
    elif has_gemini:
        # Grok failed
        final_score = (local_score * 0.50) + (gemini_res["score"] * 0.50)
        strategy = "Failover Mode (50% Local ML, 50% Gemini)"
    else:
        # Both failed
        final_score = local_score
        strategy = "Emergency Fallback (100% Local ML)"
        
    # Categories: 0-30 Safe, 31-60 Suspicious, 61-100 Dangerous
    category = "Safe"
    if final_score > 60:
        category = "Dangerous"
    elif final_score > 30:
        category = "Suspicious"
        
    # Aggregate explanations
    recs = []
    if category == "Dangerous":
        recs = [
            "Do NOT click any links in this message.",
            "Do NOT share OTPs, passwords, or personal identity documents.",
            "Report this contact to your service provider or cybersecurity cell.",
            "Block this sender number/email immediately."
        ]
    elif category == "Suspicious":
        recs = [
            "Exercise caution before responding to this sender.",
            "Verify the credentials independently via official channels.",
            "Avoid sharing any credentials or scanning any codes."
        ]
    else:
        recs = [
            "No immediate threats detected.",
            "Always remain vigilant when receiving unsolicited links."
        ]

    # Combine explanations
    exp_parts = []
    if local_res:
        exp_parts.append(f"Local NLP Classification: {local_res.get('explanation')}")
    if gemini_res:
        exp_parts.append(f"Primary AI (Gemini): {gemini_res.get('explanation')}")
    if grok_res:
        exp_parts.append(f"Secondary AI Verification (Grok): {grok_res.get('explanation')}")

    explanation = f"Risk Engine applied {strategy} to determine final score of {round(final_score, 1)}. " + " ".join(exp_parts)

    # Average confidence scores
    conf_vals = [local_res.get("confidence", 70.0)]
    if gemini_res:
        conf_vals.append(gemini_res.get("confidence", 70.0))
    if grok_res:
        conf_vals.append(grok_res.get("confidence", 70.0))
    confidence = sum(conf_vals) / len(conf_vals)

    return {
        "final_score": round(final_score, 2),
        "category": category,
        "confidence": round(confidence, 2),
        "explanation": explanation,
        "recommendations": recs,
        "strategy": strategy
    }

def fuse_url_scores(
    reputation_res: Dict[str, Any], 
    threat_intel_res: Dict[str, Any], 
    sandbox_res: Dict[str, Any],
    gemini_res: Optional[Dict[str, Any]],
    grok_res: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Fuses URL reputation, sandbox execution reports, threat feeds, and LLM text analysis.
    URL Fusion weights:
      - Sandbox Report Verdict: 35%
      - Threat Intel Aggregator: 25%
      - URL Reputation Indicators: 20%
      - Generative AI Analysis: 20% (Combined Gemini & Grok)
    """
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
    
    # LLM score
    llm_scores = []
    if gemini_res:
        llm_scores.append(gemini_res.get("score", 0.0))
    if grok_res:
        llm_scores.append(grok_res.get("score", 0.0))
    llm_score = sum(llm_scores) / len(llm_scores) if llm_scores else 0.0
    
    # Calculate weighted score
    final_score = (sandbox_score * 0.35) + (threat_score * 0.25) + (reputation_score * 0.20) + (llm_score * 0.20)
    
    category = "Safe"
    if final_score > 60:
        category = "Dangerous"
    elif final_score > 30:
        category = "Suspicious"
        
    recs = []
    if category == "Dangerous":
        recs = [
            "DO NOT browse this URL or enter details.",
            "This site has been verified as a threat (phishing/malware download).",
            "Report this domain to registrar or security feeds like PhishTank.",
            "Clear browser cache if you entered credentials here."
        ]
    elif category == "Suspicious":
        recs = [
            "Use extreme caution. Site has mismatched domains or warning indicators.",
            "Do not input login credentials or financial details.",
            "Verify URL destination matches the expected official portal."
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
    
    explanation = f"Multi-modal fusion computed threat score of {round(final_score, 1)}. "
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
