import sys
import os

# Add backend app directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.services.fusion_engine import is_whitelisted, fuse_url_scores, fuse_text_scores

def run_tests():
    print("Running whitelist and score alignment verification tests...")
    
    # 1. Test is_whitelisted cases
    print("\n1. Testing is_whitelisted:")
    cases = [
        ("google.com", True),
        ("https://google.com", True),
        ("https://accounts.google.com/login", True),
        ("https://google.com/security/login", True),
        ("https://scam-site.com/google.com", False),
        ("https://win.parimatchs123.com", False),
        ("win.parimatchs123.com", False),
        ("https://youtube.com", True),
        ("youtube.com", True),
        ("https://bad-site.com/youtube.com/confirm", False),
    ]
    
    success = True
    for text, expected in cases:
        result = is_whitelisted(text)
        status = "PASS" if result == expected else "FAIL"
        print(f"  is_whitelisted('{text}') -> {result} (Expected: {expected}) : {status}")
        if result != expected:
            success = False
            
    # 2. Test fuse_url_scores with sub-requests to whitelisted domains (and score alignment)
    print("\n2. Testing fuse_url_scores network request isolation and score alignment:")
    reputation_res = {"url": "https://win.parimatchs123.com", "risk_score": 0.0, "suspicious_patterns": []}
    threat_intel_res = {"risk_score": 0.0, "threat_indicators": []}
    sandbox_res = {
        "url": "https://win.parimatchs123.com",
        "sandbox_verdict": "Safe",
        "behavior_findings": [],
        "network_requests": [
            {"url": "https://www.google.com/recaptcha/api.js", "domain": "www.google.com"},
            {"url": "https://fonts.googleapis.com/css?family=Roboto", "domain": "fonts.googleapis.com"},
        ]
    }
    qwen_res = {
        "score": 95.0,
        "confidence": 90.0,
        "category": "Lottery Scams",
        "explanation": "Lottery-related scam domain detected."
    }
    
    res = fuse_url_scores(reputation_res, threat_intel_res, sandbox_res, qwen_res)
    print(f"  Final Score: {res.get('final_score')}")
    print(f"  Category: {res.get('category')}")
    print(f"  Explanation: {res.get('explanation')}")
    
    # Expected: The final score should be aligned to 95.0 (the AI score) because of score alignment (max), not dragged down or whitelisted to 5.0.
    if res.get("final_score") == 95.0:
        print("  PASS: Score alignment correctly matched the AI's 95.0 threat score.")
    else:
        print(f"  FAIL: Score was not aligned to 95.0! Got {res.get('final_score')}")
        success = False
        
    # 3. Test fuse_text_scores with whitelisted mention in explanation
    print("\n3. Testing fuse_text_scores explanation mentioning brand:")
    qwen_scam_res = {
        "score": 95.0,
        "confidence": 90.0,
        "category": "Tech Support Scam",
        "explanation": "Scam message pretending to be from google.com support to steal credentials."
    }
    res_text = fuse_text_scores(qwen_scam_res, text_content="Pretending to be google.com support")
    print(f"  Final Score: {res_text.get('final_score')}")
    print(f"  Category: {res_text.get('category')}")
    print(f"  Strategy: {res_text.get('strategy')}")
    
    if res_text.get("final_score") == 95.0 and res_text.get("strategy") != "Whitelist Override":
        print("  PASS: Whitelist was not triggered by explanation, and final score aligned to 95.0.")
    else:
        print(f"  FAIL: Unexpected final score or strategy: {res_text.get('final_score')}, {res_text.get('strategy')}")
        success = False
        
    # 4. Test threat intelligence service functions directly
    print("\n4. Testing threat intelligence services with and without scheme:")
    from app.services.threat_intel_service import check_phishtank
    import asyncio
    
    pt_no_scheme = asyncio.run(check_phishtank("paypal-security.com"))
    pt_with_scheme = asyncio.run(check_phishtank("https://paypal-security.com"))
    
    print(f"  check_phishtank('paypal-security.com') -> listed: {pt_no_scheme.get('listed')} (Expected: True)")
    print(f"  check_phishtank('https://paypal-security.com') -> listed: {pt_with_scheme.get('listed')} (Expected: True)")
    
    if pt_no_scheme.get("listed") is True and pt_with_scheme.get("listed") is True:
        print("  PASS: PhishTank check works properly with/without scheme.")
    else:
        print("  FAIL: PhishTank check failed scheme normalization test.")
        success = False

    if success:
        print("\nALL TESTS PASSED!")
    else:
        print("\nSOME TESTS FAILED!")

if __name__ == "__main__":
    run_tests()
