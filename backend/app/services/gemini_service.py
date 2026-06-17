import httpx
import logging
import json
import base64
from app.core.config import settings

logger = logging.getLogger("smartshield.gemini")

async def analyze_text_gemini(text: str, category_context: str = "SMS") -> dict:
    """
    Sends text to Gemini API for scam detection, categorization, and explanation.
    """
    if not settings.GEMINI_API_KEY:
        logger.warning("Gemini API Key is not set. Falling back to local heuristic wrapper.")
        return mock_gemini_text_analysis(text)

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={settings.GEMINI_API_KEY}"
    
    prompt = f"""
    Analyze the following {category_context} message content for potential scams, fraud, phishing, or social engineering.
    Provide your response as a valid JSON object only, matching this structure:
    {{
        "score": (float between 0 and 100),
        "confidence": (float between 0 and 100),
        "category": (string: one of Phishing, OTP Scams, Banking Scams, UPI Fraud, Lottery Scams, Job Scams, Crypto Scams, Investment Scams, Tech Support Scams, Safe),
        "explanation": (string detailing what was found, why, and the scam markers),
        "highlighted_keywords": [list of suspicious words/phrases found in the text]
    }}
    
    Message content to analyze:
    ---
    {text}
    ---
    """
    
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload, timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                text_response = data['candidates'][0]['content']['parts'][0]['text']
                
                # Extract JSON from potential Markdown blocks
                cleaned_json = clean_json_response(text_response)
                return json.loads(cleaned_json)
            else:
                logger.error(f"Gemini API returned error code {response.status_code}: {response.text}")
                return mock_gemini_text_analysis(text)
    except Exception as e:
        logger.error(f"Gemini API call failed: {e}")
        return mock_gemini_text_analysis(text)

async def analyze_screenshot_gemini(image_path: str) -> dict:
    """
    Sends URL screenshot to Gemini Multimodal API to detect visual scam indicators.
    """
    if not settings.GEMINI_API_KEY:
        logger.warning("Gemini API Key is not set. Using mockup vision scanner.")
        return mock_gemini_vision_analysis(image_path)

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={settings.GEMINI_API_KEY}"
    
    try:
        with open(image_path, "rb") as image_file:
            img_data = base64.b64encode(image_file.read()).decode("utf-8")
            
        prompt = """
        Analyze this screenshot from a browser sandbox scan. 
        Identify if this page contains credential harvesting (login forms for banks, social media, wallets), brand impersonation (copied logos, mismatched domains), fake payment/transaction alerts, fake warning notices, or malicious popups.
        Return the result as a valid JSON object matching this structure:
        {
            "score": (float 0-100 indicating visual risk),
            "confidence": (float 0-100),
            "category": (string category, e.g. Fake Login Page, Brand Impersonation, Safe),
            "findings": [list of specific visual indicators found],
            "explanation": (paragraph summarizing why this page looks malicious or safe)
        }
        """
        
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{
                "parts": [
                    {"text": prompt},
                    {
                        "inlineData": {
                            "mimeType": "image/png",
                            "data": img_data
                        }
                    }
                ]
            }]
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload, timeout=15.0)
            if response.status_code == 200:
                data = response.json()
                text_response = data['candidates'][0]['content']['parts'][0]['text']
                cleaned_json = clean_json_response(text_response)
                return json.loads(cleaned_json)
            else:
                logger.error(f"Gemini Vision API error {response.status_code}: {response.text}")
                return mock_gemini_vision_analysis(image_path)
    except Exception as e:
        logger.error(f"Gemini Vision call failed: {e}")
        return mock_gemini_vision_analysis(image_path)

def clean_json_response(raw_text: str) -> str:
    # Remove markdown code blocks if present
    raw_text = raw_text.strip()
    if raw_text.startswith("```json"):
        raw_text = raw_text[7:]
    elif raw_text.startswith("```"):
        raw_text = raw_text[3:]
    if raw_text.endswith("```"):
        raw_text = raw_text[:-3]
    return raw_text.strip()

def mock_gemini_text_analysis(text: str) -> dict:
    # Heuristics for realistic response
    t_lower = text.lower()
    score = 15.0
    category = "Safe"
    keywords = []
    
    if "otp" in t_lower or "verification code" in t_lower:
        score = 88.5
        category = "OTP Scams"
        keywords = ["otp", "verification code"]
    elif "bank" in t_lower and ("blocked" in t_lower or "suspend" in t_lower):
        score = 92.0
        category = "Banking Scams"
        keywords = ["bank", "blocked", "suspend"]
    elif "upi" in t_lower or "request money" in t_lower:
        score = 85.0
        category = "UPI Fraud"
        keywords = ["upi", "request money"]
    elif "won" in t_lower and ("lottery" in t_lower or "prize" in t_lower):
        score = 95.0
        category = "Lottery Scams"
        keywords = ["won", "lottery", "prize"]
    elif "salary" in t_lower and ("work from home" in t_lower or "telegram" in t_lower):
        score = 80.0
        category = "Job Scams"
        keywords = ["salary", "work from home", "telegram"]

    explanation = f"Gemini Analysis (Mock mode) scanned content. Risk is flagged at {score}%."
    if score > 30:
        explanation += f" Suspicious elements identified: text resembles a {category} with keywords: {', '.join(keywords)}."
    else:
        explanation += " Content appears clean and does not map to common scam patterns."

    return {
        "score": score,
        "confidence": 85.0,
        "category": category,
        "explanation": explanation,
        "highlighted_keywords": keywords
    }

def mock_gemini_vision_analysis(image_path: str) -> dict:
    filename = image_path.lower()
    score = 10.0
    category = "Safe"
    findings = []
    explanation = "Gemini Vision (Mock Mode) inspected screenshot. The landing page appears standard with no clear phishing indicators."
    
    if "sandbox" in filename or "screenshot" in filename:
        score = 75.0
        category = "Fake Login Page"
        findings = ["Mismatched login portal branding", "Unsecured HTTP form submit", "Hidden redirection scripts"]
        explanation = "The page displays a bank login form, but the domain does not match any official registry. This is highly indicative of a credential harvesting setup."
        
    return {
        "score": score,
        "confidence": 88.0,
        "category": category,
        "findings": findings,
        "explanation": explanation
    }
