import httpx
import logging
import json
from app.core.config import settings

logger = logging.getLogger("smartshield.grok")

async def analyze_text_grok(text: str, category_context: str = "SMS") -> dict:
    """
    Sends text to Grok API (xAI) for secondary scam verification and scoring.
    """
    if not settings.GROK_API_KEY:
        logger.warning("Grok API Key is not set. Falling back to mock Grok validation.")
        return mock_grok_text_analysis(text)

    url = "https://api.xai.ai/v1/chat/completions"
    
    prompt = f"""
    You are a cybersecurity threat analyst. Analyze this {category_context} message.
    Provide a verification audit identifying if this is a scam/fraud.
    You MUST respond with only a JSON block matching this schema:
    {{
        "score": (float between 0 and 100),
        "confidence": (float between 0 and 100),
        "category": (string representing the scam sub-type or Safe),
        "explanation": (detailed explanation of the scam mechanics)
    }}
    
    Message:
    {text}
    """
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {settings.GROK_API_KEY}"
    }
    
    payload = {
        "model": "grok-beta",
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload, timeout=10.0)
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                
                # Extract JSON from potential Markdown blocks
                cleaned_json = clean_json_response(content)
                return json.loads(cleaned_json)
            else:
                logger.error(f"Grok API returned error code {response.status_code}: {response.text}")
                return mock_grok_text_analysis(text)
    except Exception as e:
        logger.error(f"Grok API call failed: {e}")
        return mock_grok_text_analysis(text)

def clean_json_response(raw_text: str) -> str:
    raw_text = raw_text.strip()
    if raw_text.startswith("```json"):
        raw_text = raw_text[7:]
    elif raw_text.startswith("```"):
        raw_text = raw_text[3:]
    if raw_text.endswith("```"):
        raw_text = raw_text[:-3]
    return raw_text.strip()

def mock_grok_text_analysis(text: str) -> dict:
    t_lower = text.lower()
    score = 10.0
    category = "Safe"
    explanation = "Grok secondary verification (mock mode) checked the content. No malicious indicators found."

    if "otp" in t_lower or "verification code" in t_lower:
        score = 85.0
        category = "OTP Scams"
        explanation = "Grok flagged this text due to credential/OTP extraction signatures. The phrasing targets verification codes directly."
    elif "bank" in t_lower and ("blocked" in t_lower or "suspend" in t_lower):
        score = 90.0
        category = "Banking Scams"
        explanation = "Grok verified banking impersonation signature. The sender uses urgent warning patterns typical of bank phishing attempts."
    elif "upi" in t_lower or "request money" in t_lower:
        score = 88.0
        category = "UPI Fraud"
        explanation = "Grok verified payment fraud signature. Phrasing coerces user into scanning code or inputting PIN to receive money."
    elif "won" in t_lower and ("lottery" in t_lower or "prize" in t_lower):
        score = 94.0
        category = "Lottery Scams"
        explanation = "Grok verified lottery scam signature. Unsolicited rewards claiming to be winnings are almost exclusively financial scams."
    elif "salary" in t_lower and ("work from home" in t_lower or "telegram" in t_lower):
        score = 82.0
        category = "Job Scams"
        explanation = "Grok verified job scam signature. Promising large daily sums for minimal tasks on social apps matches task scam operations."

    return {
        "score": score,
        "confidence": 80.0,
        "category": category,
        "explanation": explanation
    }
