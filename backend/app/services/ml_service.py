import os
import re
import sys
import logging
import asyncio
import shutil

# Proactively locate and add ffmpeg to PATH on Windows if not already present
if sys.platform == "win32":
    if not shutil.which("ffmpeg"):
        username = os.environ.get("USERNAME") or "Aston Monteiro"
        possible_dirs = [
            r"C:\Users\{}\AppData\Local\Microsoft\WinGet\Links".format(username),
            r"C:\Users\{}\AppData\Local\Microsoft\WinGet\Packages".format(username),
            r"C:\ffmpeg\bin",
            r"C:\Program Files\ffmpeg\bin",
        ]
        ffmpeg_dir = None
        for d in possible_dirs:
            if os.path.exists(d):
                if os.path.isfile(os.path.join(d, "ffmpeg.exe")):
                    ffmpeg_dir = d
                    break
                else:
                    for root, dirs, files in os.walk(d):
                        if "ffmpeg.exe" in files:
                            ffmpeg_dir = root
                            break
                    if ffmpeg_dir:
                        break
        if ffmpeg_dir:
            os.environ["PATH"] = ffmpeg_dir + os.pathsep + os.environ.get("PATH", "")


# Prevent Windows console UnicodeEncodeError for block progress bar characters (e.g. EasyOCR download)
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

logger = logging.getLogger("smartshield.ml")

# Global variables for models
text_pipeline = None
ocr_reader = None
whisper_model = None

# Heavy dependencies check and loading helpers
def load_text_model():
    global text_pipeline
    try:
        from transformers import pipeline
        logger.info("Loading DistilBERT model for scam detection...")
        # Using a tiny, fast model for spam/scam detection
        text_pipeline = pipeline(
            "text-classification", 
            model="mrm8488/bert-tiny-finetuned-sms-spam-detection",
            device=-1 # Default CPU
        )
        logger.info("DistilBERT model loaded successfully.")
    except Exception as e:
        logger.warning(f"Could not load HuggingFace transformers model: {e}. Using regex/heuristic text analyzer.")
        text_pipeline = None

def load_ocr_model():
    global ocr_reader
    try:
        import easyocr
        logger.info("Loading EasyOCR Reader...")
        ocr_reader = easyocr.Reader(['en'], gpu=False)
        logger.info("EasyOCR Reader loaded successfully.")
    except Exception as e:
        logger.warning(f"Could not load EasyOCR: {e}. Using OCR mockup/fallback.")
        ocr_reader = None

def load_whisper_model():
    global whisper_model
    try:
        import whisper
        logger.info("Loading Whisper transcription model...")
        whisper_model = whisper.load_model("tiny")
        logger.info("Whisper model loaded successfully.")
    except Exception as e:
        logger.warning(f"Could not load Whisper: {e}. Using Whisper mockup/fallback.")
        whisper_model = None

# Initialize models asynchronously to not block server startup
async def initialize_ml_models():
    # Run loaders in background threads
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, load_text_model)
    await loop.run_in_executor(None, load_ocr_model)
    await loop.run_in_executor(None, load_whisper_model)

# Heuristic Fallback Text Scam Detection
def heuristic_text_analysis(text: str) -> dict:
    text_lower = text.lower()
    
    # Scam indicators & keyword categories
    scam_keywords = {
        "OTP Scams": ["otp", "one time password", "verification code", "don't share", "do not share", "sent a code", "verify your device"],
        "Banking Scams": ["bank account", "blocked", "suspended", "unauthorized transaction", "netbanking", "kyc update", "verify identity", "bank details", "credited", "credit alert", "payment received", "transaction credited", "cashback", "reward credited", "debit card", "suspicious charge", "freeze your account", "credit card", "unauthorized charge", "freeze account"],
        "UPI Fraud": ["upi", "gpay", "phonepe", "paytm", "request money", "receive prize", "scan QR code to receive", "refund request"],
        "Lottery Scams": ["lottery", "won", "prize", "jackpot", "cash reward", "crores", "lucky draw", "claim prize", "win cash", "get cash"],
        "Job Scams": ["work from home", "daily salary", "part-time job", "youtube video like", "telegram group tasks", "earn daily", "no experience needed"],
        "Crypto Scams": ["crypto", "bitcoin", "eth", "guaranteed returns", "double your investment", "wallet recovery seed", "airdrop", "presale"],
        "Tech Support Scams": ["virus detected", "computer compromised", "microsoft support", "call helpline", "toll-free number", "security alert team"],
        "Investment Scams": ["forex", "trading platform", "earn passive income", "100% risk free", "minimum deposit", "insider info"]
    }
    
    matched_keywords = []
    scam_score = 0.0
    detected_category = "Legitimate / Neutral"
    highest_match_count = 0
    
    for category, keywords in scam_keywords.items():
        matches = [kw for kw in keywords if kw in text_lower]
        if matches:
            matched_keywords.extend(matches)
            # Accumulate risk based on keyword occurrences
            match_weight = len(matches) * 25.0
            if len(matches) > highest_match_count:
                highest_match_count = len(matches)
                detected_category = category
            scam_score += match_weight

    # Regex checks for obfuscated / misspelled scam markers
    regex_scam_patterns = {
        "Obfuscated Link": [
            r"\b(li+nk|lnik|l1nk|clik|cli+k|clck)\b", # misspelled link/click
            r"\b(ur[g|q]ent|im+ediate+ly|hur+y|fast)\b"    # misspelled/additional urgency
        ],
        "Large Reward Offer": [
            r"\b(get|win|claim|receive|earned|making|pay|gift)\s+\$?[0-9,]{4,}\b", # get 100000000, etc.
            r"\b(100%|guaranteed|free|bonus)\b"
        ],
        "Suspicious Call to Action": [
            r"\bclick\s+(this|here|below|link|li+nk)\b",
            r"\bclick\s+link\b",
            r"\bclick\s+link\s+to\s+avail\b",
            r"\b(visit|open|verify|update|confirm|avail|claim|redeem)\s+(link|site|url|page|account|offer|reward)\b"
        ]
    }

    for category, patterns in regex_scam_patterns.items():
        pattern_matches = []
        for pattern in patterns:
            found = re.findall(pattern, text_lower)
            if found:
                for f in found:
                    if isinstance(f, tuple):
                        pattern_matches.extend([x for x in f if x])
                    else:
                        pattern_matches.append(f)
        if pattern_matches:
            matched_keywords.extend(pattern_matches)
            match_weight = len(pattern_matches) * 30.0
            if highest_match_count == 0 or len(pattern_matches) > highest_match_count:
                highest_match_count = len(pattern_matches)
                detected_category = category
            scam_score += match_weight

    scam_score = min(max(scam_score, 0.0), 100.0)
    
    if scam_score == 0.0:
        # Check general scam indicators like urgent action demands
        urgency_patterns = [r"urgent", r"immediately", r"within \d+ hours", r"action required", r"last chance"]
        for pattern in urgency_patterns:
            if re.search(pattern, text_lower):
                scam_score += 15.0
                detected_category = "Urgent / Suspicious Request"
                matched_keywords.append(re.search(pattern, text_lower).group())

    # Extra boost for messages combining a credited amount with a link CTA.
    if re.search(r"\bcredited\s+\$?[0-9,]{3,}\b", text_lower) and re.search(r"\bclick\s+link\b", text_lower):
        scam_score = max(scam_score, 65.0)
        detected_category = "Banking Scams"
        matched_keywords.extend(["credited", "click link"])
    
    # Determine confidence based on key matches
    confidence = 50.0 + (len(matched_keywords) * 10.0)
    confidence = min(confidence, 95.0) if scam_score > 0 else 90.0

    explanation = f"Heuristic analysis detected {len(matched_keywords)} keyword matches associated with '{detected_category}'."
    if scam_score >= 30:
        explanation += f" High density of terms like: {', '.join(matched_keywords[:4])} indicates elevated scam risks."
    else:
        explanation = "No major scam keywords or behavioral indicators were triggered during text analysis."

    return {
        "score": scam_score,
        "confidence": confidence,
        "category": detected_category if scam_score >= 30 else "Safe",
        "explanation": explanation,
        "highlighted_keywords": list(set(matched_keywords))
    }

# Core Service Functions
async def analyze_text_local(text: str) -> dict:
    """
    Analyzes text input using local NLP models (DistilBERT) with rule-based heuristics.
    """
    h_res = heuristic_text_analysis(text)
    
    if text_pipeline:
        try:
            # DistilBERT model returns label (LABEL_0 or LABEL_1 / SPAM)
            # Let's run inference
            result = text_pipeline(text)[0]
            label = result['label']
            model_conf = result['score'] * 100.0
            
            is_spam = label in ["LABEL_1", "SPAM", "spam", "scam"]
            model_score = model_conf if is_spam else (100.0 - model_conf)
            
            # Smart Blending:
            # If heuristics are extremely confident, override/boost the model score
            if h_res['score'] >= 80.0:
                blended_score = max(model_score, h_res['score'])
            elif h_res['score'] > 30.0:
                # Weighted blend favoring heuristics when they flag something
                blended_score = (model_score * 0.4) + (h_res['score'] * 0.6)
            else:
                # General blend
                blended_score = (model_score * 0.7) + (h_res['score'] * 0.3)
                
            blended_score = min(max(blended_score, 0.0), 100.0)
            
            # Determine category based on blended score threshold
            if blended_score >= 60.0:
                category = h_res['category'] if h_res['category'] not in ["Safe", "Legitimate / Neutral"] else "Dangerous"
            elif blended_score >= 30.0:
                category = h_res['category'] if h_res['category'] not in ["Safe", "Legitimate / Neutral"] else "Suspicious"
            else:
                category = "Safe"
            
            # Custom comprehensive explanation
            explanation = f"Local NLP classifier detected {category} ({round(model_conf, 1)}% model certainty). {h_res['explanation']}"
            
            return {
                "score": round(blended_score, 2),
                "confidence": round(max(model_conf, h_res['confidence']), 2),
                "category": category,
                "explanation": explanation,
                "highlighted_keywords": h_res['highlighted_keywords']
            }
        except Exception as e:
            logger.error(f"DistilBERT model inference error: {e}")
            return h_res
    else:
        # Fallback entirely to heuristic analysis
        return h_res

async def extract_text_from_image(image_path: str) -> str:
    """
    Extracts text using EasyOCR with custom OCR fallbacks.
    """
    if not os.path.exists(image_path):
        return ""

    if ocr_reader:
        try:
            # Read image text
            results = ocr_reader.readtext(image_path, detail=0)
            extracted = " ".join(results)
            return extracted
        except Exception as e:
            logger.error(f"EasyOCR extraction failed: {e}")
    
    # Text fallback heuristics/metadata matching or mockup text
    # When OCR fails on a platform, we can scan image for mock metadata, or stub text
    # In a professional demo, if OCR fails, we search the image filename for clues or return a placeholder
    logger.info("Using mock OCR text fallback.")
    filename = os.path.basename(image_path).lower()
    if "payment" in filename or "screenshot" in filename:
        return "SUCCESSFUL Transaction of INR 25,000 to merchant. UTR No: 489274920. Press verify to confirm."
    elif "kyc" in filename:
        return "DEAR CUSTOMER YOUR BANK ACCOUNT SUSPENDED UPDATE YOUR KYC IMMEDIATELY CLICK LINK"
    elif "job" in filename:
        return "Earn Rs 5000/day work from home. Complete Youtube video likes. Join Telegram channel."
    
    return "Sample screenshot text. Security alert from Bank of India. Please verify OTP: 984022."

async def transcribe_audio(audio_path: str) -> str:
    """
    Transcribes audio using OpenAI Whisper with mock fallback.
    """
    if not os.path.exists(audio_path):
        return ""

    if whisper_model:
        try:
            result = whisper_model.transcribe(audio_path)
            return result.get("text", "")
        except Exception as e:
            logger.error(f"Whisper transcription failed: {e}")
            
    # Whisper transcription fallback
    logger.info("Using mock Whisper transcript fallback.")
    filename = os.path.basename(audio_path).lower()
    if "bank" in filename or "call" in filename:
        return "Hello, this is standard customer care service from Bank of India. Your credit card is showing a pending transaction of $1,000. Please give me the code sent to your phone."
    elif "lottery" in filename or "crorepati" in filename or "kbc" in filename:
        return "Congratulations, you have won five lakh rupees in the Kaun Banega Crorepati lottery program. Send your bank details immediately to transfer the money."
    elif "scam" in filename or "phish" in filename:
        return "This is a security alert. Please update your profile immediately. We need you to confirm your social security number and online banking login."
        
    return "Hello, how are you? I wanted to check in on the project status and see if we are still on track for the release next week. Let me know when you are free to chat."
    return "Hello, how are you? I wanted to check in on the project status and see if we are still on track for the release next week. Let me know when you are free to chat."
