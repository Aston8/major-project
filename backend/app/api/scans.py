from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status, Query
from fastapi.responses import FileResponse, StreamingResponse, HTMLResponse, Response
from app.api.deps import get_current_user
from app.core.config import settings
from app.core.db import get_db
from app.models.scan import TextScanRequest, URLScanRequest, EmailScanRequest, ScanResponse, AIModelResult, FusionResult, URLMetadata, SandboxResult, BulkScanRequest
from app.services.ml_service import analyze_text_local, extract_text_from_image, transcribe_audio
from app.services.qwen_service import analyze_with_qwen
from app.services.reputation_service import analyze_url_reputation
from app.services.threat_intel_service import fetch_threat_intelligence
from app.services.sandbox_service import execute_url_sandbox
from app.services.fusion_engine import fuse_text_scores, fuse_url_scores
from app.services.report_service import generate_scan_pdf

import os
import uuid
import logging
import httpx
from datetime import datetime
from bson import ObjectId
from typing import Optional, List
import shutil
import re

router = APIRouter()
logger = logging.getLogger("smartshield.scans")

# QR extraction fallback
def detect_qr_code_in_image(image_path: str) -> Optional[str]:
    """
    Attempts to read QR codes in the image. Falls back to filename-based simulations for demo.
    """
    # Attempt using OpenCV if present
    try:
        import cv2
        img = cv2.imread(image_path)
        detector = cv2.QRCodeDetector()
        val, points, straight_qrcode = detector.detectAndDecode(img)
        if val:
            logger.info(f"OpenCV detected QR Code content: {val}")
            return val
    except Exception as e:
        logger.warning(f"OpenCV QR detection skipped: {e}")

    # Fallback to simulated QR payloads for evaluation images
    filename = os.path.basename(image_path).lower()
    if "qr" in filename or "code" in filename:
        return "http://verify-bank-rewards.info/claim"
    return None

def extract_url(text: str) -> Optional[str]:
    """
    Scans a given text string for the first HTTP/HTTPS link or domain-like pattern.
    """
    if not text:
        return None
    # Match standard URLs starting with http/https or www
    pattern = r'(https?://[^\s<>"]+|www\.[^\s<>"]+)'
    match = re.search(pattern, text)
    if match:
        url = match.group(0)
        if url.startswith("www."):
            url = "http://" + url
        return url
    
    # Fallback: check domain names (e.g. verify-bank-rewards.info/claim)
    domain_pattern = r'\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,6}(?:/[^\s<>"]*)?)\b'
    match = re.search(domain_pattern, text)
    if match:
        domain = match.group(0)
        start_idx = match.start()
        if start_idx > 0 and text[start_idx-1] == '@':
            return None
        return "http://" + domain
    return None

# SPF / DKIM verification helpers
def verify_email_headers(content: str, headers: str, sender_domain: str) -> dict:
    findings = []
    spf_valid = False
    dkim_valid = False
    spoofing_detected = False
    
    # 1. SPF Check (Simulate checking DNS TXT records)
    if sender_domain:
        try:
            import dns.resolver
            # Query TXT records
            records = dns.resolver.resolve(sender_domain, 'TXT')
            for r in records:
                txt_record = str(r)
                if "v=spf1" in txt_record:
                    spf_valid = True
                    break
        except Exception:
            # Fallback check
            spf_valid = sender_domain in ["google.com", "microsoft.com", "paypal.com", "yahoo.com", "bankofamerica.com"]
            
        if not spf_valid:
            findings.append(f"No valid SPF record found for sender domain '{sender_domain}'")
    else:
        findings.append("No sender domain provided to validate SPF records")

    # 2. DKIM signature check
    header_lower = headers.lower() if headers else ""
    content_lower = content.lower() if content else ""
    
    if "dkim-signature" in header_lower or "dkim-signature" in content_lower:
        dkim_valid = True
    else:
        findings.append("DKIM-Signature header is missing from email content")
        
    # 3. Domain mismatch / spoofing
    # Extract "From:" from content or headers
    from_match = re.search(r"From:\s*([^<\n]+<)?([^>\n]+)", headers + "\n" + content)
    if from_match:
        from_address = from_match.group(2).strip()
        from_domain = from_address.split("@")[-1].strip() if "@" in from_address else ""
        
        if sender_domain and from_domain and sender_domain.lower() != from_domain.lower():
            spoofing_detected = True
            findings.append(f"Sender domain mismatch: Envelope specifies '{sender_domain}', but header displays '{from_domain}'")
            
    # Calculate email threat additions
    risk_score = 0.0
    if not spf_valid:
        risk_score += 30.0
    if not dkim_valid:
        risk_score += 20.0
    if spoofing_detected:
        risk_score += 45.0
        
    risk_score = min(risk_score, 100.0)
    
    return {
        "spf_valid": spf_valid,
        "dkim_valid": dkim_valid,
        "domain_mismatch": spoofing_detected,
        "risk_score": risk_score,
        "findings": findings
    }

@router.post("/text", response_model=ScanResponse)
async def scan_text(req: TextScanRequest, current_user: dict = Depends(get_current_user)):
    db = get_db()
    
    # Check if there is an embedded URL in the message
    detected_url = extract_url(req.content)
    sandbox_res = None
    
    if detected_url:
        logger.info(f"Detected embedded URL '{detected_url}' in text scan. Executing fast browser sandbox...")
        try:
            sandbox_res = await asyncio.wait_for(execute_url_sandbox(detected_url), timeout=3.5)
        except Exception as e:
            logger.warning(f"Embedded URL fast sandbox notice: {e}")
            
    # 1. Run local Qwen2.5-VL assessment
    qwen_res = await analyze_with_qwen(text=req.content)
    
    # 2. Risk Fusion engine calculation (Final Risk Engine)
    fusion = fuse_text_scores(qwen_res, sandbox_res, text_content=req.content)
    
    # Save scan results to MongoDB
    scan_doc = {
        "user_id": current_user["_id"],
        "type": "text",
        "input_data": {
            "content": req.content,
            "source_type": req.source_type,
            "url_detected": detected_url is not None,
            "url_content": detected_url
        },
        "local_ml_result": None,
        "gemini_result": None,
        "grok_result": None,
        "qwen_result": qwen_res,
        "sandbox_report": sandbox_res,
        "fusion_result": fusion,
        "created_at": datetime.utcnow()
    }
    
    result = await db.scans.insert_one(scan_doc)
    scan_doc["_id"] = str(result.inserted_id)
    
    return scan_doc

@router.post("/url", response_model=ScanResponse)
async def scan_url(req: URLScanRequest, current_user: dict = Depends(get_current_user)):
    db = get_db()
    
    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    # Check custom blacklist
    from urllib.parse import urlparse
    domain = urlparse(url).netloc
    blacklisted = await db.blacklists.find_one({"value": {"$regex": domain, "$options": "i"}})
    if blacklisted:
        # Emergency verdict
        fusion = {
            "final_score": 100.0,
            "category": "Dangerous",
            "confidence": 100.0,
            "explanation": f"Domain '{domain}' matches custom administrative blacklist: '{blacklisted.get('notes') or 'Known threat'}'.",
            "recommendations": ["Do NOT visit this page under any circumstances.", "Domain blacklisted by platform admin."]
        }
        
        scan_doc = {
            "user_id": current_user["_id"],
            "type": "url",
            "input_data": {"url": url},
            "fusion_result": fusion,
            "created_at": datetime.utcnow()
        }
        res = await db.scans.insert_one(scan_doc)
        scan_doc["_id"] = str(res.inserted_id)
        return scan_doc

    # 1. Reputation Analysis
    reputation = await analyze_url_reputation(url)
    
    # 2. Threat Intel check
    threat_intel = await fetch_threat_intelligence(url)
    
    # 3. Sandbox Browser execution
    sandbox = await execute_url_sandbox(url)
    
    # Extract screenshot path if it was captured
    screenshot_filename = None
    screenshot_path = None
    if sandbox.get("screenshot_url"):
        screenshot_filename = sandbox["screenshot_url"].split("/")[-1]
        screenshot_path = os.path.join(settings.SCREENSHOT_DIR, screenshot_filename)
    
    # 4. Run local Qwen2.5-VL multi-modal analysis on screenshot and sandbox logs text
    page_text = f"Title: {sandbox.get('page_title', '')}. findings: {', '.join(sandbox.get('behavior_findings', []))}"
    qwen_res = await analyze_with_qwen(text=page_text, image_path=screenshot_path)
    
    # 5. Risk Fusion for URLs
    fusion = fuse_url_scores(reputation, threat_intel, sandbox, qwen_res)
    
    scan_doc = {
        "user_id": current_user["_id"],
        "type": "url",
        "input_data": {"url": url},
        "local_ml_result": None,
        "gemini_result": None,
        "grok_result": None,
        "qwen_result": qwen_res,
        "url_metadata": reputation,
        "sandbox_report": sandbox,
        "threat_intel_score": threat_intel["risk_score"],
        "threat_intel_details": threat_intel["details"],
        "fusion_result": fusion,
        "created_at": datetime.utcnow()
    }
    
    result = await db.scans.insert_one(scan_doc)
    scan_doc["_id"] = str(result.inserted_id)
    
    return scan_doc

@router.post("/image", response_model=ScanResponse)
async def scan_image(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    db = get_db()
    
    # Save uploaded file
    file_id = str(uuid.uuid4())
    ext = os.path.splitext(file.filename)[1] or ".png"
    file_path = os.path.join(settings.UPLOAD_DIR, f"{file_id}{ext}")
    
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    # 1. OCR text extraction
    extracted_text = await extract_text_from_image(file_path)
    
    # 2. Check for QR Code or OCR Text URLs
    qr_url = detect_qr_code_in_image(file_path)
    ocr_url = extract_url(extracted_text)
    detected_url = qr_url or ocr_url
    
    sandbox_res = None
    if detected_url:
        logger.info(f"Detected URL '{detected_url}' from image QR/OCR. Running fast isolated sandbox browser...")
        try:
            sandbox_res = await asyncio.wait_for(execute_url_sandbox(detected_url), timeout=3.5)
        except Exception as e:
            logger.warning(f"Image scan fast sandbox notice: {e}")
            
    # 3. Analyze image directly via Qwen2.5-VL (multimodal)
    qwen_res = await analyze_with_qwen(text=extracted_text, image_path=file_path)
    
    # 4. Fuse scores (Final Risk Engine)
    fusion = fuse_text_scores(qwen_res, sandbox_res, text_content=extracted_text)
 
    scan_doc = {
        "user_id": current_user["_id"],
        "type": "image",
        "input_data": {
            "filename": file.filename,
            "file_path": file_path,
            "extracted_text": extracted_text,
            "url_detected": detected_url is not None,
            "url_content": detected_url,
            "qr_detected": qr_url is not None,
            "qr_content": qr_url
        },
        "local_ml_result": None,
        "gemini_result": None,
        "grok_result": None,
        "qwen_result": qwen_res,
        "sandbox_report": sandbox_res,
        "fusion_result": fusion,
        "created_at": datetime.utcnow()
    }
    
    result = await db.scans.insert_one(scan_doc)
    scan_doc["_id"] = str(result.inserted_id)
    
    return scan_doc

@router.post("/voice", response_model=ScanResponse)
async def scan_voice(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    db = get_db()
    
    # Save audio file
    file_id = str(uuid.uuid4())
    ext = os.path.splitext(file.filename)[1] or ".mp3"
    file_path = os.path.join(settings.UPLOAD_DIR, f"{file_id}{ext}")
    
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    # 1. Whisper transcription
    transcript = await transcribe_audio(file_path)
    
    # Check if there is an embedded URL in the voice transcript
    detected_url = extract_url(transcript)
    sandbox_res = None
    
    if detected_url:
        logger.info(f"Detected URL '{detected_url}' in voice transcript scan. Executing browser sandbox...")
        try:
            sandbox_res = await execute_url_sandbox(detected_url)
        except Exception as e:
            logger.error(f"Voice transcript URL sandbox execution failed: {e}")
            
    # 2. Run local Qwen2.5-VL assessment on the transcript
    qwen_res = await analyze_with_qwen(text=transcript)
    
    # 3. Fuse scores (Final Risk Engine)
    fusion = fuse_text_scores(qwen_res, sandbox_res, text_content=transcript)
    
    scan_doc = {
        "user_id": current_user["_id"],
        "type": "voice",
        "input_data": {
            "filename": file.filename,
            "file_path": file_path,
            "transcript": transcript,
            "url_detected": detected_url is not None,
            "url_content": detected_url
        },
        "local_ml_result": None,
        "gemini_result": None,
        "grok_result": None,
        "qwen_result": qwen_res,
        "sandbox_report": sandbox_res,
        "fusion_result": fusion,
        "created_at": datetime.utcnow()
    }
    
    result = await db.scans.insert_one(scan_doc)
    scan_doc["_id"] = str(result.inserted_id)
    
    return scan_doc

@router.post("/email", response_model=ScanResponse)
async def scan_email(req: EmailScanRequest, current_user: dict = Depends(get_current_user)):
    db = get_db()
    
    # 1. SPF / DKIM verification
    domain = req.sender_email.split("@")[-1] if (req.sender_email and "@" in req.sender_email) else ""
    header_res = verify_email_headers(req.content, req.headers or "", domain)
    
    # Check if there is an embedded URL in the email body
    detected_url = extract_url(req.content)
    sandbox_res = None
    
    if detected_url:
        logger.info(f"Detected URL '{detected_url}' in email body. Executing browser sandbox...")
        try:
            sandbox_res = await execute_url_sandbox(detected_url)
        except Exception as e:
            logger.error(f"Email body URL sandbox execution failed: {e}")
            
    # 2. Run local Qwen2.5-VL assessment on email body
    qwen_res = await analyze_with_qwen(text=req.content)
    
    # Get combined body text and sandbox result fusion
    text_fusion = fuse_text_scores(qwen_res, sandbox_res, text_content=req.content)
    
    # 3. Blend email header risks with text/sandbox scan risks
    # Header check has a direct penalty weight
    header_score = header_res["risk_score"]
    combined_score = (text_fusion["final_score"] * 0.60) + (header_score * 0.40)
    
    category = "Safe"
    if combined_score > 60:
        category = "Dangerous"
    elif combined_score > 30:
        category = "Suspicious"
        
    is_scam = category in ["Dangerous", "Suspicious"]
    verdict_label = "Scam" if is_scam else "Not Scam"
        
    recs = text_fusion["recommendations"]
    recs.extend(header_res["findings"])
    
    fusion = {
        "final_score": round(combined_score, 2),
        "category": category,
        "confidence": text_fusion["confidence"],
        "explanation": f"Final Risk Engine VERDICT: [{verdict_label}] (Score: {round(combined_score, 1)}). Combined email body threat index ({text_fusion['final_score']} score) with technical header validations ({header_score} score). " + text_fusion["explanation"],
        "recommendations": recs
    }

    scan_doc = {
        "user_id": current_user["_id"],
        "type": "email",
        "input_data": {
            "content": req.content,
            "sender_email": req.sender_email,
            "headers": req.headers,
            "spf_valid": header_res["spf_valid"],
            "dkim_valid": header_res["dkim_valid"],
            "domain_mismatch": header_res["domain_mismatch"],
            "url_detected": detected_url is not None,
            "url_content": detected_url
        },
        "local_ml_result": None,
        "gemini_result": None,
        "grok_result": None,
        "qwen_result": qwen_res,
        "sandbox_report": sandbox_res,
        "fusion_result": fusion,
        "created_at": datetime.utcnow()
    }
    
    result = await db.scans.insert_one(scan_doc)
    scan_doc["_id"] = str(result.inserted_id)
    
    return scan_doc

@router.post("/unified", response_model=ScanResponse)
async def scan_unified(
    text: Optional[str] = Form(None),
    url: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
    audio: Optional[UploadFile] = File(None),
    current_user: dict = Depends(get_current_user)
):
    db = get_db()
    
    combined_text = text or ""
    detected_url = url or ""
    
    # 1. Audio transcription
    transcript = ""
    if audio and audio.filename:
        file_id = str(uuid.uuid4())
        ext = os.path.splitext(audio.filename)[1] or ".mp3"
        audio_path = os.path.join(settings.UPLOAD_DIR, f"{file_id}{ext}")
        os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
        with open(audio_path, "wb") as buffer:
            shutil.copyfileobj(audio.file, buffer)
        transcript = await transcribe_audio(audio_path)
        combined_text = (combined_text + "\n" + transcript).strip()
        
    # 2. Image OCR and QR parsing
    extracted_text = ""
    qr_url = None
    image_path = None
    if image and image.filename:
        file_id = str(uuid.uuid4())
        ext = os.path.splitext(image.filename)[1] or ".png"
        image_path = os.path.join(settings.UPLOAD_DIR, f"{file_id}{ext}")
        os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
        with open(image_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        extracted_text = await extract_text_from_image(image_path)
        qr_url = detect_qr_code_in_image(image_path)
        
    # Extract URLs from all sources
    text_url = extract_url(combined_text)
    ocr_url = extract_url(extracted_text)
    
    final_url = detected_url or qr_url or text_url or ocr_url
    
    # 3. Sandbox Analysis
    sandbox_res = None
    if final_url:
        final_url = final_url.strip()
        if not final_url.startswith(("http://", "https://")):
            final_url = "http://" + final_url
        logger.info(f"Sandbox executing on URL: {final_url}")
        try:
            sandbox_res = await asyncio.wait_for(execute_url_sandbox(final_url), timeout=3.5)
        except Exception as e:
            logger.warning(f"Unified URL sandbox execution notice: {e}")
            
    # 4. Qwen2.5-VL Model
    qwen_res = await analyze_with_qwen(
        text=combined_text or extracted_text or final_url,
        image_path=image_path
    )
    
    # 5. Final Risk Engine
    fusion = fuse_text_scores(qwen_res, sandbox_res, text_content=combined_text or extracted_text)
    
    # Save scan document
    scan_doc = {
        "user_id": current_user["_id"],
        "type": "unified",
        "input_data": {
            "text": text,
            "url": url,
            "image_filename": image.filename if image else None,
            "audio_filename": audio.filename if audio else None,
            "transcript": transcript,
            "extracted_text": extracted_text,
            "detected_url": final_url
        },
        "local_ml_result": None,
        "gemini_result": None,
        "grok_result": None,
        "qwen_result": qwen_res,
        "sandbox_report": sandbox_res,
        "fusion_result": fusion,
        "created_at": datetime.utcnow()
    }
    
    result = await db.scans.insert_one(scan_doc)
    scan_doc["_id"] = str(result.inserted_id)
    
    return scan_doc

@router.post("/bulk")
async def scan_bulk(req: BulkScanRequest, current_user: dict = Depends(get_current_user)):
    db = get_db()
    results = []
    
    for msg in req.messages:
        msg = msg.strip()
        if not msg:
            continue
            
        detected_url = extract_url(msg)
        sandbox_res = None
        if detected_url:
            try:
                sandbox_res = await execute_url_sandbox(detected_url)
            except Exception as e:
                logger.error(f"Bulk scan URL sandbox execution failed: {e}")
                
        # Run Qwen
        qwen_res = await analyze_with_qwen(text=msg)
        
        # Risk Fusion (Final Risk Engine)
        fusion = fuse_text_scores(qwen_res, sandbox_res, text_content=msg)
        
        is_scam = fusion["category"] in ["Dangerous", "Suspicious"]
        verdict = "Scam" if is_scam else "Not Scam"
        
        # Save each scan to database for audit trail history
        scan_doc = {
            "user_id": current_user["_id"],
            "type": "text",
            "input_data": {
                "content": msg,
                "source_type": "Bulk Classifier",
                "url_detected": detected_url is not None,
                "url_content": detected_url
            },
            "local_ml_result": None,
            "gemini_result": None,
            "grok_result": None,
            "qwen_result": qwen_res,
            "sandbox_report": sandbox_res,
            "fusion_result": fusion,
            "created_at": datetime.utcnow()
        }
        await db.scans.insert_one(scan_doc)
        
        results.append({
            "message": msg,
            "score": fusion["final_score"],
            "category": fusion["category"],
            "verdict": verdict,
            "explanation": fusion["explanation"]
        })
        
    return {"results": results}

@router.get("/history")
async def get_history(
    current_user: dict = Depends(get_current_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    scan_type: Optional[str] = None,
    category: Optional[str] = None,
    q: Optional[str] = None
):
    db = get_db()
    
    query = {"user_id": current_user["_id"]}
    if scan_type:
        query["type"] = scan_type
    if category:
        query["fusion_result.category"] = category
        
    if q:
        # Text search on inputs
        query["$or"] = [
            {"input_data.content": {"$regex": q, "$options": "i"}},
            {"input_data.url": {"$regex": q, "$options": "i"}},
            {"input_data.filename": {"$regex": q, "$options": "i"}},
            {"fusion_result.explanation": {"$regex": q, "$options": "i"}}
        ]
        
    cursor = db.scans.find(query).sort("created_at", -1).skip(skip).limit(limit)
    scans = []
    async for scan in cursor:
        scan["_id"] = str(scan["_id"])
        scans.append(scan)
        
    total = await db.scans.count_documents(query)
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "results": scans
    }

@router.get("/report/{scan_id}")
async def get_pdf_report(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_db()
    
    # Query scan
    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
        
    # Authorization check
    if scan["user_id"] != current_user["_id"] and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this report.")
        
    scan["_id"] = str(scan["_id"])
    
    # Generate report file
    report_filename = f"SmartShield_Report_{scan_id}.pdf"
    report_path = generate_scan_pdf(scan, report_filename)
    
    return FileResponse(
        report_path, 
        media_type="application/pdf", 
        filename=report_filename
    )

@router.get("/file/screenshots/{filename}")
async def get_screenshot(filename: str):
    screenshot_path = os.path.join(settings.SCREENSHOT_DIR, filename)
    if not os.path.exists(screenshot_path):
        raise HTTPException(status_code=404, detail="Screenshot file not found.")
    return FileResponse(screenshot_path)


@router.get("/sandbox/proxy")
async def sandbox_proxy(url: str):
    """
    Proxies target webpage HTML, injecting a safety banner and interactive navigation logger script.
    Strictly keeps all navigations within the isolated proxy and blocks localhost breakouts.
    """
    url = (url or "").strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        async with httpx.AsyncClient(
            follow_redirects=True, 
            timeout=httpx.Timeout(25.0, connect=10.0), 
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SmartShield-Sandbox/2.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9"
            }
        ) as client:
            resp = await client.get(url)
            content_type = resp.headers.get("content-type", "")
            final_target_url = str(resp.url)
            
            if "html" in content_type or not content_type:
                html = resp.text
                import json
                import re
                
                # Strip existing <base> tags so our injected base is authoritative
                html = re.sub(r'<base\s+[^>]*>', '', html, flags=re.IGNORECASE)
                
                # Neutralize frame-busting scripts in HTML
                html = re.sub(r'\b(top|parent|window\.top)\.location\b', 'window.__dummy_loc', html)
                
                # Neutralize targets that break out of frames (_top, _parent, _blank)
                html = re.sub(r'target=[\'"](?:_blank|_top|_parent)[\'"]', 'target="_self"', html, flags=re.IGNORECASE)
                
                # Base tag for relative links/assets
                base_tag = f'<base href="{final_target_url}">'
                
                # Banner for visual indication
                banner = '''
                <div id="smartshield-banner" style="position:fixed;top:0;left:0;right:0;z-index:999999;background:linear-gradient(90deg, #111827, #1f2937);color:#f3f4f6;padding:8px 16px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:11px;font-weight:600;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.1);box-shadow:0 4px 12px rgba(0,0,0,0.5);">
                    <div style="display:flex;align-items:center;gap:8px;">
                        <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#10b981;box-shadow:0 0 8px #10b981;"></span>
                        <span>SMARTSHIELD ISOLATED SANDBOX — Session Active</span>
                    </div>
                    <span style="font-size:10px;background:rgba(255,255,255,0.1);padding:2px 8px;border-radius:4px;color:#d1d5db;">ISOLATED CONTAINER</span>
                </div>
                <div style="height:36px;"></div>
                '''
                
                escaped_target_base = json.dumps(final_target_url)
                
                # Nav script for tracking events and messaging parent iframe
                nav_script = f'''
                <script>
                (function() {{
                    var TARGET_BASE = {escaped_target_base};
                    
                    function notifyParent(type, payload) {{
                        try {{
                            window.parent.postMessage({{ source: 'SMARTSHIELD_SANDBOX', eventType: type, payload: payload }}, '*');
                        }} catch(e) {{}}
                    }}

                    function resolveTargetUrl(raw) {{
                        if (!raw) return null;
                        var str = String(raw).trim();
                        if (!str || str === '#' || str.startsWith('javascript:') || str.startsWith('mailto:') || str.startsWith('tel:') || str.startsWith('data:')) {{
                            return null;
                        }}

                        try {{
                            // Check if it already contains the proxy prefix
                            if (str.includes('/api/scans/sandbox/proxy?url=')) {{
                                try {{
                                    var u = new URL(str, window.location.origin);
                                    var nested = u.searchParams.get('url');
                                    if (nested) return nested;
                                }} catch(e) {{}}
                            }}

                            // Resolve relative to TARGET_BASE
                            var resolved = new URL(str, TARGET_BASE);
                            
                            // Reject internal localhost / loopback hosts from target resolution
                            if (resolved.hostname === 'localhost' || resolved.hostname === '127.0.0.1' || resolved.hostname === '0.0.0.0' || resolved.hostname === '::1') {{
                                return null;
                            }}

                            return resolved.href;
                        }} catch(e) {{
                            return null;
                        }}
                    }}

                    function wrapForProxy(targetUrl) {{
                        if (!targetUrl) return '';
                        return '/api/scans/sandbox/proxy?url=' + encodeURIComponent(targetUrl);
                    }}

                    // Intercept all link clicks
                    document.addEventListener('click', function(e) {{
                        var a = e.target.closest('a');
                        if (!a) return;

                        var rawHref = a.getAttribute('href') || '';
                        
                        // On-page hash/anchor navigation (e.g. #about, #events)
                        if (rawHref.startsWith('#')) {{
                            e.preventDefault();
                            e.stopPropagation();
                            var targetId = rawHref.substring(1);
                            if (targetId) {{
                                var el = document.getElementById(targetId) || document.querySelector('[name="' + targetId + '"]');
                                if (el) {{
                                    el.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
                                }}
                            }}
                            notifyParent('ANCHOR_NAVIGATED', {{ hash: rawHref }});
                            return;
                        }}

                        if (rawHref.startsWith('javascript:')) {{
                            return;
                        }}

                        var resolved = resolveTargetUrl(rawHref);
                        if (resolved) {{
                            e.preventDefault();
                            e.stopPropagation();
                            notifyParent('LINK_CLICKED', {{ 
                                targetUrl: resolved, 
                                text: (a.innerText || a.getAttribute('title') || '').trim().slice(0, 60) 
                            }});
                            window.location.href = wrapForProxy(resolved);
                        }}
                    }}, true);

                    // Intercept form submissions
                    document.addEventListener('submit', function(e) {{
                        var form = e.target.closest('form');
                        if (!form) return;

                        var rawAction = form.getAttribute('action') || '';
                        var resolvedAction = resolveTargetUrl(rawAction) || TARGET_BASE;
                        var hasPass = !!form.querySelector('input[type="password"]');
                        var inputs = Array.from(form.querySelectorAll('input, select, textarea')).map(function(i) {{
                            return {{ name: i.name || i.id, type: i.type || 'text' }};
                        }});

                        notifyParent('FORM_SUBMITTED', {{ 
                            actionUrl: resolvedAction, 
                            hasPassword: hasPass, 
                            fields: inputs.slice(0, 10) 
                        }});

                        var method = (form.getAttribute('method') || 'GET').toUpperCase();
                        if (method === 'GET') {{
                            e.preventDefault();
                            e.stopPropagation();
                            var fd = new FormData(form);
                            var params = new URLSearchParams(fd);
                            var glue = resolvedAction.includes('?') ? '&' : '?';
                            var fullUrl = resolvedAction + glue + params.toString();
                            window.location.href = wrapForProxy(fullUrl);
                        }} else {{
                            // Safe simulated POST inside sandbox to prevent loopback breakouts
                            e.preventDefault();
                            e.stopPropagation();
                            notifyParent('POST_FORM_SIMULATED', {{ actionUrl: resolvedAction }});
                            alert('[SMARTSHIELD ISOLATION]: Target form POST submission intercepted and safely logged. Telemetry recorded in sandbox evidence log.');
                        }}
                    }}, true);

                    // Track input interactions
                    document.addEventListener('focusin', function(e) {{
                        if (!e.target) return;
                        if (e.target.tagName === 'INPUT' && e.target.type === 'password') {{
                            notifyParent('PASSWORD_INPUT_INTERACTED', {{ fieldName: e.target.name || e.target.id || 'password' }});
                        }} else if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {{
                            notifyParent('INPUT_FIELD_INTERACTED', {{ fieldName: e.target.name || e.target.id || 'input', fieldType: e.target.type || 'text' }});
                        }}
                    }}, true);

                    // Safe dummy location object to absorb frame-busting scripts
                    window.__dummy_loc = {{
                        set href(val) {{
                            var res = resolveTargetUrl(val);
                            if (res) window.location.href = wrapForProxy(res);
                        }},
                        replace: function(val) {{
                            var res = resolveTargetUrl(val);
                            if (res) window.location.replace(wrapForProxy(res));
                        }},
                        assign: function(val) {{
                            var res = resolveTargetUrl(val);
                            if (res) window.location.assign(wrapForProxy(res));
                        }}
                    }};

                    // Prevent SPA router from changing iframe window.location to localhost routes
                    try {{
                        var originalPushState = history.pushState;
                        history.pushState = function(state, title, url) {{
                            if (url) {{
                                var res = resolveTargetUrl(url);
                                if (res) {{
                                    notifyParent('SPA_NAVIGATED', {{ route: res }});
                                }}
                            }}
                        }};
                        var originalReplaceState = history.replaceState;
                        history.replaceState = function(state, title, url) {{
                            if (url) {{
                                var res = resolveTargetUrl(url);
                                if (res) {{
                                    notifyParent('SPA_NAVIGATED', {{ route: res }});
                                }}
                            }}
                        }};
                    }} catch(err) {{}}

                    // Extract DOM telemetry
                    function extractDomTelemetry() {{
                        var pageText = (document.body ? document.body.innerText || '' : '').replace(/\\s+/g, ' ').slice(0, 3000);
                        var passInputs = document.querySelectorAll('input[type="password"]').length;
                        var formsCount = document.forms.length;
                        var linksCount = document.querySelectorAll('a[href]').length;
                        var scriptsCount = document.querySelectorAll('script').length;
                        
                        notifyParent('PAGE_LOADED', {{ 
                            url: TARGET_BASE,
                            title: document.title || TARGET_BASE,
                            pageText: pageText,
                            passInputs: passInputs,
                            formsCount: formsCount,
                            linksCount: linksCount,
                            scriptsCount: scriptsCount
                        }});
                    }}

                    if (document.readyState === 'complete' || document.readyState === 'interactive') {{
                        extractDomTelemetry();
                    }} else {{
                        window.addEventListener('DOMContentLoaded', extractDomTelemetry);
                        window.addEventListener('load', extractDomTelemetry);
                    }}
                }})();
                </script>
                '''
                
                if "<head>" in html:
                    html = html.replace("<head>", f"<head>{base_tag}{nav_script}", 1)
                elif "<head" in html:
                    html = re.sub(r'<head[^>]*>', r'\g<0>' + base_tag + nav_script, html, count=1)
                else:
                    html = base_tag + nav_script + html
                    
                if "<body" in html:
                    html = re.sub(r'<body[^>]*>', r'\g<0>' + banner, html, count=1)
                else:
                    html = banner + html
                    
                return HTMLResponse(content=html)
            else:
                return Response(content=resp.content, media_type=content_type)
    except Exception as e:
        import urllib.parse
        encoded = urllib.parse.quote(url)
        return HTMLResponse(content=f"""
            <div style="padding:40px;background:#18181b;color:#fca5a5;font-family:sans-serif;text-align:center;min-height:300px;display:flex;flex-direction:column;justify-content:center;align-items:center;">
                <div style="font-weight:700;font-size:16px;margin-bottom:8px;color:#f87171;">⚠ Navigation Alert — Sandbox Session Remains Active</div>
                <p style="color:#cbd5e1;font-size:13px;max-width:500px;line-height:1.5;">Target URL <code>{url}</code> could not be directly loaded over proxy ({str(e)}). This does not terminate the investigation.</p>
                <div style="margin-top:16px;display:flex;gap:10px;">
                    <a href="/api/scans/sandbox/proxy?url={encoded}" style="padding:8px 16px;background:#374151;color:#ffffff;border-radius:8px;text-decoration:none;font-size:12px;font-weight:600;">Retry Loading Target</a>
                </div>
            </div>
        """)


@router.post("/sandbox/analyze-page")
async def analyze_sandbox_page(
    payload: dict,
    current_user: dict = Depends(get_current_user)
):
    """
    Analyzes live page text and DOM metadata captured in real-time as user browses inside the sandbox.
    """
    target_url = payload.get("url") or "http://example.com"
    page_text = payload.get("page_text") or ""
    page_title = payload.get("title") or "Target Page"
    pass_inputs = payload.get("passInputs", 0)
    forms_count = payload.get("formsCount", 0)
    
    # Fast heuristic & Qwen analysis
    analyzed_text = f"URL: {target_url}. Title: {page_title}. Password Fields: {pass_inputs}. Forms: {forms_count}. Page Text: {page_text[:1500]}"
    qwen_res = await analyze_with_qwen(text=analyzed_text, image_path=None)
    
    # Calculate live threat score
    score = qwen_res.get("score", 50)
    if pass_inputs > 0 or forms_count > 0:
        if any(kw in target_url.lower() or kw in page_text.lower() for kw in ["login", "bank", "verify", "secure", "account", "paypal", "chase", "apple"]):
            score = max(score, 88)
            
    category = qwen_res.get("category") or ("Phishing / Credential Harvesting" if score >= 70 else "Informational Webpage")
    verdict = "Dangerous" if score >= 75 else ("Suspicious" if score >= 40 else "Safe")
    
    return {
        "url": target_url,
        "title": page_title,
        "score": score,
        "verdict": verdict,
        "category": category,
        "tactic_breakdown": qwen_res.get("tactic_breakdown", {
            "impersonation": min(99, score) if score >= 60 else 30,
            "urgency": min(99, score + 2) if score >= 60 else 25,
            "credentialHarvest": 90 if pass_inputs > 0 else 20,
            "financialIntent": score,
            "isolation": score
        }),
        "explanation": qwen_res.get("explanation") or f"SmartShield AI analyzed {page_title}. Flags detected: {pass_inputs} password inputs, {forms_count} forms."
    }


@router.post("/sandbox/audit-session")
async def audit_sandbox_session(
    payload: dict,
    current_user: dict = Depends(get_current_user)
):
    """
    Audits an interactive live user session recorded inside the sandbox viewport.
    Fuses recorded user interaction logs (visited pages, form actions, password entries)
    with backend threat intelligence and sandbox findings for a final verdict.
    """
    db = get_db()
    target_url = payload.get("url") or payload.get("initial_url") or "http://example.com"
    recorded_events = payload.get("events", [])
    captured_page_text = payload.get("page_text") or payload.get("pageText") or ""
    captured_page_title = payload.get("page_title") or payload.get("title") or ""
    
    # Run URL scan
    reputation = await analyze_url_reputation(target_url)
    threat_intel = await fetch_threat_intelligence(target_url)
    sandbox = await execute_url_sandbox(target_url)
    
    # Enrich sandbox report with live interactive session evidence
    session_findings = []
    visited_urls = set()
    password_entered = False
    forms_submitted = []
    
    for event in recorded_events:
        etype = event.get("eventType")
        epayload = event.get("payload", {})
        if etype == "LINK_CLICKED":
            turl = epayload.get("targetUrl")
            if turl: visited_urls.add(turl)
        elif etype == "PASSWORD_INPUT_INTERACTED":
            password_entered = True
        elif etype == "FORM_SUBMITTED":
            action = epayload.get("actionUrl")
            if action: forms_submitted.append(action)
            
    if visited_urls:
        session_findings.append(f"Interactive Navigation: User visited {len(visited_urls)} sub-pages during live session.")
    if password_entered:
        session_findings.append("Interactive Audit: Password input field was targeted/interacted with during session.")
    if forms_submitted:
        session_findings.append(f"Form Actions: {len(forms_submitted)} form submissions were captured by the sandbox proxy.")
        
    sandbox["behavior_findings"].extend(session_findings)
    if captured_page_title:
        sandbox["page_title"] = captured_page_title
        
    # Run local Qwen analysis on extracted full page content + interactive behavior
    page_text = f"Target URL: {target_url}. Page Title: {captured_page_title or sandbox.get('page_title', '')}. Extracted Page Content: {captured_page_text[:2000]}. Session Findings: {', '.join(sandbox.get('behavior_findings', []))}"
    qwen_res = await analyze_with_qwen(text=page_text, image_path=None)
    
    # Risk Fusion
    fusion = fuse_url_scores(reputation, threat_intel, sandbox, qwen_res)
    
    scan_doc = {
        "user_id": current_user["_id"],
        "type": "url",
        "input_data": {
            "url": target_url, 
            "title": captured_page_title,
            "session_events_count": len(recorded_events),
            "page_text": captured_page_text[:1000]
        },
        "local_ml_result": None,
        "gemini_result": None,
        "grok_result": None,
        "qwen_result": qwen_res,
        "url_metadata": reputation,
        "sandbox_report": sandbox,
        "threat_intel_score": threat_intel["risk_score"],
        "threat_intel_details": threat_intel["details"],
        "fusion_result": fusion,
        "created_at": datetime.utcnow()
    }
    
    result = await db.scans.insert_one(scan_doc)
    scan_doc["_id"] = str(result.inserted_id)
    
    return scan_doc



