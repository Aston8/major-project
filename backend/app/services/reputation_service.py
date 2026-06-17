import socket
import ssl
import whois
from urllib.parse import urlparse
import datetime
import httpx
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("smartshield.reputation")

COMMON_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "adf.ly", "bit.do", 
    "mcaf.ee", "su.pr", "ow.ly", "goo.gl", "tiny.cc", "lnk.d", "shorte.st"
}

TARGET_BRANDS = [
    "paypal", "google", "facebook", "instagram", "netflix", "microsoft", "apple", 
    "amazon", "chase", "bankofamerica", "wellsfargo", "binance", "coinbase", "whatsapp"
]

def calculate_levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return calculate_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]

async def check_ssl(hostname: str) -> Dict[str, Any]:
    context = ssl.create_default_context()
    try:
        # Wrap connection to fetch certificate details
        conn = socket.create_connection((hostname, 443), timeout=3.0)
        sock = context.wrap_socket(conn, server_hostname=hostname)
        cert = sock.getpeercert()
        
        # Parse cert details
        subject = dict(x[0] for x in cert.get('subject', ()))
        issuer = dict(x[0] for x in cert.get('issuer', ()))
        
        # Expiry checks
        not_after_str = cert.get('notAfter')
        if not_after_str:
            expiry_date = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
            days_left = (expiry_date - datetime.datetime.utcnow()).days
            ssl_valid = days_left > 0
        else:
            expiry_date = None
            days_left = 0
            ssl_valid = False
            
        sock.close()
        return {
            "valid": ssl_valid,
            "issuer": issuer.get('commonName', 'Unknown'),
            "subject": subject.get('commonName', hostname),
            "days_left": days_left,
            "not_after": not_after_str
        }
    except Exception as e:
        logger.warning(f"SSL handshake failed for {hostname}: {e}")
        return {
            "valid": False,
            "error": str(e),
            "days_left": 0
        }

async def get_domain_whois(domain: str) -> Dict[str, Any]:
    try:
        # Run WHOIS query
        # Since whois.whois(domain) is blocking, wrap it in a thread executor
        import asyncio
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)
        
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
            
        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0]
            
        domain_age_days = None
        if creation_date and isinstance(creation_date, datetime.datetime):
            domain_age_days = (datetime.datetime.utcnow() - creation_date).days
            
        return {
            "creation_date": creation_date.isoformat() if creation_date else None,
            "expiration_date": expiration_date.isoformat() if expiration_date else None,
            "registrar": registrar or "Unknown",
            "domain_age_days": domain_age_days,
            "emails": w.emails if hasattr(w, 'emails') else None
        }
    except Exception as e:
        logger.warning(f"WHOIS check failed for {domain}: {e}")
        return {
            "error": str(e),
            "domain_age_days": None,
            "registrar": "Unknown"
        }

async def track_redirects(url: str) -> List[str]:
    redirects = [url]
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            # We track redirect histories manually
            response = await client.head(url, timeout=5.0)
            for r in response.history:
                redirects.append(str(r.url))
            if str(response.url) not in redirects:
                redirects.append(str(response.url))
    except Exception as e:
        logger.warning(f"Error tracking redirects for {url}: {e}")
    return redirects

def detect_suspicious_patterns(url: str, domain: str) -> List[str]:
    findings = []
    
    # Check IP domain
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    import re
    if re.match(ip_pattern, domain):
        findings.append("URL domain is an IP address (obscured origin)")
        
    # Check suspicious characters
    if "@" in url:
        findings.append("URL contains '@' symbol (phishing/user redirection technique)")
    if "%" in url:
        findings.append("URL contains encoded characters (obfuscation technique)")
        
    # Check excessive subdomains
    parts = domain.split('.')
    if len(parts) > 4:
        findings.append(f"Excessive subdomains ({len(parts)} levels) often used to mimic target brands")
        
    # Redirection queries
    redirect_queries = ["url=", "redirect=", "dest=", "link=", "to=", "path="]
    parsed = urlparse(url)
    for q in redirect_queries:
        if q in parsed.query:
            findings.append(f"URL contains open redirection parameter: '{q.replace('=', '')}'")
            
    # Check Typosquatting / Brand Mimicking
    clean_domain = domain.lower()
    for brand in TARGET_BRANDS:
        if brand in clean_domain:
            if clean_domain != f"{brand}.com" and clean_domain != f"www.{brand}.com":
                findings.append(f"Brand keyword '{brand}' found in domain. Possible impersonation.")
        else:
            # Levenshtein distance check on domain second level name
            domain_name = parts[-2] if len(parts) >= 2 else parts[0]
            if len(domain_name) >= 4:
                dist = calculate_levenshtein(domain_name, brand)
                if dist == 1 or dist == 2:
                    findings.append(f"Typosquatting indicator: Domain '{domain_name}' is visually close to brand '{brand}'")
                    
    return findings

async def analyze_url_reputation(url: str) -> dict:
    """
    Combines SSL status, domain age WHOIS lookup, typosquatting checks, and redirect tracking.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    parsed = urlparse(url)
    domain = parsed.netloc
    
    # Run subtasks in parallel
    import asyncio
    ssl_task = check_ssl(domain) if url.startswith("https://") else asyncio.sleep(0, result={"valid": False, "days_left": 0})
    whois_task = get_domain_whois(domain)
    redirect_task = track_redirects(url)
    
    ssl_res, whois_res, redirect_chain = await asyncio.gather(ssl_task, whois_task, redirect_task)
    
    suspicious_patterns = detect_suspicious_patterns(url, domain)
    is_shortener = domain.lower() in COMMON_SHORTENERS
    
    # Calculate score
    reputation_score = 0.0
    
    # Deductions
    if not ssl_res.get("valid"):
        reputation_score += 25.0
    if whois_res.get("domain_age_days") is not None:
        age = whois_res["domain_age_days"]
        if age < 30:
            reputation_score += 40.0
        elif age < 180:
            reputation_score += 20.0
    else:
        # Missing WHOIS is highly suspicious for a URL
        reputation_score += 30.0
        
    if is_shortener:
        reputation_score += 15.0
        
    # Pattern hits addition
    reputation_score += len(suspicious_patterns) * 20.0
    reputation_score = min(max(reputation_score, 0.0), 100.0)
    
    return {
        "url": url,
        "domain": domain,
        "domain_age_days": whois_res.get("domain_age_days"),
        "whois_info": whois_res,
        "ssl_valid": ssl_res.get("valid", False),
        "ssl_info": ssl_res,
        "redirect_chain": redirect_chain,
        "is_shortener": is_shortener,
        "suspicious_patterns": suspicious_patterns,
        "risk_score": reputation_score
    }
