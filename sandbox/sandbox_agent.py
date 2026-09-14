import argparse
import json
import os
import sys
import time
from urllib.parse import urlparse
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:
    sync_playwright = None
    class PlaywrightTimeoutError(Exception):
        pass

SAFE_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "chatgpt.com", "openai.com",
    "github.com", "facebook.com", "netflix.com", "amazon.com", "youtube.com",
    "wikipedia.org", "linkedin.com", "twitter.com", "x.com", "instagram.com"
]

def is_whitelisted_domain(url: str) -> bool:
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.split(":")[0].lower().strip()
        if hostname.startswith("www."):
            hostname = hostname[4:]
        for domain in SAFE_DOMAINS:
            if hostname == domain or hostname.endswith("." + domain):
                return True
    except Exception:
        pass
    return False

def get_base_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 3:
        if parts[-2] in ["com", "co", "org", "net", "gov", "edu", "ac"]:
            return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain

def is_same_base_domain(d1: str, d2: str) -> bool:
    return get_base_domain(d1) == get_base_domain(d2)


def analyze_url(url: str, screenshot_path: str, html_path: str) -> dict:
    report = {
        "executed": True,
        "page_title": "",
        "redirect_chain": [],
        "network_requests": [],
        "download_attempts": [],
        "console_errors": [],
        "detected_forms": [],
        "behavior_findings": [],
        "sandbox_verdict": "Safe"
    }

    if sync_playwright is None:
        report["executed"] = False
        report["behavior_findings"].append("Sandbox error: Playwright is not installed on host. Run 'pip install playwright' and 'playwright install'")
        report["sandbox_verdict"] = "Unknown"
        return report

    try:
        with sync_playwright() as p:
            # Launch headless browser
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
            
            # Setup context with download handling and network monitoring
            context = browser.new_context(
                accept_downloads=True,
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Sandbox/1.0"
            )
            
            page = context.new_page()
            
            # Track redirects and request events
            def on_request(request):
                parsed = urlparse(request.url)
                if parsed.netloc:
                    report["network_requests"].append({
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "domain": parsed.netloc
                    })
                    
            def on_console(msg):
                if msg.type == "error":
                    report["console_errors"].append(msg.text)
                    
            def on_download(download):
                report["download_attempts"].append({
                    "url": download.url,
                    "suggested_filename": download.suggested_filename
                })
                report["behavior_findings"].append(f"Malicious behavior: Site triggered automatic download of '{download.suggested_filename}'")
                report["sandbox_verdict"] = "Dangerous"

            page.on("request", on_request)
            page.on("console", on_console)
            page.on("download", on_download)
            
            # Track navigate requests (redirect chain)
            report["redirect_chain"].append(url)
            
            # Navigate to page
            try:
                # Flag target URLs using insecure unencrypted HTTP protocol
                if url.startswith("http://") and not is_whitelisted_domain(url):
                    report["behavior_findings"].append("Insecure connection: Target URL uses unencrypted HTTP protocol.")

                response = page.goto(url, timeout=30000, wait_until="load")
                
                # Check redirect chain
                if response:
                    # Capture final URL and status
                    final_url = page.url
                    
                    # Flag if final page is served over unencrypted HTTP
                    if final_url.startswith("http://") and not is_whitelisted_domain(final_url) and "Insecure connection: Target URL uses unencrypted HTTP protocol." not in report["behavior_findings"]:
                        report["behavior_findings"].append("Insecure connection: Final page is served over unencrypted HTTP protocol.")

                    if final_url != url:
                        report["redirect_chain"].append(final_url)
                        try:
                            orig_parsed = urlparse(url)
                            final_parsed = urlparse(final_url)
                            orig_domain = orig_parsed.netloc.split(":")[0].lower().strip()
                            final_domain = final_parsed.netloc.split(":")[0].lower().strip()
                            if orig_domain.startswith("www."): orig_domain = orig_domain[4:]
                            if final_domain.startswith("www."): final_domain = final_domain[4:]
                            
                            # Only warn/flag if redirecting to an entirely different host (cross-domain)
                            if not is_same_base_domain(orig_domain, final_domain) and not is_whitelisted_domain(final_url):
                                report["behavior_findings"].append(f"Redirected to external URL: {final_url}")
                        except Exception:
                            pass
            except PlaywrightTimeoutError:
                report["behavior_findings"].append("Page navigation timed out after 30 seconds.")
            except Exception as e:
                report["behavior_findings"].append(f"Page load encountered error: {str(e)}")

            # Extract details from page
            try:
                report["page_title"] = page.title()
            except Exception:
                pass
                
            # Scan for form elements (credential harvesting signatures)
            try:
                forms = page.query_selector_all("form")
                for index, form in enumerate(forms):
                    inputs = form.query_selector_all("input")
                    input_types = []
                    has_password = False
                    
                    for inp in inputs:
                        itype = inp.get_attribute("type") or "text"
                        name = inp.get_attribute("name") or ""
                        placeholder = inp.get_attribute("placeholder") or ""
                        input_types.append({"type": itype, "name": name, "placeholder": placeholder})
                        
                        if itype == "password" or "pass" in name.lower() or "pwd" in name.lower():
                            has_password = True
                            
                    action = form.get_attribute("action") or ""
                    
                    form_details = {
                        "form_index": index,
                        "action": action,
                        "has_password": has_password,
                        "input_types": input_types
                    }
                    report["detected_forms"].append(form_details)
                    
                    if has_password:
                        if is_whitelisted_domain(url):
                            report["behavior_findings"].append("Secure login form detected on trusted domain.")
                        else:
                            report["behavior_findings"].append("Credential harvesting: Password login form detected on landing page.")
                            if report["sandbox_verdict"] != "Dangerous":
                                report["sandbox_verdict"] = "Suspicious"
            except Exception as e:
                report["behavior_findings"].append(f"Error parsing DOM forms: {str(e)}")

            # Check for popups, alert messages, clipboard scripts, notification prompts
            try:
                # Basic DOM scripts inspection
                scripts = page.evaluate("""() => {
                    const findings = [];
                    // Check if window.location redirect is used
                    if (document.querySelectorAll('iframe[sandbox]').length > 0) {
                        findings.push('Page embeds sandbox-restricted iframes');
                    }
                    if (window.Notification && window.Notification.permission === 'prompt') {
                        findings.push('Requests browser notifications permissions');
                    }
                    return findings;
                }""")
                report["behavior_findings"].extend(scripts)
            except Exception:
                pass
                
            # Take screenshot
            os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
            page.screenshot(path=screenshot_path, full_page=True)
            
            # Save HTML
            os.makedirs(os.path.dirname(html_path), exist_ok=True)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(page.content())
                
            browser.close()
            
    except Exception as e:
        report["executed"] = False
        report["behavior_findings"].append(f"Sandbox crash/error: {str(e)}")
        report["sandbox_verdict"] = "Unknown"
        
    # Analyze gathered findings to finalize verdict
    if report["sandbox_verdict"] != "Dangerous":
        danger_triggers = [
            "download of", "malicious behavior:"
        ]
        suspicious_triggers = [
            "password login form", "iframes", "notification", "redirected to external url",
            "insecure connection", "unencrypted http"
        ]
        
        has_danger = any(any(dt in f.lower() for dt in danger_triggers) for f in report["behavior_findings"])
        has_suspicious = any(any(st in f.lower() for st in suspicious_triggers) for f in report["behavior_findings"])
        
        if has_danger:
            report["sandbox_verdict"] = "Dangerous"
        elif has_suspicious:
            report["sandbox_verdict"] = "Suspicious"
            
    return report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Playwright sandbox scan agent")
    parser.add_argument("--url", required=True, help="URL to analyze")
    parser.add_argument("--output", required=True, help="Path to write JSON output report")
    parser.add_argument("--screenshot", required=True, help="Path to write PNG screenshot")
    parser.add_argument("--html", required=True, help="Path to write HTML snapshot")
    
    args = parser.parse_args()
    
    # Run scan
    results = analyze_url(args.url, args.screenshot, args.html)
    
    # Write JSON report
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
        
    print(f"Scan complete. Results written to {args.output}")
