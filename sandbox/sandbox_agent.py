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
                response = page.goto(url, timeout=30000, wait_until="load")
                
                # Check redirect chain
                if response:
                    # Capture final URL and status
                    final_url = page.url
                    if final_url != url:
                        report["redirect_chain"].append(final_url)
                        report["behavior_findings"].append(f"Redirected from original URL to: {final_url}")
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
            "download of", "redirected from original URL to"
        ]
        suspicious_triggers = [
            "password login form", "iframes", "notification"
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
