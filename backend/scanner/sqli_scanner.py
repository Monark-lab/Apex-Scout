import requests
from urllib.parse import (
    urlparse,
    parse_qs,
    urlencode,
    urlunparse,
    urljoin
)

# ---------------- SQL Injection Payload ----------------

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "'--",
    "\"--",
    "' OR 1=1--"
]


# ---------------- SQL Error Signature ----------------

SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "syntax error",
    "mysql_fetch"
]

# ---------------- Detect SQL Errors ----------------

def contains_sqli_error(response_text: str) -> bool:
    text = response_text.lower()
    return any(error in text for error in SQL_ERROR_PATTERNS)

# ---------------- Test URL Query Parameters ----------------
def test_url_for_sqli(url: str):
    findings = {}
    
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    if not params:
        return []

    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = [payload]

            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed_url._replace(query=test_query))

            try:
                response = requests.get(test_url, timeout=5)

                if contains_sqli_error(response.text):
                    key = f"url_sqli::{parsed_url.path}::{param}"

                    if key not in findings:
                        findings[key] = {
                            "type": "SQL Injection",
                            "location": "URL Parameter",
                            "parameter": param,
                            "page": parsed_url.path,
                            "risk": "High",
                            "evidence": "Database error message detected",
                            "payloads": []
                        }

                    findings[key]["payloads"].append(payload)

            except requests.RequestException:
                continue

    return list(findings.values())


# ---------------- Test HTML Forms for SQLi ----------------

def test_form_for_sqli(page_url: str, form: dict):
    findings = []

    action_url = urljoin(page_url, form.get("action", ""))
    method = form.get("method", "get").lower()
    inputs = form.get("inputs", [])

    if not inputs:
        return findings

    for payload in SQLI_PAYLOADS:
        data = {}

        for field in inputs:
            name = field.get("name")
            if name:
                data[name] = payload

        try:
            if method == "post":
                response = requests.post(
                    action_url,
                    data=data,
                    timeout=5
                )
            else:
                response = requests.get(
                    action_url,
                    params=data,
                    timeout=5
                )

            if contains_sqli_error(response.text):
                findings.append({
                    "type": "SQL Injection",
                    "location": "Form Input",
                    "page": page_url,
                    "action": action_url,
                    "method": method.upper(),
                    "payload": payload,
                    "risk": "High",
                    "evidence": "Database error message detected"
                })

        except requests.RequestException:
            continue

    return findings
