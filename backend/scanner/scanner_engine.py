import time
from scanner.crawler import WebCrawler
from scanner.sqli_scanner import test_form_for_sqli, test_url_for_sqli
from utils.helpers import extract_forms
from scanner.blind_sqli_scanner import test_url_for_blind_sqli
from urllib.parse import urlencode, urljoin

def start_scan(scan_id, target_url, scans):
    try:
        print("\n" + "═"*60)
        print(" APEXSCOUT SECURITY ENGINE - INITIALIZING")
        print(f" Target URL : {target_url}")
        print(f" Session ID : {scan_id}")
        print("═"*60)

        scans[scan_id]["status"] = "running"

        # ---------------- PHASE 1: RECONNAISSANCE ----------------
        print("\n[PHASE 1] 🌐 Scanning Site Structure...")
        crawler = WebCrawler(target_url)
        recon_data = crawler.crawl()

        pages_with_params = recon_data.get("pages_with_query_params", [])
        forms_dict = recon_data.get("forms_found", {})
        visited_urls = recon_data.get("visited", [])
        
        pages_count = len(visited_urls)
        forms_count = sum(len(v) for v in forms_dict.values())

        scans[scan_id]["results"].append({
            "type": "Reconnaissance",
            "pages_discovered": pages_count,
            "forms_found": forms_count,
            "details": recon_data
        })
        
        print(f"    - Found {pages_count} pages.")
        print(f"    - Found {forms_count} forms.")
        print("    ✅ Phase 1 complete.")

        # ---------------- PHASE 2: ERROR-BASED SQLI ----------------
        print("\n[PHASE 2] ⚡ Testing Injection Points...")
        initial_count = len(scans[scan_id]["results"])

        for url in pages_with_params:
            findings = test_url_for_sqli(url)
            if findings:
                for f in findings:
                    print(f"    ❌ VULNERABILITY: SQLi | Param: {f['parameter']} | Target: {url[:40]}...")
                scans[scan_id]["results"].extend(findings)

        for page_url, forms in forms_dict.items():
            for form in forms:
                findings = test_form_for_sqli(page_url, form)
                if findings:
                    print(f"    ❌ VULNERABILITY: Form-Based SQLi | Path: {page_url}")
                    scans[scan_id]["results"].extend(findings)
        
        phase2_total = len(scans[scan_id]["results"]) - initial_count
        print(f"    ✅ Phase 2 complete. Issues found: {phase2_total}")

        # ---------------- PHASE 3: BLIND SQLI ----------------
        print("\n[PHASE 3] ⏱ Testing Time-Based Delays...")
        blind_count = 0
        tested_blind_targets = set()

        for url in pages_with_params:
            if url not in tested_blind_targets:
                blind_findings = test_url_for_blind_sqli(url)
                tested_blind_targets.add(url)
                if blind_findings:
                    for bf in blind_findings:
                        print(f"    ❌ VULNERABILITY: Blind SQLi | Param: {bf['parameter']}")
                    scans[scan_id]["results"].extend(blind_findings)
                    blind_count += len(blind_findings)

        print(f"    ✅ Phase 3 complete. Issues found: {blind_count}")

        # ---------------- FINAL SUMMARY REPORT ----------------
        scans[scan_id]["status"] = "completed"
        total_issues = len(scans[scan_id]["results"]) - 1

        print("\n" + "═"*60)
        print(" FINAL SCAN REPORT")
        print("═"*60)
        print(f" Analyzed URL    : {target_url}")
        print(f" Pages Crawled   : {pages_count}")
        print(f" Entry Points    : {len(pages_with_params)}")
        print(f" SQLi Detected   : {phase2_total}")
        print(f" Blind Detected  : {blind_count}")
        
        if total_issues > 0:
            print(" SECURITY STATUS : ❌ CRITICAL ISSUES FOUND")
        else:
            print(" SECURITY STATUS : ✅ NO ISSUES DETECTED")
            
        print("═"*60)
        print(f" Results JSON: /scan-result/{scan_id}")
        print("═"*60 + "\n")

    except Exception as e:
        scans[scan_id]["status"] = f"failed: {str(e)}"
        print(f"\n❌ CRITICAL SYSTEM ERROR: {e}")